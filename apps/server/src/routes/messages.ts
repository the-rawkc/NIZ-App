import type { FastifyPluginAsync } from 'fastify';
import type { WebSocket } from 'ws';
import { MessageEnvelopeSchema, assertNoSecretsInPayload } from '@niz/validation';
import type { IStorageAdapter } from '../storage/interface.js';
import { logger } from '../utils/logger.js';

export const messageRoutes = (
  storage: IStorageAdapter,
  activeSockets?: Map<string, WebSocket>
): FastifyPluginAsync => {
  return async (fastify) => {
    // Send / Enqueue Ciphertext Message
    fastify.post('/v1/messages', async (request, reply) => {
      try {
        assertNoSecretsInPayload(request.body);
      } catch (err: unknown) {
        return reply.status(400).send({
          error: 'BAD_REQUEST',
          message: err instanceof Error ? err.message : 'Forbidden field',
        });
      }

      const parseResult = MessageEnvelopeSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          details: parseResult.error.format(),
        });
      }

      const envelope = parseResult.data;

      // Invariant: Recipient approval is required before normal messaging by default
      const isApproved = await storage.areConnected(
        envelope.senderPublicId,
        envelope.recipientPublicId
      );

      if (!isApproved) {
        logger.warn('Blocked unauthorized message attempt from unapproved sender', {
          senderPublicId: envelope.senderPublicId,
          recipientPublicId: envelope.recipientPublicId,
        });
        return reply.status(403).send({
          error: 'FORBIDDEN',
          message: 'Recipient approval required before messaging',
        });
      }

      // Verify recipient device exists and is not revoked
      const recipientDevice = await storage.getDevice(envelope.recipientDeviceId);
      if (!recipientDevice || recipientDevice.revokedAt) {
        return reply.status(400).send({
          error: 'DEVICE_UNAVAILABLE_OR_REVOKED',
        });
      }

      await storage.enqueueMessage(envelope);

      // Real-time WebSocket delivery if recipient device is currently connected
      if (activeSockets) {
        const recipientSocket = activeSockets.get(envelope.recipientDeviceId);
        if (recipientSocket && recipientSocket.readyState === 1) { // OPEN
          recipientSocket.send(JSON.stringify({ type: 'ciphertext_envelope', envelope }));
          logger.info('Pushed ciphertext envelope via WebSocket', {
            envelopeId: envelope.envelopeId,
            recipientDeviceId: envelope.recipientDeviceId,
          });
        }
      }

      logger.info('Enqueued ciphertext envelope', {
        envelopeId: envelope.envelopeId,
        senderPublicId: envelope.senderPublicId,
        recipientPublicId: envelope.recipientPublicId,
      });

      return reply.status(202).send({
        success: true,
        envelopeId: envelope.envelopeId,
        queuedAt: new Date().toISOString(),
      });
    });

    // Ingest batch of ciphertext messages (High-throughput batch endpoint)
    fastify.post<{ Body: { envelopes: unknown[] } }>('/v1/messages/batch', async (request, reply) => {
      try {
        assertNoSecretsInPayload(request.body);
      } catch (err: unknown) {
        return reply.status(400).send({
          error: 'BAD_REQUEST',
          message: err instanceof Error ? err.message : 'Forbidden field',
        });
      }

      const { envelopes } = request.body || {};
      if (!Array.isArray(envelopes) || envelopes.length === 0 || envelopes.length > 500) {
        return reply.status(400).send({
          error: 'INVALID_BATCH',
          message: 'Envelopes must be a non-empty array with at most 500 items',
        });
      }

      const validatedEnvelopes = [];
      const connectionCache = new Map<string, boolean>();

      for (const item of envelopes) {
        const parseResult = MessageEnvelopeSchema.safeParse(item);
        if (!parseResult.success) {
          return reply.status(400).send({
            error: 'VALIDATION_ERROR',
            details: parseResult.error.format(),
          });
        }

        const env = parseResult.data;
        const cacheKey = `${env.senderPublicId}::${env.recipientPublicId}`;
        let isApproved = connectionCache.get(cacheKey);
        if (isApproved === undefined) {
          isApproved = await storage.areConnected(env.senderPublicId, env.recipientPublicId);
          connectionCache.set(cacheKey, isApproved);
        }

        if (!isApproved) {
          return reply.status(403).send({
            error: 'FORBIDDEN',
            message: `Recipient approval required before messaging recipient ${env.recipientPublicId}`,
          });
        }

        validatedEnvelopes.push(env);
      }

      await storage.enqueueBatchMessages(validatedEnvelopes);

      // WebSocket push for connected devices
      if (activeSockets) {
        for (const env of validatedEnvelopes) {
          const recipientSocket = activeSockets.get(env.recipientDeviceId);
          if (recipientSocket && recipientSocket.readyState === 1) {
            recipientSocket.send(JSON.stringify({ type: 'ciphertext_envelope', envelope: env }));
          }
        }
      }

      logger.info('Enqueued batch of ciphertext envelopes', { count: validatedEnvelopes.length });

      return reply.status(202).send({
        success: true,
        count: validatedEnvelopes.length,
        envelopeIds: validatedEnvelopes.map((e) => e.envelopeId),
      });
    });

    // Fetch queued ciphertext envelopes for a recipient device
    fastify.get<{
      Params: { deviceId: string };
      Querystring: { limit?: string };
    }>('/v1/messages/queue/:deviceId', async (request, reply) => {
      const { deviceId } = request.params;
      const device = await storage.getDevice(deviceId);
      if (!device || device.revokedAt) {
        return reply.status(403).send({ error: 'DEVICE_NOT_FOUND_OR_REVOKED' });
      }

      const limit = request.query.limit ? parseInt(request.query.limit, 10) : undefined;
      const messages = await storage.getPendingMessages(deviceId, limit);
      return reply.send({
        deviceId,
        count: messages.length,
        envelopes: messages,
      });
    });

    // Acknowledge and purge delivered ciphertext
    fastify.post<{ Body: { envelopeIds: string[] } }>('/v1/messages/ack', async (request, reply) => {
      const { envelopeIds } = request.body || {};
      if (!Array.isArray(envelopeIds) || envelopeIds.length === 0) {
        return reply.status(400).send({ error: 'INVALID_ENVELOPE_IDS' });
      }

      const purged = await storage.acknowledgeMessages(envelopeIds);
      logger.info('Purged acknowledged ciphertext envelopes', { count: purged });

      return reply.send({ success: true, purgedCount: purged });
    });
  };
};
