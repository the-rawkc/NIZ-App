import type { FastifyPluginAsync } from 'fastify';
import { MessageEnvelopeSchema, assertNoSecretsInPayload } from '@niz/validation';
import type { IStorageAdapter } from '../storage/interface.js';
import { logger } from '../utils/logger.js';

export const messageRoutes = (storage: IStorageAdapter): FastifyPluginAsync => {
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

    // Fetch queued ciphertext envelopes for a recipient device
    fastify.get<{ Params: { deviceId: string } }>('/v1/messages/queue/:deviceId', async (request, reply) => {
      const { deviceId } = request.params;
      const device = await storage.getDevice(deviceId);
      if (!device || device.revokedAt) {
        return reply.status(403).send({ error: 'DEVICE_NOT_FOUND_OR_REVOKED' });
      }

      const messages = await storage.getPendingMessages(deviceId);
      return reply.send({
        deviceId,
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
