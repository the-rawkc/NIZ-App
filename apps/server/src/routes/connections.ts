import type { FastifyPluginAsync } from 'fastify';
import crypto from 'node:crypto';
import {
  SendConnectionRequestSchema,
  ConnectionDecisionSchema,
  BlockContactSchema,
  ReportAbuseSchema,
  assertNoSecretsInPayload,
} from '@niz/validation';
import type { IStorageAdapter } from '../storage/interface.js';
import { logger } from '../utils/logger.js';

export const connectionRoutes = (storage: IStorageAdapter): FastifyPluginAsync => {
  return async (fastify) => {
    fastify.post('/v1/connection-requests', async (request, reply) => {
      try {
        assertNoSecretsInPayload(request.body);
      } catch (err: unknown) {
        return reply.status(400).send({
          error: 'BAD_REQUEST',
          message: err instanceof Error ? err.message : 'Forbidden field',
        });
      }

      const senderPublicId = request.headers['x-sender-public-id'] as string;
      if (!senderPublicId) {
        return reply.status(401).send({ error: 'UNAUTHORIZED_SENDER' });
      }

      const parseResult = SendConnectionRequestSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          details: parseResult.error.format(),
        });
      }

      const { recipientPublicId, invitationToken } = parseResult.data;

      if (senderPublicId === recipientPublicId) {
        return reply.status(400).send({ error: 'CANNOT_CONNECT_TO_SELF' });
      }

      const recipient = await storage.getAccount(recipientPublicId);
      if (!recipient) {
        return reply.status(404).send({ error: 'RECIPIENT_NOT_FOUND' });
      }

      let originatedInvitationId: string | undefined;

      // If an invitation token was provided, validate and mark redeemed if single-use
      if (invitationToken) {
        const tokenHash = crypto.createHash('sha256').update(invitationToken).digest('hex');
        const inv = await storage.getInvitationByHash(tokenHash);
        if (!inv || inv.isRevoked || new Date() > new Date(inv.expiresAt)) {
          return reply.status(400).send({ error: 'INVALID_OR_EXPIRED_INVITATION' });
        }
        if (inv.isSingleUse && inv.redemptionCount > 0) {
          return reply.status(400).send({ error: 'INVITATION_ALREADY_REDEEMED' });
        }
        await storage.markInvitationRedeemed(inv.id);
        originatedInvitationId = inv.id;
      }

      const requestId = crypto.randomUUID();
      const now = new Date().toISOString();

      await storage.createConnectionRequest({
        id: requestId,
        senderPublicId,
        recipientPublicId,
        state: 'pending',
        originatedInvitationId,
        createdAt: now,
        updatedAt: now,
      });

      logger.info('Connection request created', {
        senderPublicId,
        recipientPublicId,
        requestId,
      });

      return reply.status(201).send({
        success: true,
        requestId,
        state: 'pending',
        createdAt: now,
      });
    });

    fastify.post('/v1/connection-requests/decision', async (request, reply) => {
      const recipientPublicId = request.headers['x-recipient-public-id'] as string;
      if (!recipientPublicId) {
        return reply.status(401).send({ error: 'UNAUTHORIZED_RECIPIENT' });
      }

      const parseResult = ConnectionDecisionSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          details: parseResult.error.format(),
        });
      }

      const { requestId, decision } = parseResult.data;
      const targetState = decision === 'approve' ? 'approved' : decision === 'decline' ? 'declined' : 'blocked';

      const updated = await storage.updateConnectionState(requestId, targetState, recipientPublicId);
      if (!updated) {
        return reply.status(404).send({ error: 'REQUEST_NOT_FOUND_OR_FORBIDDEN' });
      }

      logger.info('Connection decision processed', {
        recipientPublicId,
        requestId,
        targetState,
      });

      return reply.send({ success: true, requestId, state: targetState });
    });

    fastify.get<{ Params: { publicId: string } }>('/v1/connection-requests/pending/:publicId', async (request, reply) => {
      const { publicId } = request.params;
      const requests = await storage.listIncomingRequests(publicId);
      return reply.send({ requests });
    });

    // List all contacts for user
    fastify.get<{ Params: { publicId: string } }>('/v1/contacts/:publicId', async (request, reply) => {
      const { publicId } = request.params;
      const contacts = await storage.listContacts(publicId);
      return reply.send({ contacts });
    });

    // Block contact
    fastify.post('/v1/contacts/block', async (request, reply) => {
      const callerPublicId = request.headers['x-sender-public-id'] as string;
      if (!callerPublicId) {
        return reply.status(401).send({ error: 'UNAUTHORIZED' });
      }

      const parseResult = BlockContactSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({ error: 'VALIDATION_ERROR', details: parseResult.error.format() });
      }

      const { targetPublicId } = parseResult.data;
      await storage.setContactState(callerPublicId, targetPublicId, 'blocked');
      logger.info('Contact blocked', { senderPublicId: callerPublicId, recipientPublicId: targetPublicId });

      return reply.send({ success: true, targetPublicId, state: 'blocked' });
    });

    // Unblock contact
    fastify.post('/v1/contacts/unblock', async (request, reply) => {
      const callerPublicId = request.headers['x-sender-public-id'] as string;
      if (!callerPublicId) {
        return reply.status(401).send({ error: 'UNAUTHORIZED' });
      }

      const parseResult = BlockContactSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({ error: 'VALIDATION_ERROR', details: parseResult.error.format() });
      }

      const { targetPublicId } = parseResult.data;
      await storage.setContactState(callerPublicId, targetPublicId, 'approved');
      logger.info('Contact unblocked', { senderPublicId: callerPublicId, recipientPublicId: targetPublicId });

      return reply.send({ success: true, targetPublicId, state: 'approved' });
    });

    // Remove contact relationship
    fastify.delete<{ Params: { targetPublicId: string } }>('/v1/contacts/:targetPublicId', async (request, reply) => {
      const callerPublicId = request.headers['x-sender-public-id'] as string;
      if (!callerPublicId) {
        return reply.status(401).send({ error: 'UNAUTHORIZED' });
      }

      const { targetPublicId } = request.params;
      const removed = await storage.removeContact(callerPublicId, targetPublicId);
      logger.info('Contact removed', { senderPublicId: callerPublicId, recipientPublicId: targetPublicId, removed });

      return reply.send({ success: true, removed });
    });

    // Report abuse (strictly metadata, no plaintext messages)
    fastify.post('/v1/reports', async (request, reply) => {
      try {
        assertNoSecretsInPayload(request.body);
      } catch (err: unknown) {
        return reply.status(400).send({
          error: 'BAD_REQUEST',
          message: err instanceof Error ? err.message : 'Forbidden field',
        });
      }

      const callerPublicId = request.headers['x-sender-public-id'] as string;
      if (!callerPublicId) {
        return reply.status(401).send({ error: 'UNAUTHORIZED' });
      }

      const parseResult = ReportAbuseSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({ error: 'VALIDATION_ERROR', details: parseResult.error.format() });
      }

      const { reportedPublicId, category, reason } = parseResult.data;
      const reportId = crypto.randomUUID();

      await storage.recordAbuseReport({
        reportId,
        reporterPublicId: callerPublicId,
        reportedPublicId,
        category,
        reason,
        createdAt: new Date().toISOString(),
      });

      logger.info('Abuse report submitted', {
        reportId,
        senderPublicId: callerPublicId,
        recipientPublicId: reportedPublicId,
        category,
      });

      return reply.status(201).send({ success: true, reportId });
    });
  };
};
