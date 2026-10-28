import type { FastifyPluginAsync } from 'fastify';
import crypto from 'node:crypto';
import { CreateInvitationSchema, assertNoSecretsInPayload } from '@niz/validation';
import type { IStorageAdapter } from '../storage/interface.js';
import { logger } from '../utils/logger.js';

export const invitationRoutes = (storage: IStorageAdapter): FastifyPluginAsync => {
  return async (fastify) => {
    fastify.post('/v1/invitations', async (request, reply) => {
      try {
        assertNoSecretsInPayload(request.body);
      } catch (err: unknown) {
        return reply.status(400).send({
          error: 'BAD_REQUEST',
          message: err instanceof Error ? err.message : 'Forbidden field',
        });
      }

      const parseResult = CreateInvitationSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          details: parseResult.error.format(),
        });
      }

      const { creatorPublicId, expiresInSeconds, isSingleUse } = parseResult.data;

      // Verify creator account exists
      const account = await storage.getAccount(creatorPublicId);
      if (!account) {
        return reply.status(404).send({ error: 'ACCOUNT_NOT_FOUND' });
      }

      // Generate 256-bit cryptographically secure token
      const rawToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
      const invitationId = crypto.randomUUID();

      const now = Date.now();
      const expiresAt = new Date(now + expiresInSeconds * 1000).toISOString();

      await storage.createInvitation({
        id: invitationId,
        creatorPublicId,
        tokenHash,
        isSingleUse,
        isRevoked: false,
        redemptionCount: 0,
        expiresAt,
        createdAt: new Date(now).toISOString(),
      });

      logger.info('Created ephemeral invitation', {
        senderPublicId: creatorPublicId,
        invitationId,
      });

      return reply.status(201).send({
        invitationId,
        invitationToken: rawToken,
        expiresAt,
        isSingleUse,
        qrPayload: `niz:invite:${rawToken}`,
      });
    });

    fastify.post<{ Body: { invitationToken: string } }>('/v1/invitations/resolve', async (request, reply) => {
      const { invitationToken } = request.body || {};
      if (!invitationToken || typeof invitationToken !== 'string') {
        return reply.status(400).send({ error: 'TOKEN_REQUIRED' });
      }

      const tokenHash = crypto.createHash('sha256').update(invitationToken).digest('hex');
      const inv = await storage.getInvitationByHash(tokenHash);

      if (!inv) {
        return reply.status(404).send({ valid: false, reason: 'not_found' });
      }

      if (inv.isRevoked) {
        return reply.status(400).send({ valid: false, reason: 'revoked' });
      }

      if (new Date() > new Date(inv.expiresAt)) {
        return reply.status(400).send({ valid: false, reason: 'expired' });
      }

      if (inv.isSingleUse && inv.redemptionCount > 0) {
        return reply.status(400).send({ valid: false, reason: 'already_redeemed' });
      }

      return reply.send({
        valid: true,
        creatorPublicId: inv.creatorPublicId,
        isSingleUse: inv.isSingleUse,
        expiresAt: inv.expiresAt,
      });
    });

    fastify.post<{ Params: { id: string } }>('/v1/invitations/:id/revoke', async (request, reply) => {
      const { id } = request.params;
      const creatorPublicId = request.headers['x-sender-public-id'] as string;

      if (!creatorPublicId) {
        return reply.status(401).send({ error: 'UNAUTHORIZED' });
      }

      const revoked = await storage.revokeInvitation(id, creatorPublicId);
      if (!revoked) {
        return reply.status(404).send({ error: 'INVITATION_NOT_FOUND_OR_FORBIDDEN' });
      }

      logger.info('Revoked ephemeral invitation', { invitationId: id, senderPublicId: creatorPublicId });
      return reply.send({ success: true, invitationId: id, status: 'revoked' });
    });
  };
};
