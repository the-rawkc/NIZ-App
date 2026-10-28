import type { FastifyPluginAsync } from 'fastify';
import { RegisterIdentitySchema, assertNoSecretsInPayload } from '@niz/validation';
import type { IStorageAdapter } from '../storage/interface.js';
import { logger } from '../utils/logger.js';

export const identityRoutes = (storage: IStorageAdapter): FastifyPluginAsync => {
  return async (fastify) => {
    fastify.post('/v1/identity/register', async (request, reply) => {
      // Invariant check: Fail closed if any private key is in payload
      try {
        assertNoSecretsInPayload(request.body);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Forbidden field in payload';
        logger.warn('Security invariant rejection on identity registration', { reason: msg });
        return reply.status(400).send({ error: 'BAD_REQUEST', message: msg });
      }

      const parseResult = RegisterIdentitySchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          details: parseResult.error.format(),
        });
      }

      const { publicId, device } = parseResult.data;

      // Ensure account exists or create it
      const existingAccount = await storage.getAccount(publicId);
      if (!existingAccount) {
        await storage.createAccount({
          publicId,
          createdAt: new Date().toISOString(),
          status: 'active',
        });
      }

      // Register device
      await storage.createDevice({
        deviceId: device.deviceId,
        accountPublicId: publicId,
        publicIdentityKey: device.publicIdentityKey,
        publicSignedPrekey: device.publicSignedPrekey,
        signedPrekeySignature: device.signedPrekeySignature,
        deviceName: device.deviceName,
        createdAt: new Date().toISOString(),
      });

      logger.info('Registered identity and device', {
        senderPublicId: publicId,
        deviceId: device.deviceId,
      });

      return reply.status(201).send({
        success: true,
        publicId,
        deviceId: device.deviceId,
        registeredAt: new Date().toISOString(),
      });
    });

    fastify.get<{ Params: { publicId: string } }>('/v1/identity/:publicId/devices', async (request, reply) => {
      const { publicId } = request.params;
      const devices = await storage.listDevices(publicId);
      return reply.send({ publicId, devices });
    });

    // Account Closure & Permanent Data Deletion (FR-020)
    fastify.delete<{ Params: { publicId: string } }>('/v1/identity/:publicId', async (request, reply) => {
      const { publicId } = request.params;
      const caller = request.headers['x-sender-public-id'] as string;

      if (!caller || caller !== publicId) {
        return reply.status(401).send({ error: 'UNAUTHORIZED_ACCOUNT_CLOSURE' });
      }

      const deleted = await storage.deleteAccount(publicId);
      if (!deleted) {
        return reply.status(404).send({ error: 'ACCOUNT_NOT_FOUND' });
      }

      logger.info('Account closed and all associated server data purged', { senderPublicId: publicId });

      return reply.send({
        success: true,
        deletedPublicId: publicId,
        purged: true,
        timestamp: new Date().toISOString(),
      });
    });
  };
};
