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
  };
};
