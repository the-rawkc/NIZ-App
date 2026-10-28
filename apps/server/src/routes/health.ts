import type { FastifyPluginAsync } from 'fastify';
import type { IStorageAdapter } from '../storage/interface.js';

export const healthRoutes = (storage: IStorageAdapter): FastifyPluginAsync => {
  return async (fastify) => {
    fastify.get('/health', async () => {
      const queuedCount = await storage.countQueuedMessages();
      return {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        queuedMessagesTotal: queuedCount,
        uptimeSeconds: Math.floor(process.uptime()),
        version: '0.1.0-alpha',
      };
    });
  };
};
