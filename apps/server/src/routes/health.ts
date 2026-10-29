import type { FastifyPluginAsync } from 'fastify';
import type { IStorageAdapter } from '../storage/interface.js';

export const healthRoutes = (storage: IStorageAdapter): FastifyPluginAsync => {
  return async (fastify) => {
    fastify.get('/health', async (_request, reply) => {
      let queuedCount = 0;
      let dbStatus = 'connected';
      try {
        queuedCount = await storage.countQueuedMessages();
      } catch {
        dbStatus = 'connecting';
      }

      return reply.status(200).send({
        status: 'healthy',
        database: dbStatus,
        timestamp: new Date().toISOString(),
        queuedMessagesTotal: queuedCount,
        uptimeSeconds: Math.floor(process.uptime()),
        version: '0.1.0-alpha',
      });
    });
  };
};
