import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import type { IStorageAdapter } from './storage/interface.js';
import { healthRoutes } from './routes/health.js';
import { identityRoutes } from './routes/identity.js';
import { invitationRoutes } from './routes/invitations.js';
import { connectionRoutes } from './routes/connections.js';
import { messageRoutes } from './routes/messages.js';
import { logger } from './utils/logger.js';

export interface AppOptions {
  storage: IStorageAdapter;
  rateLimitMax?: number;
}

export async function buildApp(opts: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false, // Using our structured content-free logger
  });

  // CORS configuration
  await app.register(cors, {
    origin: (_origin, cb) => {
      // In dev allow localhost; fail-closed in strict production
      cb(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
  });

  // Rate Limiting
  await app.register(rateLimit, {
    max: opts.rateLimitMax ?? 100,
    timeWindow: '1 minute',
  });

  // Request logging hook (content-free)
  app.addHook('onRequest', async (req) => {
    logger.info('Incoming request', {
      method: req.method,
      url: req.url,
      ip: req.ip,
    });
  });

  // Error handling hook
  app.setErrorHandler((error, req, reply) => {
    logger.error('Unhandled server error', {
      error: error.message,
      statusCode: error.statusCode || 500,
      url: req.url,
    });
    return reply.status(error.statusCode || 500).send({
      error: 'SERVER_ERROR',
      message: error.statusCode && error.statusCode < 500 ? error.message : 'Internal server error',
    });
  });

  // Register domain routes
  await app.register(healthRoutes(opts.storage));
  await app.register(identityRoutes(opts.storage));
  await app.register(invitationRoutes(opts.storage));
  await app.register(connectionRoutes(opts.storage));
  await app.register(messageRoutes(opts.storage));

  return app;
}
