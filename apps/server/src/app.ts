import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import websocket from '@fastify/websocket';
import type { WebSocket } from 'ws';
import type { IStorageAdapter } from './storage/interface.js';
import { healthRoutes } from './routes/health.js';
import { identityRoutes } from './routes/identity.js';
import { invitationRoutes } from './routes/invitations.js';
import { connectionRoutes } from './routes/connections.js';
import { messageRoutes } from './routes/messages.js';
import { adminRoutes } from './routes/admin.js';
import { attachmentRoutes } from './routes/attachments.js';
import { billingRoutes } from './routes/billing.js';
import { logger } from './utils/logger.js';

export interface AppOptions {
  storage: IStorageAdapter;
  rateLimitMax?: number;
}

export async function buildApp(opts: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false, // Using our structured content-free logger
    bodyLimit: 30 * 1024 * 1024, // 30MB limit for raw attachments
  });

  // Support raw octet-stream buffers for encrypted attachment uploads
  app.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer' },
    (_req, body, done) => {
      done(null, body);
    }
  );

  const activeSockets = new Map<string, WebSocket>();

  // CORS configuration
  await app.register(cors, {
    origin: (_origin, cb) => {
      // In dev allow localhost; fail-closed in strict production
      cb(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
  });

  // WebSocket support
  await app.register(websocket);

  // Rate Limiting
  await app.register(rateLimit, {
    max: opts.rateLimitMax ?? 100,
    timeWindow: '1 minute',
  });

  // WebSocket route for real-time ciphertext delivery
  app.get('/v1/ws', { websocket: true }, (connection, req) => {
    const rawConn = connection as unknown as { socket?: WebSocket };
    const socket = rawConn.socket || (connection as unknown as WebSocket);

    const deviceId = (req.query as { deviceId?: string })?.deviceId;
    if (!deviceId) {
      socket.close();
      return;
    }

    activeSockets.set(deviceId, socket);
    logger.info('Device connected via WebSocket', { deviceId });

    // Bidirectional Heartbeat / Ping-Pong handling
    socket.on('message', (data: Buffer | string) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'ping') {
          if (socket.readyState === 1) { // OPEN
            socket.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
          }
        }
      } catch {
        // Ignore unparseable raw frames
      }
    });

    socket.on('close', () => {
      activeSockets.delete(deviceId);
      logger.info('Device disconnected from WebSocket', { deviceId });
    });

    socket.on('error', (err) => {
      activeSockets.delete(deviceId);
      logger.warn('WebSocket client error', { deviceId, error: err.message });
    });
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
  await app.register(messageRoutes(opts.storage, activeSockets));
  await app.register(adminRoutes(opts.storage));
  await app.register(attachmentRoutes(opts.storage));
  await app.register(billingRoutes(opts.storage));

  return app;
}
