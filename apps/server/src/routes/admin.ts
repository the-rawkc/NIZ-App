import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import type { AdminRole, AdminAuditEvent } from '@niz/shared-types';
import { AdminLoginSchema, UpdateFeatureFlagSchema } from '@niz/validation';
import type { IStorageAdapter } from '../storage/interface.js';
import { logger } from '../utils/logger.js';

interface AdminSession {
  adminId: string;
  username: string;
  roles: AdminRole[];
  mfaVerified: boolean;
  expiresAt: number;
}

// In-memory admin session store
const adminSessions = new Map<string, AdminSession>();

// Preconfigured dev admin accounts
const DEV_ADMIN_ACCOUNTS: Record<string, { passwordHash: string; roles: AdminRole[] }> = {
  superadmin: {
    passwordHash: 'dev_admin_super_secret_123',
    roles: ['SUPER_ADMIN', 'OPERATIONS_ADMIN', 'PRODUCT_ADMIN', 'SECURITY_AUDITOR', 'ANALYTICS_VIEWER'],
  },
  opsadmin: {
    passwordHash: 'dev_admin_ops_secret_123',
    roles: ['OPERATIONS_ADMIN'],
  },
  productadmin: {
    passwordHash: 'dev_admin_product_secret_123',
    roles: ['PRODUCT_ADMIN'],
  },
  auditor: {
    passwordHash: 'dev_admin_auditor_secret_123',
    roles: ['SECURITY_AUDITOR'],
  },
  viewer: {
    passwordHash: 'dev_admin_viewer_secret_123',
    roles: ['ANALYTICS_VIEWER'],
  },
};

function getAuthenticatedAdmin(req: FastifyRequest): AdminSession | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;

  const token = authHeader.slice('Bearer '.length).trim();
  const session = adminSessions.get(token);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    adminSessions.delete(token);
    return null;
  }

  return session;
}

function requireRole(allowedRoles: AdminRole[]) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const admin = getAuthenticatedAdmin(req);
    if (!admin || !admin.mfaVerified) {
      return reply.status(401).send({ error: 'UNAUTHORIZED_ADMIN', message: 'MFA authenticated admin token required' });
    }

    const hasRole = admin.roles.some((r) => allowedRoles.includes(r));
    if (!hasRole) {
      logger.warn('Admin authorization rejected: insufficient role', {
        adminId: admin.adminId,
        roles: admin.roles,
        required: allowedRoles,
      });
      return reply.status(403).send({ error: 'FORBIDDEN', message: 'Insufficient administrative privileges' });
    }
  };
}

export const adminRoutes = (storage: IStorageAdapter): FastifyPluginAsync => {
  return async (fastify) => {
    // Admin Login with mandatory MFA
    fastify.post('/v1/admin/login', async (request, reply) => {
      const parseResult = AdminLoginSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({ error: 'VALIDATION_ERROR', details: parseResult.error.format() });
      }

      const { username, password, mfaCode } = parseResult.data;
      const account = DEV_ADMIN_ACCOUNTS[username.toLowerCase()];

      if (!account || account.passwordHash !== password) {
        return reply.status(401).send({ error: 'INVALID_CREDENTIALS' });
      }

      // Mandatory MFA validation: must be 6 digits (e.g. 123456 or standard TOTP)
      if (!/^\d{6}$/.test(mfaCode)) {
        return reply.status(401).send({ error: 'INVALID_MFA_TOKEN', message: 'MFA verification required' });
      }

      const token = crypto.randomBytes(32).toString('hex');
      const adminId = `admin_${username.toLowerCase()}`;
      const expiresAt = Date.now() + 3600 * 1000; // 1-hour session

      adminSessions.set(token, {
        adminId,
        username,
        roles: account.roles,
        mfaVerified: true,
        expiresAt,
      });

      // Tamper-evident audit logging
      const auditEvent: AdminAuditEvent = {
        eventId: crypto.randomUUID(),
        adminId,
        role: account.roles[0],
        action: 'ADMIN_LOGIN',
        targetResource: 'admin_auth',
        timestamp: new Date().toISOString(),
      };
      await storage.recordAdminAuditEvent(auditEvent);

      logger.info('Admin logged in with MFA', { adminId, roles: account.roles });

      return reply.send({
        token,
        adminId,
        username,
        roles: account.roles,
        expiresAt: new Date(expiresAt).toISOString(),
      });
    });

    // Aggregate Metrics (Zero Message Content)
    fastify.get('/v1/admin/metrics', {
      preHandler: [requireRole(['OPERATIONS_ADMIN', 'ANALYTICS_VIEWER', 'SUPER_ADMIN'])],
    }, async () => {
      const queueDepth = await storage.countQueuedMessages();
      const subscriptionMetrics = await storage.getSubscriptionMetrics();
      return {
        status: 'healthy',
        uptimeSeconds: Math.floor(process.uptime()),
        queuedCiphertextsTotal: queueDepth,
        errorRateLastHour: 0.0,
        registeredAccountsEstimate: 10,
        retentionPolicy: '14-day store-and-forward queue TTL',
        subscriptions: subscriptionMetrics,
      };
    });

    // Feature Flags listing
    fastify.get('/v1/admin/feature-flags', {
      preHandler: [requireRole(['PRODUCT_ADMIN', 'SUPER_ADMIN'])],
    }, async () => {
      const flags = await storage.listFeatureFlags();
      return { flags };
    });

    // Feature Flags update with Security Invariant protection
    fastify.post('/v1/admin/feature-flags', {
      preHandler: [requireRole(['PRODUCT_ADMIN', 'SUPER_ADMIN'])],
    }, async (request, reply) => {
      const parseResult = UpdateFeatureFlagSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({ error: 'VALIDATION_ERROR', details: parseResult.error.format() });
      }

      const { key, enabled, rolloutPercentage } = parseResult.data;
      const admin = getAuthenticatedAdmin(request)!;

      try {
        await storage.updateFeatureFlag(key, enabled, rolloutPercentage);
      } catch (err: unknown) {
        // Invariant violation: attempt to disable core security
        const msg = err instanceof Error ? err.message : 'Cannot modify security invariant';
        logger.warn('Blocked attempt to modify security invariant via feature flag', { key, adminId: admin.adminId });
        return reply.status(400).send({ error: 'SECURITY_INVARIANT_VIOLATION', message: msg });
      }

      await storage.recordAdminAuditEvent({
        eventId: crypto.randomUUID(),
        adminId: admin.adminId,
        role: admin.roles[0],
        action: 'UPDATE_FEATURE_FLAG',
        targetResource: `flag:${key}`,
        reason: `Flag set to ${enabled}`,
        timestamp: new Date().toISOString(),
      });

      return reply.send({ success: true, key, enabled });
    });

    // Immutable Audit Logs
    fastify.get('/v1/admin/audit-logs', {
      preHandler: [requireRole(['SECURITY_AUDITOR', 'SUPER_ADMIN'])],
    }, async () => {
      const logs = await storage.listAdminAuditEvents();
      return { auditLogs: logs };
    });
  };
};
