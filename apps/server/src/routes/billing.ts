import type { FastifyPluginAsync } from 'fastify';
import crypto from 'node:crypto';
import type { IStorageAdapter } from '../storage/interface.js';
import type {
  CheckoutSessionResponse,
  BillingWebhookPayload,
  SubscriptionTier,
} from '@niz/shared-types';
import { assertNoSecretsInPayload } from '@niz/validation';
import { logger } from '../utils/logger.js';

export function billingRoutes(storage: IStorageAdapter): FastifyPluginAsync {
  return async function (fastify) {
    // GET /v1/billing/subscription
    // Retrieve subscription state & quotas. NEVER paywalls E2EE messaging.
    fastify.get('/v1/billing/subscription', async (req, reply) => {
      const caller = req.headers['x-sender-public-id'] as string | undefined;
      if (!caller) {
        return reply.status(401).send({ error: 'UNAUTHORIZED' });
      }

      const subscription = await storage.getSubscription(caller);
      return reply.send(subscription);
    });

    // POST /v1/billing/checkout
    // Sandbox simulated checkout for PRO or BUSINESS tiers
    fastify.post<{ Body: { tier?: SubscriptionTier } }>(
      '/v1/billing/checkout',
      async (req, reply) => {
        try {
          assertNoSecretsInPayload(req.body);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : 'Forbidden field';
          return reply.status(400).send({ error: 'BAD_REQUEST', message: msg });
        }

        const caller = req.headers['x-sender-public-id'] as string | undefined;
        if (!caller) {
          return reply.status(401).send({ error: 'UNAUTHORIZED' });
        }

        const tier = req.body?.tier || 'PRO';
        if (tier !== 'PRO' && tier !== 'BUSINESS') {
          return reply.status(400).send({ error: 'INVALID_TIER', message: 'Tier must be PRO or BUSINESS.' });
        }

        const sessionId = `sbx_sess_${crypto.randomUUID()}`;

        // In local sandbox environment, immediately activate subscription upgrade
        const updated = await storage.updateSubscription(caller, {
          tier,
          status: 'active',
          currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
          cancelAtPeriodEnd: false,
        });

        logger.info('Simulated sandbox checkout completed', {
          senderPublicId: caller,
          tier: updated.tier,
          sessionId,
        });

        const response: CheckoutSessionResponse = {
          sessionId,
          checkoutUrl: `http://localhost:5173/?checkout_success=true&session_id=${sessionId}`,
          tier: updated.tier,
          simulated: true,
        };

        return reply.status(200).send(response);
      }
    );

    // POST /v1/billing/webhook
    // Payment gateway webhook handler (supports simulated events)
    fastify.post<{ Body: BillingWebhookPayload }>(
      '/v1/billing/webhook',
      async (req, reply) => {
        const { eventType, publicId, tier } = req.body || {};

        if (!eventType || !publicId) {
          return reply.status(400).send({ error: 'INVALID_WEBHOOK_PAYLOAD' });
        }

        logger.info('Billing webhook event received', { eventType, publicId });

        if (eventType === 'checkout.session.completed' || eventType === 'invoice.payment_succeeded') {
          await storage.updateSubscription(publicId, {
            tier: tier || 'PRO',
            status: 'active',
            currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
            cancelAtPeriodEnd: false,
          });
        } else if (eventType === 'customer.subscription.deleted') {
          // Downgrade to FREE tier on cancellation - E2EE and messaging remain intact!
          await storage.updateSubscription(publicId, {
            tier: 'FREE',
            status: 'canceled',
            cancelAtPeriodEnd: false,
          });
          logger.info('Subscription downgraded to FREE tier (E2EE remains active)', { publicId });
        }

        return reply.send({ received: true });
      }
    );

    // POST /v1/billing/cancel
    // User cancels their subscription
    fastify.post('/v1/billing/cancel', async (req, reply) => {
      const caller = req.headers['x-sender-public-id'] as string | undefined;
      if (!caller) {
        return reply.status(401).send({ error: 'UNAUTHORIZED' });
      }

      const updated = await storage.updateSubscription(caller, {
        tier: 'FREE',
        status: 'canceled',
        cancelAtPeriodEnd: true,
      });

      logger.info('Subscription canceled by user; preserved FREE E2EE status', { senderPublicId: caller });

      return reply.send({
        success: true,
        tier: updated.tier,
        status: updated.status,
      });
    });
  };
}
