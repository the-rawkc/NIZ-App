/**
 * Billing & Subscription Contracts for NIZ Chat.
 * INVARIANT: Core End-to-End Encryption, QR identity, and message security
 * are NEVER paywalled. Subscriptions only expand storage caps and device counts.
 */

export type SubscriptionTier = 'FREE' | 'PRO' | 'BUSINESS';

export type SubscriptionStatus = 'active' | 'past_due' | 'canceled' | 'trialing' | 'free';

export interface SubscriptionRecord {
  publicId: string;
  tier: SubscriptionTier;
  status: SubscriptionStatus;
  currentPeriodEnd: string;
  cancelAtPeriodEnd: boolean;
  maxDevices: number;
  maxAttachmentSizeBytes: number;
  retentionDays: number;
  createdAt: string;
  updatedAt: string;
}

export interface CheckoutSessionRequest {
  tier: 'PRO' | 'BUSINESS';
}

export interface CheckoutSessionResponse {
  sessionId: string;
  checkoutUrl: string;
  tier: SubscriptionTier;
  simulated: boolean;
}

export interface BillingWebhookPayload {
  eventType: 'checkout.session.completed' | 'invoice.payment_succeeded' | 'customer.subscription.deleted';
  publicId: string;
  tier?: SubscriptionTier;
  timestamp: string;
}

export interface SubscriptionMetrics {
  free: number;
  pro: number;
  business: number;
  totalSubscribers: number;
}
