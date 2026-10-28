/**
 * Admin Console RBAC and Audit types.
 * INVARIANT: No role can read plaintext messages or retrieve private keys.
 */

export type AdminRole =
  | 'SUPER_ADMIN'
  | 'OPERATIONS_ADMIN'
  | 'BILLING_ADMIN'
  | 'PRODUCT_ADMIN'
  | 'SECURITY_AUDITOR'
  | 'ANALYTICS_VIEWER';

export interface AdminUser {
  adminId: string;
  username: string;
  roles: AdminRole[];
  mfaEnabled: boolean;
  createdAt: string;
  lastLoginAt?: string;
}

export interface AdminAuditEvent {
  eventId: string;
  adminId: string;
  role: AdminRole;
  action: string;
  targetResource: string;
  timestamp: string;
  reason?: string;
  ipAddressMasked?: string;
}

export interface FeatureFlag {
  key: string;
  enabled: boolean;
  description: string;
  rolloutPercentage: number;
  /** Invariant: Flags marked as critical security invariants can NEVER be disabled */
  isSecurityInvariant: boolean;
}
