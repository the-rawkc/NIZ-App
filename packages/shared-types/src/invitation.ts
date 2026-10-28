/**
 * Ephemeral Invitation types for NIZ Chat.
 * INVARIANT: Permanent QRs have no bearer secrets.
 * Temporary invitation tokens are high-entropy, expiring, revocable, and optionally single-use.
 */

export interface CreateInvitationRequest {
  creatorPublicId: string;
  /** Expiration duration in seconds (min 60, max 86400) */
  expiresInSeconds: number;
  /** Whether the invitation can only be redeemed once */
  isSingleUse: boolean;
}

export interface InvitationRecord {
  id: string;
  creatorPublicId: string;
  /** Salted hash of token stored on server */
  tokenHash: string;
  isSingleUse: boolean;
  isRevoked: boolean;
  redemptionCount: number;
  expiresAt: string;
  createdAt: string;
}

export interface CreateInvitationResponse {
  invitationId: string;
  /** Plaintext invitation token returned ONLY to creator upon creation */
  invitationToken: string;
  expiresAt: string;
  isSingleUse: boolean;
  qrPayload: string;
}

export interface ResolveInvitationRequest {
  invitationToken: string;
}

export interface ResolveInvitationResponse {
  valid: boolean;
  creatorPublicId?: string;
  isSingleUse?: boolean;
  expiresAt?: string;
  reason?: 'expired' | 'revoked' | 'already_redeemed' | 'not_found';
}
