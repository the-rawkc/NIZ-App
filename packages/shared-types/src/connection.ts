/**
 * Connection and Request state types for NIZ Chat.
 * INVARIANT: Recipient approval is required before normal messaging by default.
 */

export type ConnectionState = 'pending' | 'approved' | 'declined' | 'blocked';

export interface ConnectionRequest {
  id: string;
  senderPublicId: string;
  recipientPublicId: string;
  state: ConnectionState;
  /** Optional verification fingerprint/safety number */
  safetyNumberFingerprint?: string;
  createdAt: string;
  updatedAt: string;
  /** Optional invitation ID used to originate request */
  originatedInvitationId?: string;
}

export interface SendConnectionRequestPayload {
  recipientPublicId: string;
  invitationToken?: string;
}

export interface ConnectionDecisionPayload {
  requestId: string;
  decision: 'approve' | 'decline' | 'block';
}

export interface ConnectionRelationship {
  id: string;
  userA: string;
  userB: string;
  state: ConnectionState;
  createdAt: string;
  updatedAt: string;
}
