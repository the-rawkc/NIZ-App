/**
 * Messaging and Envelope types for NIZ Chat.
 * INVARIANT: Server holds ciphertext ONLY. Zero plaintext bodies.
 */

export interface MessageEnvelope {
  /** Unique message envelope ID (UUIDv4) */
  envelopeId: string;
  /** Sender account public ID */
  senderPublicId: string;
  /** Sender device ID */
  senderDeviceId: string;
  /** Recipient account public ID */
  recipientPublicId: string;
  /** Recipient device ID */
  recipientDeviceId: string;
  /** Double ratchet ephemeral public key or ratchet header */
  ratchetHeader: {
    dhPublicKey: string;
    pn: number; // Previous chain length
    n: number;  // Message index in chain
  };
  /** AEAD authenticated ciphertext (Base64) */
  ciphertext: string;
  /** Initialization vector / nonce (Base64) */
  nonce: string;
  /** Protocol version string (e.g. 'niz-dr-v1') */
  protocolVersion: string;
  /** Created timestamp */
  createdAt: string;
}

export interface SendMessageRequest {
  recipientPublicId: string;
  recipientDeviceId: string;
  ratchetHeader: {
    dhPublicKey: string;
    pn: number;
    n: number;
  };
  ciphertext: string;
  nonce: string;
  protocolVersion: string;
}

export interface SendMessageResponse {
  success: boolean;
  envelopeId: string;
  queuedAt: string;
}

export interface MessageAcknowledgePayload {
  envelopeIds: string[];
}
