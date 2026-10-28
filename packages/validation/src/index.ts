import { z } from 'zod';

/**
 * Regex for NIZ Public Identifier:
 * Begins with 'niz_id_', followed by 32 to 64 hexadecimal characters.
 */
export const NIZ_PUBLIC_ID_REGEX = /^niz_id_[0-9a-fA-F]{32,64}$/;

/**
 * Validates public ID format.
 */
export const PublicIdSchema = z
  .string()
  .min(39)
  .max(75)
  .regex(NIZ_PUBLIC_ID_REGEX, {
    message: 'Invalid NIZ public ID format (must match niz_id_<32-64 hex chars>)',
  });

/**
 * Device Registration Schema (Strictly Public Keys)
 */
export const RegisterIdentitySchema = z.object({
  publicId: PublicIdSchema,
  device: z.object({
    deviceId: z.string().uuid(),
    publicIdentityKey: z.string().min(32).max(128), // Base64 public Ed25519
    publicSignedPrekey: z.string().min(32).max(128), // Base64 public X25519
    signedPrekeySignature: z.string().min(64).max(256), // Base64 signature
    deviceName: z.string().max(64).optional(),
  }),
});

/**
 * Create Invitation Schema
 */
export const CreateInvitationSchema = z.object({
  creatorPublicId: PublicIdSchema,
  expiresInSeconds: z.number().int().min(60).max(86400), // 1 minute to 24 hours
  isSingleUse: z.boolean().default(true),
});

/**
 * Send Connection Request Schema
 */
export const SendConnectionRequestSchema = z.object({
  recipientPublicId: PublicIdSchema,
  invitationToken: z.string().min(16).max(128).optional(),
});

/**
 * Connection Decision Schema
 */
export const ConnectionDecisionSchema = z.object({
  requestId: z.string().uuid(),
  decision: z.enum(['approve', 'decline', 'block']),
});

/**
 * Block / Unblock Contact Schema
 */
export const BlockContactSchema = z.object({
  targetPublicId: PublicIdSchema,
});

/**
 * Report Abuse Schema (Strictly Metadata, No Message Content)
 */
export const ReportAbuseSchema = z.object({
  reportedPublicId: PublicIdSchema,
  category: z.enum(['spam', 'harassment', 'impersonation', 'other']),
  reason: z.string().max(500).optional(),
});

/**
 * Message Envelope Schema
 * Verifies ciphertext envelope format; rejects empty ciphertexts.
 */
export const MessageEnvelopeSchema = z.object({
  envelopeId: z.string().uuid(),
  senderPublicId: PublicIdSchema,
  senderDeviceId: z.string().uuid(),
  recipientPublicId: PublicIdSchema,
  recipientDeviceId: z.string().uuid(),
  ratchetHeader: z.object({
    dhPublicKey: z.string().min(32).max(128),
    pn: z.number().int().nonnegative(),
    n: z.number().int().nonnegative(),
  }),
  ciphertext: z.string().min(16).max(1048576), // Base64 ciphertext, max 1MB per text envelope
  nonce: z.string().min(12).max(64), // Base64 AEAD nonce
  protocolVersion: z.string().min(1).max(32),
  createdAt: z.string().datetime(),
});

/**
 * Negative Security Validator:
 * Deeply scans any object or JSON payload and throws if any forbidden secret
 * keys (private keys, mnemonics, seed phrases, plaintext passwords) are detected.
 */
const FORBIDDEN_SECRET_KEYS = [
  'privatekey',
  'private_key',
  'secretkey',
  'secret_key',
  'privkey',
  'priv_key',
  'seedphrase',
  'seed_phrase',
  'mnemonic',
  'ratchetkey',
  'ratchet_key',
  'identityprivatekey',
  'identity_private_key',
  'password',
  'plaintextbody',
  'plaintext_body',
];

export function assertNoSecretsInPayload(data: unknown): void {
  if (!data || typeof data !== 'object') {
    return;
  }

  const stack: unknown[] = [data];

  while (stack.length > 0) {
    const current = stack.pop();

    if (current && typeof current === 'object') {
      if (Array.isArray(current)) {
        for (const item of current) {
          stack.push(item);
        }
      } else {
        for (const [key, value] of Object.entries(current as Record<string, unknown>)) {
          const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');

          if (FORBIDDEN_SECRET_KEYS.includes(normalizedKey)) {
            throw new Error(
              `SECURITY INVARIANT VIOLATION: Forbidden secret or private field detected: "${key}"`
            );
          }

          if (typeof value === 'object' && value !== null) {
            stack.push(value);
          }
        }
      }
    }
  }
}
