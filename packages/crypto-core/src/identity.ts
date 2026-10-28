import _sodium from 'libsodium-wrappers-sumo';
import { assertNoSecretsInPayload } from '@niz/validation';
import type { RegisterIdentityRequest } from '@niz/shared-types';
import { computeSafetyFingerprint } from './fingerprint.js';

export interface ClientPrivateKeys {
  /** Ed25519 private identity signing key - NEVER sent to server */
  privateIdentityKeyBase64: string;
  /** X25519 private prekey exchange key - NEVER sent to server */
  privateSignedPrekeyBase64: string;
}

export interface ClientIdentityBundle {
  /** Public user-visible identity ID (niz_id_...) */
  publicId: string;
  deviceId: string;
  /** Public Ed25519 signing key (Base64) */
  publicIdentityKeyBase64: string;
  /** Public X25519 key exchange prekey (Base64) */
  publicSignedPrekeyBase64: string;
  /** Signature of prekey signed with identity key (Base64) */
  signedPrekeySignatureBase64: string;
  /** User-verifiable safety number */
  safetyFingerprint: string;
  /** Client-side private keys (Must remain in client secure storage) */
  privateKeys: ClientPrivateKeys;
  /** Payload ready for POST /v1/identity/register (Guaranteed zero private keys) */
  registrationPayload: RegisterIdentityRequest;
}

/**
 * Creates a cryptographically secure client identity.
 * - Ed25519 Identity Keypair
 * - X25519 Signed Prekey Keypair
 * - Cryptographic detached signature verifying prekey authenticity
 * - Guaranteed separation: returns public registration payload with no private keys
 */
export async function createClientIdentity(
  deviceId: string,
  deviceName: string = 'NIZ Web Client'
): Promise<ClientIdentityBundle> {
  await _sodium.ready;
  const sodium = _sodium;

  // 1. Generate Ed25519 Identity Keypair
  const identityKeyPair = sodium.crypto_sign_keypair();

  // 2. Generate X25519 Prekey Keypair
  const prekeyPair = sodium.crypto_kx_keypair();

  // 3. Sign the public prekey using the private identity key
  const signature = sodium.crypto_sign_detached(
    prekeyPair.publicKey,
    identityKeyPair.privateKey
  );

  // 4. Verify signature locally before proceeding (fail closed)
  const isValidSig = sodium.crypto_sign_verify_detached(
    signature,
    prekeyPair.publicKey,
    identityKeyPair.publicKey
  );
  if (!isValidSig) {
    throw new Error('Cryptographic self-check failed: Prekey signature invalid');
  }

  // 5. Generate high-entropy 160-bit random Public Identity ID
  const randomHex = sodium.to_hex(sodium.randombytes_buf(20));
  const publicId = `niz_id_${randomHex}`;

  // Base64 encodings
  const publicIdentityKeyBase64 = sodium.to_base64(
    identityKeyPair.publicKey,
    sodium.base64_variants.ORIGINAL
  );
  const publicSignedPrekeyBase64 = sodium.to_base64(
    prekeyPair.publicKey,
    sodium.base64_variants.ORIGINAL
  );
  const signedPrekeySignatureBase64 = sodium.to_base64(
    signature,
    sodium.base64_variants.ORIGINAL
  );
  const privateIdentityKeyBase64 = sodium.to_base64(
    identityKeyPair.privateKey,
    sodium.base64_variants.ORIGINAL
  );
  const privateSignedPrekeyBase64 = sodium.to_base64(
    prekeyPair.privateKey,
    sodium.base64_variants.ORIGINAL
  );

  // Compute safety fingerprint
  const safetyFingerprint = await computeSafetyFingerprint(publicIdentityKeyBase64);

  // 6. Build server registration payload (strictly public parameters)
  const registrationPayload: RegisterIdentityRequest = {
    publicId,
    device: {
      deviceId,
      publicIdentityKey: publicIdentityKeyBase64,
      publicSignedPrekey: publicSignedPrekeyBase64,
      signedPrekeySignature: signedPrekeySignatureBase64,
      deviceName,
    },
  };

  // 7. Verify security invariant: registration payload must have NO secret keys
  assertNoSecretsInPayload(registrationPayload);

  return {
    publicId,
    deviceId,
    publicIdentityKeyBase64,
    publicSignedPrekeyBase64,
    signedPrekeySignatureBase64,
    safetyFingerprint,
    privateKeys: {
      privateIdentityKeyBase64,
      privateSignedPrekeyBase64,
    },
    registrationPayload,
  };
}

/**
 * Verifies a counterpart's public signed prekey using their public identity key.
 */
export async function verifyPrekeySignature(
  publicIdentityKeyBase64: string,
  publicSignedPrekeyBase64: string,
  signatureBase64: string
): Promise<boolean> {
  await _sodium.ready;
  const sodium = _sodium;

  try {
    const identityKey = sodium.from_base64(publicIdentityKeyBase64, sodium.base64_variants.ORIGINAL);
    const prekey = sodium.from_base64(publicSignedPrekeyBase64, sodium.base64_variants.ORIGINAL);
    const signature = sodium.from_base64(signatureBase64, sodium.base64_variants.ORIGINAL);

    return sodium.crypto_sign_verify_detached(signature, prekey, identityKey);
  } catch {
    return false;
  }
}
