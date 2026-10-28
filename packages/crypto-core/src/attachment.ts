import _sodium from 'libsodium-wrappers-sumo';
import type { EncryptedAttachmentMetadata } from '@niz/shared-types';

export interface EncryptedAttachmentResult {
  ciphertext: Uint8Array;
  metadata: EncryptedAttachmentMetadata;
}

/**
 * Encrypt an attachment client-side using Libsodium XChaCha20-Poly1305-IETF.
 * Generates an ephemeral 256-bit symmetric key that is NEVER sent to the server.
 * The server only receives the opaque ciphertext.
 */
export async function encryptAttachment(
  fileBytes: Uint8Array,
  mimeType: string,
  filename: string
): Promise<EncryptedAttachmentResult> {
  await _sodium.ready;
  const sodium = _sodium;

  // Generate random 256-bit symmetric media key and 192-bit nonce
  const mediaKey = sodium.randombytes_buf(32);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  // Authenticated encryption of the file contents
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    fileBytes,
    null,
    null,
    nonce,
    mediaKey
  );

  // Compute SHA-256 digest of the ciphertext blob for transport integrity
  const sha256Bytes = sodium.crypto_hash_sha256(ciphertext);
  const sha256Hex = sodium.to_hex(sha256Bytes);

  return {
    ciphertext,
    metadata: {
      mediaKey: sodium.to_hex(mediaKey),
      nonce: sodium.to_hex(nonce),
      sha256: sha256Hex,
      mimeType,
      filename,
      byteSize: fileBytes.length,
    },
  };
}

/**
 * Decrypt an attachment client-side after verifying ciphertext integrity.
 * Aborts immediately if integrity check fails or MAC tag verification fails.
 */
export async function decryptAttachment(
  ciphertext: Uint8Array,
  metadata: EncryptedAttachmentMetadata
): Promise<Uint8Array> {
  await _sodium.ready;
  const sodium = _sodium;

  // 1. Verify ciphertext SHA-256 before decryption
  const computedHashBytes = sodium.crypto_hash_sha256(ciphertext);
  const computedHashHex = sodium.to_hex(computedHashBytes);

  if (computedHashHex !== metadata.sha256) {
    throw new Error('ATTACHMENT_INTEGRITY_ERROR: Ciphertext SHA-256 hash mismatch.');
  }

  // 2. Decode hex media key and nonce
  const mediaKey = sodium.from_hex(metadata.mediaKey);
  const nonce = sodium.from_hex(metadata.nonce);

  // 3. Decrypt and authenticate
  try {
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      mediaKey
    );
    return plaintext;
  } catch (err) {
    throw new Error('ATTACHMENT_DECRYPTION_FAILED: Ciphertext corrupted or authentication failed.');
  }
}
