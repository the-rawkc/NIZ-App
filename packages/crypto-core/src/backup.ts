import _sodium from 'libsodium-wrappers-sumo';
import type { EncryptedBackupVault, DecryptedBackupData } from '@niz/shared-types';

/**
 * Creates a zero-knowledge encrypted backup vault using Argon2id key derivation
 * and XChaCha20-Poly1305 authenticated symmetric encryption.
 *
 * INVARIANT: Neither the plaintext passphrase nor the derived key is ever transmitted to the server.
 */
export async function createEncryptedBackup(
  passphrase: string,
  data: DecryptedBackupData
): Promise<EncryptedBackupVault> {
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters long.');
  }

  await _sodium.ready;
  const sodium = _sodium;

  // 1. Generate cryptographic salt for Argon2id KDF
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  const alg = sodium.crypto_pwhash_ALG_DEFAULT;

  // 2. Derive 256-bit encryption key using Argon2id
  const derivedKey = sodium.crypto_pwhash(
    32,
    passphrase,
    salt,
    opslimit,
    memlimit,
    alg
  );

  // 3. Encrypt payload with XChaCha20-Poly1305
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null,
    null,
    nonce,
    derivedKey
  );

  return {
    version: 1,
    algorithm: 'argon2id-xchacha20poly1305',
    kdf: {
      salt: sodium.to_hex(salt),
      opslimit,
      memlimit,
      alg,
    },
    ciphertext: sodium.to_base64(ciphertext),
    nonce: sodium.to_hex(nonce),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Restores identity and contacts from an encrypted backup vault.
 * Fails closed if the passphrase is incorrect or if the vault was tampered with.
 */
export async function restoreEncryptedBackup(
  passphrase: string,
  vault: EncryptedBackupVault
): Promise<DecryptedBackupData> {
  if (vault.version !== 1 || vault.algorithm !== 'argon2id-xchacha20poly1305') {
    throw new Error('Unsupported backup vault format or version.');
  }

  await _sodium.ready;
  const sodium = _sodium;

  try {
    // 1. Derive decryption key using stored KDF parameters and salt
    const salt = sodium.from_hex(vault.kdf.salt);
    const derivedKey = sodium.crypto_pwhash(
      32,
      passphrase,
      salt,
      vault.kdf.opslimit,
      vault.kdf.memlimit,
      vault.kdf.alg
    );

    // 2. Decrypt and authenticate AEAD ciphertext
    const nonce = sodium.from_hex(vault.nonce);
    const ciphertext = sodium.from_base64(vault.ciphertext);

    const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      derivedKey
    );
    const jsonStr = new TextDecoder().decode(decrypted);
    const parsed = JSON.parse(jsonStr) as DecryptedBackupData;

    // Verify minimum required fields
    if (!parsed.publicId || !parsed.privateIdentityKeyBase64 || !parsed.privateSignedPrekeyBase64) {
      throw new Error('Corrupted backup payload: missing core identity keys.');
    }

    return parsed;
  } catch (err: unknown) {
    throw new Error(
      'VAULT_RESTORE_FAILED: Invalid passphrase or corrupted backup vault. (MAC verification failed)'
    );
  }
}
