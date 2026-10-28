/**
 * Encrypted Backup Vault Types
 * INVARIANT: Plaintext recovery passphrases and private keys NEVER leave client memory.
 * Server stores strictly the opaque Argon2id-XChaCha20-Poly1305 vault.
 */

export interface EncryptedBackupVault {
  version: 1;
  algorithm: 'argon2id-xchacha20poly1305';
  kdf: {
    salt: string; // Hex (16 bytes)
    opslimit: number;
    memlimit: number;
    alg: number;
  };
  ciphertext: string; // Base64 AEAD ciphertext
  nonce: string; // Hex (24 bytes)
  createdAt: string;
}

export interface BackupContactItem {
  counterpartPublicId: string;
  counterpartIdentityKey?: string;
  verified: boolean;
}

export interface DecryptedBackupData {
  publicId: string;
  privateIdentityKeyBase64: string;
  privateSignedPrekeyBase64: string;
  contacts: BackupContactItem[];
  exportedAt: string;
}

export interface LinkDeviceRequest {
  publicId: string;
  device: {
    deviceId: string;
    publicIdentityKey: string;
    publicSignedPrekey: string;
    signedPrekeySignature: string;
    deviceName?: string;
  };
}

export interface RevokeDeviceRequest {
  deviceId: string;
}
