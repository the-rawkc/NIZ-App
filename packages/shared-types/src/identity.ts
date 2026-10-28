/**
 * Public Identity and Device types for NIZ Chat.
 * INVARIANT: Private keys MUST NEVER exist in these structures.
 */

export interface PublicIdentity {
  /** Random cryptographically generated public ID (e.g. niz_id_...) */
  publicId: string;
  /** Creation timestamp (ISO string) */
  createdAt: string;
  /** Status of the identity */
  status: 'active' | 'suspended' | 'revoked';
}

export interface PublicDevice {
  deviceId: string;
  accountPublicId: string;
  /** Base64-encoded public identity key (e.g. Ed25519) */
  publicIdentityKey: string;
  /** Base64-encoded signed prekey (e.g. X25519) */
  publicSignedPrekey: string;
  /** Base64-encoded signature of signed prekey by identity key */
  signedPrekeySignature: string;
  createdAt: string;
  revokedAt?: string | null;
  deviceName?: string;
}

export interface RegisterIdentityRequest {
  publicId: string;
  device: {
    deviceId: string;
    publicIdentityKey: string;
    publicSignedPrekey: string;
    signedPrekeySignature: string;
    deviceName?: string;
  };
}

export interface RegisterIdentityResponse {
  success: boolean;
  publicId: string;
  deviceId: string;
  registeredAt: string;
}
