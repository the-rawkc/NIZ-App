import { NIZ_PUBLIC_ID_REGEX, assertNoSecretsInPayload } from '@niz/validation';

export type NizParsedQr =
  | {
      type: 'permanent_identity';
      publicId: string;
      publicIdentityKeyBase64: string;
      fingerprint: string;
    }
  | {
      type: 'ephemeral_invitation';
      invitationToken: string;
      creatorPublicId: string;
      expiresAt: string;
      isSingleUse: boolean;
    };

/**
 * Generates a Permanent Identity QR URI.
 *
 * INVARIANT: Permanent QRs encode ONLY public identity ID, public key, and safety fingerprint.
 * NO session tokens, NO bearer credentials, NO private keys.
 */
export function generatePermanentIdentityQrPayload(
  publicId: string,
  publicIdentityKeyBase64: string,
  fingerprint: string
): string {
  if (!NIZ_PUBLIC_ID_REGEX.test(publicId)) {
    throw new Error(`Invalid publicId format for permanent QR: ${publicId}`);
  }

  const encodedKey = encodeURIComponent(publicIdentityKeyBase64);
  const encodedFp = encodeURIComponent(fingerprint);
  const uri = `niz:id:${publicId}?ik=${encodedKey}&fp=${encodedFp}`;

  // Negative security assertion: Ensure no secret was somehow embedded
  assertNoSecretsInPayload({ uri, publicId, publicIdentityKeyBase64, fingerprint });

  return uri;
}

/**
 * Generates an Ephemeral Invitation QR URI.
 */
export function generateEphemeralInvitationQrPayload(
  invitationToken: string,
  creatorPublicId: string,
  expiresAt: string,
  isSingleUse: boolean
): string {
  if (!invitationToken || invitationToken.length < 16) {
    throw new Error('Invitation token must be at least 16 characters');
  }

  const encodedToken = encodeURIComponent(invitationToken);
  const encodedCreator = encodeURIComponent(creatorPublicId);
  const encodedExp = encodeURIComponent(expiresAt);
  const singleUseParam = isSingleUse ? '1' : '0';

  return `niz:invite:${encodedToken}?creator=${encodedCreator}&exp=${encodedExp}&singleUse=${singleUseParam}`;
}

/**
 * Parses and validates an incoming QR payload string.
 */
export function parseNizQrPayload(rawUri: string): NizParsedQr {
  if (!rawUri || typeof rawUri !== 'string') {
    throw new Error('QR payload is empty or invalid');
  }

  const trimmed = rawUri.trim();

  // 1. Permanent Identity QR: niz:id:<publicId>?ik=...&fp=...
  if (trimmed.startsWith('niz:id:')) {
    const withoutPrefix = trimmed.slice('niz:id:'.length);
    const [publicId, queryString] = withoutPrefix.split('?');

    if (!publicId || !NIZ_PUBLIC_ID_REGEX.test(publicId)) {
      throw new Error(`Invalid Public ID in QR payload: "${publicId}"`);
    }

    const params = new URLSearchParams(queryString || '');
    const publicIdentityKeyBase64 = decodeURIComponent(params.get('ik') || '');
    const fingerprint = decodeURIComponent(params.get('fp') || '');

    if (!publicIdentityKeyBase64 || !fingerprint) {
      throw new Error('Permanent Identity QR is missing public key or safety fingerprint');
    }

    return {
      type: 'permanent_identity',
      publicId,
      publicIdentityKeyBase64,
      fingerprint,
    };
  }

  // 2. Ephemeral Invitation QR: niz:invite:<token>?creator=...&exp=...&singleUse=...
  if (trimmed.startsWith('niz:invite:')) {
    const withoutPrefix = trimmed.slice('niz:invite:'.length);
    const [token, queryString] = withoutPrefix.split('?');

    if (!token || token.length < 16) {
      throw new Error('Invalid or corrupted invitation token in QR');
    }

    const params = new URLSearchParams(queryString || '');
    const creatorPublicId = decodeURIComponent(params.get('creator') || '');
    const expiresAt = decodeURIComponent(params.get('exp') || '');
    const singleUse = params.get('singleUse') === '1';

    if (!creatorPublicId || !expiresAt) {
      throw new Error('Ephemeral Invitation QR is missing creator ID or expiration');
    }

    return {
      type: 'ephemeral_invitation',
      invitationToken: token,
      creatorPublicId,
      expiresAt,
      isSingleUse: singleUse,
    };
  }

  throw new Error('Unrecognized NIZ QR code format');
}
