import _sodium from 'libsodium-wrappers-sumo';

/**
 * Standard Double Ratchet Algorithm implementation using Libsodium primitives.
 * - DH Ratchet: X25519
 * - KDF Ratchet: BLAKE2b (crypto_generichash)
 * - AEAD Encryption: XChaCha20-Poly1305-IETF
 *
 * Implements out-of-order delivery with skipped message keys (MKSKIPPED)
 * and replay protection.
 */

export interface RatchetHeader {
  dhPublicKey: string; // Base64 X25519 public key
  pn: number;          // Previous chain length
  n: number;           // Message index in current sending chain
}

export interface EncryptedMessagePayload {
  header: RatchetHeader;
  ciphertext: string; // Base64 AEAD ciphertext
  nonce: string;      // Base64 24-byte nonce
}

export interface RatchetSessionState {
  dhsKeyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
  dhrPublicKey: Uint8Array | null;
  rk: Uint8Array;
  cks: Uint8Array | null;
  ckr: Uint8Array | null;
  ns: number;
  nr: number;
  pn: number;
  mkSkipped: Map<string, Uint8Array>; // key: `${dhPublicKeyHex}_${n}`
}

const MAX_SKIP = 1000;

function kdfRk(sodium: typeof _sodium, rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  // Input: RK and DH output -> Output: [New RK, New Chain Key]
  const input = new Uint8Array([...rk, ...dhOut]);
  const newRk = sodium.crypto_generichash(32, input, 'niz_dr_rk_salt');
  const newCk = sodium.crypto_generichash(32, input, 'niz_dr_ck_salt');
  return [newRk, newCk];
}

function kdfCk(sodium: typeof _sodium, ck: Uint8Array): [Uint8Array, Uint8Array] {
  // Input: Chain Key -> Output: [New Chain Key, Message Key]
  const newCk = sodium.crypto_generichash(32, ck, 'niz_dr_ck_step');
  const messageKey = sodium.crypto_generichash(32, ck, 'niz_dr_mk_step');
  return [newCk, messageKey];
}

/**
 * Initializes Double Ratchet for Alice (Initiator).
 */
export async function initAliceSession(
  sharedMasterKey: Uint8Array,
  bobDhPublicKeyBase64: string
): Promise<RatchetSessionState> {
  await _sodium.ready;
  const sodium = _sodium;

  const bobDhPublicKey = sodium.from_base64(bobDhPublicKeyBase64, sodium.base64_variants.ORIGINAL);
  const aliceDhKeyPair = sodium.crypto_kx_keypair();

  const dhShared = sodium.crypto_scalarmult(aliceDhKeyPair.privateKey, bobDhPublicKey);
  const [rk, cks] = kdfRk(sodium, sharedMasterKey, dhShared);

  return {
    dhsKeyPair: aliceDhKeyPair,
    dhrPublicKey: bobDhPublicKey,
    rk,
    cks,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    mkSkipped: new Map(),
  };
}

/**
 * Initializes Double Ratchet for Bob (Responder).
 */
export async function initBobSession(
  sharedMasterKey: Uint8Array,
  bobDhKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array }
): Promise<RatchetSessionState> {
  await _sodium.ready;

  return {
    dhsKeyPair: bobDhKeyPair,
    dhrPublicKey: null,
    rk: sharedMasterKey,
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    mkSkipped: new Map(),
  };
}

/**
 * Encrypts a plaintext message using the Double Ratchet session.
 */
export async function ratchetEncrypt(
  session: RatchetSessionState,
  plaintext: string
): Promise<EncryptedMessagePayload> {
  await _sodium.ready;
  const sodium = _sodium;

  if (!session.cks) {
    throw new Error('Sending chain key not initialized');
  }

  const [newCks, messageKey] = kdfCk(sodium, session.cks);
  session.cks = newCks;

  const header: RatchetHeader = {
    dhPublicKey: sodium.to_base64(session.dhsKeyPair.publicKey, sodium.base64_variants.ORIGINAL),
    pn: session.pn,
    n: session.ns,
  };
  session.ns += 1;

  // Use XChaCha20-Poly1305 with random 24-byte nonce
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ad = Buffer.from(`${header.dhPublicKey}:${header.pn}:${header.n}`, 'utf8');
  const plaintextBytes = Buffer.from(plaintext, 'utf8');

  const ciphertextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintextBytes,
    ad,
    null,
    nonce,
    messageKey
  );

  return {
    header,
    ciphertext: sodium.to_base64(ciphertextBytes, sodium.base64_variants.ORIGINAL),
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
  };
}

function skipMessageKeys(
  sodium: typeof _sodium,
  session: RatchetSessionState,
  until: number
): void {
  if (!session.ckr) return;
  if (session.nr + MAX_SKIP < until) {
    throw new Error('Excessive message skipping detected');
  }

  while (session.nr < until) {
    const [newCkr, messageKey] = kdfCk(sodium, session.ckr);
    session.ckr = newCkr;
    const skipKey = `${session.dhrPublicKey ? sodium.to_hex(session.dhrPublicKey) : ''}_${session.nr}`;
    session.mkSkipped.set(skipKey, messageKey);
    session.nr += 1;
  }
}

function dhRatchetStep(
  sodium: typeof _sodium,
  session: RatchetSessionState,
  header: RatchetHeader
): void {
  const remoteDh = sodium.from_base64(header.dhPublicKey, sodium.base64_variants.ORIGINAL);
  session.pn = session.ns;
  session.ns = 0;
  session.nr = 0;
  session.dhrPublicKey = remoteDh;

  const dhSharedRecv = sodium.crypto_scalarmult(session.dhsKeyPair.privateKey, session.dhrPublicKey);
  const [rk1, ckr] = kdfRk(sodium, session.rk, dhSharedRecv);
  session.rk = rk1;
  session.ckr = ckr;

  session.dhsKeyPair = sodium.crypto_kx_keypair();
  const dhSharedSend = sodium.crypto_scalarmult(session.dhsKeyPair.privateKey, session.dhrPublicKey);
  const [rk2, cks] = kdfRk(sodium, session.rk, dhSharedSend);
  session.rk = rk2;
  session.cks = cks;
}

/**
 * Decrypts an encrypted message payload using the Double Ratchet session.
 * Handles out-of-order delivery, rejects replays, and verifies AEAD MAC.
 */
export async function ratchetDecrypt(
  session: RatchetSessionState,
  payload: EncryptedMessagePayload
): Promise<string> {
  await _sodium.ready;
  const sodium = _sodium;

  const { header } = payload;
  const remoteDh = sodium.from_base64(header.dhPublicKey, sodium.base64_variants.ORIGINAL);
  const skipKey = `${sodium.to_hex(remoteDh)}_${header.n}`;

  // 1. Check if message key was previously skipped (out-of-order arrival)
  if (session.mkSkipped.has(skipKey)) {
    const messageKey = session.mkSkipped.get(skipKey)!;
    session.mkSkipped.delete(skipKey); // Burn key immediately after retrieval (prevent replay)

    return decryptWithKey(sodium, payload, messageKey);
  }

  // 2. Perform DH Ratchet step if a new ephemeral public key is observed
  if (
    !session.dhrPublicKey ||
    !sodium.memcmp(remoteDh, session.dhrPublicKey)
  ) {
    skipMessageKeys(sodium, session, header.pn);
    dhRatchetStep(sodium, session, header);
  }

  // 3. Skip messages in current receiving chain if out of order
  skipMessageKeys(sodium, session, header.n);

  if (!session.ckr) {
    throw new Error('Receiving chain key not available for decryption');
  }

  const [newCkr, messageKey] = kdfCk(sodium, session.ckr);
  session.ckr = newCkr;
  session.nr += 1;

  return decryptWithKey(sodium, payload, messageKey);
}

function decryptWithKey(
  sodium: typeof _sodium,
  payload: EncryptedMessagePayload,
  messageKey: Uint8Array
): string {
  const { header, ciphertext, nonce } = payload;
  const ciphertextBytes = sodium.from_base64(ciphertext, sodium.base64_variants.ORIGINAL);
  const nonceBytes = sodium.from_base64(nonce, sodium.base64_variants.ORIGINAL);
  const ad = Buffer.from(`${header.dhPublicKey}:${header.pn}:${header.n}`, 'utf8');

  try {
    const decryptedBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertextBytes,
      ad,
      nonceBytes,
      messageKey
    );
    return Buffer.from(decryptedBytes).toString('utf8');
  } catch {
    throw new Error('AEAD Decryption failed: MAC verification failed or payload tampered');
  }
}
