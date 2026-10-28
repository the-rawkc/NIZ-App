import _sodium from 'libsodium-wrappers-sumo';

/**
 * Computes a standardized, user-verifiable Safety Number (fingerprint)
 * from one or two public identity keys.
 *
 * Format: 6 blocks of 5 digits (e.g. "58291 03847 19284 84930 10293 84729")
 */
export async function computeSafetyFingerprint(
  publicIdentityKeyBase64: string,
  counterpartKeyBase64?: string
): Promise<string> {
  await _sodium.ready;
  const sodium = _sodium;

  const keyA = sodium.from_base64(publicIdentityKeyBase64, sodium.base64_variants.ORIGINAL);
  let combined: Uint8Array;

  if (counterpartKeyBase64) {
    const keyB = sodium.from_base64(counterpartKeyBase64, sodium.base64_variants.ORIGINAL);
    // Sort keys lexicographically to ensure symmetric fingerprint regardless of caller order
    const comparison = Buffer.compare(keyA, keyB);
    combined = comparison <= 0
      ? new Uint8Array([...keyA, ...keyB])
      : new Uint8Array([...keyB, ...keyA]);
  } else {
    combined = keyA;
  }

  // 32-byte BLAKE2b hash
  const hash = sodium.crypto_generichash(32, combined, null);

  // Convert first 15 bytes into 6 groups of 5-digit numbers
  const chunks: string[] = [];
  for (let i = 0; i < 6; i++) {
    const offset = i * 2;
    // 16-bit integer mapped to 0..99999
    const val = (hash[offset] << 8) | hash[offset + 1];
    const fiveDigit = String(val % 100000).padStart(5, '0');
    chunks.push(fiveDigit);
  }

  return chunks.join(' ');
}
