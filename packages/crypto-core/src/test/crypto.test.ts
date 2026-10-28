import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import _sodium from 'libsodium-wrappers-sumo';
import {
  createClientIdentity,
  verifyPrekeySignature,
  computeSafetyFingerprint,
  generatePermanentIdentityQrPayload,
  generateEphemeralInvitationQrPayload,
  parseNizQrPayload,
  initAliceSession,
  initBobSession,
  ratchetEncrypt,
  ratchetDecrypt,
  encryptAttachment,
  decryptAttachment,
  createEncryptedBackup,
  restoreEncryptedBackup,
} from '../index.js';

describe('NIZ Crypto Core & QR Lifecycle (Phase 2)', () => {
  it('createClientIdentity generates valid cryptographic identity & signed prekey', async () => {
    const deviceId = crypto.randomUUID();
    const identity = await createClientIdentity(deviceId, 'Test Device');

    assert.ok(identity.publicId.startsWith('niz_id_'));
    assert.equal(identity.publicId.length, 7 + 40); // 'niz_id_' + 40 hex chars
    assert.equal(identity.deviceId, deviceId);
    assert.ok(identity.publicIdentityKeyBase64.length > 20);
    assert.ok(identity.publicSignedPrekeyBase64.length > 20);
    assert.ok(identity.signedPrekeySignatureBase64.length > 40);
    assert.ok(identity.safetyFingerprint.split(' ').length === 6);

    // Verify client private keys exist locally
    assert.ok(identity.privateKeys.privateIdentityKeyBase64.length > 20);
    assert.ok(identity.privateKeys.privateSignedPrekeyBase64.length > 20);

    // Verify registration payload has NO private keys
    assert.equal(identity.registrationPayload.publicId, identity.publicId);
    assert.equal(identity.registrationPayload.device.deviceId, deviceId);
    assert.equal((identity.registrationPayload as unknown as Record<string, unknown>).privateKeys, undefined);

    // Verify prekey signature is cryptographically valid
    const isValid = await verifyPrekeySignature(
      identity.publicIdentityKeyBase64,
      identity.publicSignedPrekeyBase64,
      identity.signedPrekeySignatureBase64
    );
    assert.equal(isValid, true);
  });

  it('verifyPrekeySignature rejects tampered prekey', async () => {
    const deviceId = crypto.randomUUID();
    const identity = await createClientIdentity(deviceId);

    // Tamper with prekey by altering one character
    const tamperedPrekey = Buffer.from('completely-tampered-fake-prekey-32b').toString('base64');

    const isValid = await verifyPrekeySignature(
      identity.publicIdentityKeyBase64,
      tamperedPrekey,
      identity.signedPrekeySignatureBase64
    );
    assert.equal(isValid, false);
  });

  it('computeSafetyFingerprint produces symmetric, order-independent fingerprints', async () => {
    const keyA = Buffer.from('identity-public-key-user-alice-32b').toString('base64');
    const keyB = Buffer.from('identity-public-key-user-bob---32b').toString('base64');

    const fpAB = await computeSafetyFingerprint(keyA, keyB);
    const fpBA = await computeSafetyFingerprint(keyB, keyA);

    assert.equal(fpAB, fpBA);
    assert.match(fpAB, /^\d{5} \d{5} \d{5} \d{5} \d{5} \d{5}$/);
  });

  it('Permanent Identity QR encodes public info and zero bearer credentials', async () => {
    const deviceId = crypto.randomUUID();
    const identity = await createClientIdentity(deviceId);

    const qrUri = generatePermanentIdentityQrPayload(
      identity.publicId,
      identity.publicIdentityKeyBase64,
      identity.safetyFingerprint
    );

    assert.ok(qrUri.startsWith(`niz:id:${identity.publicId}`));
    assert.ok(!qrUri.includes('private'));
    assert.ok(!qrUri.includes('token'));

    const parsed = parseNizQrPayload(qrUri);
    assert.equal(parsed.type, 'permanent_identity');
    if (parsed.type === 'permanent_identity') {
      assert.equal(parsed.publicId, identity.publicId);
      assert.equal(parsed.publicIdentityKeyBase64, identity.publicIdentityKeyBase64);
      assert.equal(parsed.fingerprint, identity.safetyFingerprint);
    }
  });

  it('Ephemeral Invitation QR parses and round-trips correctly', () => {
    const fakeToken = crypto.randomBytes(32).toString('hex');
    const creatorPublicId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 3600000).toISOString();

    const qrUri = generateEphemeralInvitationQrPayload(fakeToken, creatorPublicId, expiresAt, true);

    const parsed = parseNizQrPayload(qrUri);
    assert.equal(parsed.type, 'ephemeral_invitation');
    if (parsed.type === 'ephemeral_invitation') {
      assert.equal(parsed.invitationToken, fakeToken);
      assert.equal(parsed.creatorPublicId, creatorPublicId);
      assert.equal(parsed.expiresAt, expiresAt);
      assert.equal(parsed.isSingleUse, true);
    }
  });

  it('Negative test: parseNizQrPayload rejects malformed strings', () => {
    assert.throws(() => parseNizQrPayload('https://malicious-site.com'), /Unrecognized NIZ QR/);
    assert.throws(() => parseNizQrPayload('niz:id:invalid_id?ik=test&fp=test'), /Invalid Public ID/);
    assert.throws(() => parseNizQrPayload('niz:invite:short?creator=foo'), /Invalid or corrupted/);
  });

  it('Phase 4: Double Ratchet session ping-pong, burst, and out-of-order delivery', async () => {
    await _sodium.ready;
    const sodium = _sodium;

    // Simulate initial shared master secret established via X3DH handshake
    const sharedMasterSecret = crypto.randomBytes(32);
    const bobDhKeyPair = sodium.crypto_kx_keypair();
    const bobDhPubBase64 = sodium.to_base64(bobDhKeyPair.publicKey, sodium.base64_variants.ORIGINAL);

    // Initialize Alice and Bob
    const aliceSession = await initAliceSession(sharedMasterSecret, bobDhPubBase64);
    const bobSession = await initBobSession(sharedMasterSecret, bobDhKeyPair);

    // 1. Alice sends message to Bob
    const msg1 = await ratchetEncrypt(aliceSession, 'Hello Bob! This is message 1');
    const decrypted1 = await ratchetDecrypt(bobSession, msg1);
    assert.equal(decrypted1, 'Hello Bob! This is message 1');

    // 2. Bob replies to Alice (DH Ratchet step triggered)
    const reply1 = await ratchetEncrypt(bobSession, 'Hi Alice! Received message 1 loud and clear');
    const decryptedReply1 = await ratchetDecrypt(aliceSession, reply1);
    assert.equal(decryptedReply1, 'Hi Alice! Received message 1 loud and clear');

    // 3. Alice sends a burst of 3 consecutive messages before Bob replies
    const burstA = await ratchetEncrypt(aliceSession, 'Burst message A');
    const burstB = await ratchetEncrypt(aliceSession, 'Burst message B');
    const burstC = await ratchetEncrypt(aliceSession, 'Burst message C');

    // 4. Out-of-Order Delivery: Bob receives burstC first, then burstA, then burstB
    const decC = await ratchetDecrypt(bobSession, burstC);
    assert.equal(decC, 'Burst message C');

    const decA = await ratchetDecrypt(bobSession, burstA);
    assert.equal(decA, 'Burst message A');

    const decB = await ratchetDecrypt(bobSession, burstB);
    assert.equal(decB, 'Burst message B');

    // 5. Replay Attack Test: Attempt to replay burstB -> Must throw error!
    await assert.rejects(
      async () => {
        await ratchetDecrypt(bobSession, burstB);
      },
      /AEAD Decryption failed/
    );

    // 6. Tampering Test: Modify one byte of ciphertext -> Must fail MAC verification!
    const tamperedPayload = { ...burstA, ciphertext: 'AAAA' + burstA.ciphertext.slice(4) };
    await assert.rejects(
      async () => {
        await ratchetDecrypt(bobSession, tamperedPayload);
      },
      /AEAD Decryption failed: MAC verification failed/
    );
  });

  it('Phase 6: Client-side attachment encryption, integrity verification, and tamper rejection', async () => {
    const originalContent = new TextEncoder().encode('Confidential contract signed document content: NIZ Chat E2EE attachment.');
    const mimeType = 'text/plain';
    const filename = 'contract.txt';

    // 1. Client encrypts attachment
    const { ciphertext, metadata } = await encryptAttachment(originalContent, mimeType, filename);

    assert.ok(ciphertext.length > originalContent.length); // AEAD overhead (tag)
    assert.equal(metadata.mimeType, mimeType);
    assert.equal(metadata.filename, filename);
    assert.equal(metadata.byteSize, originalContent.length);
    assert.equal(metadata.mediaKey.length, 64); // 32 bytes hex
    assert.equal(metadata.nonce.length, 48); // 24 bytes hex
    assert.equal(metadata.sha256.length, 64); // 32 bytes SHA-256 hex

    // 2. Client decrypts attachment
    const decrypted = await decryptAttachment(ciphertext, metadata);
    assert.deepEqual(decrypted, originalContent);
    assert.equal(new TextDecoder().decode(decrypted), 'Confidential contract signed document content: NIZ Chat E2EE attachment.');

    // 3. Negative Security Invariant: SHA-256 mismatch rejection
    const alteredMetadata = { ...metadata, sha256: '0'.repeat(64) };
    await assert.rejects(
      async () => {
        await decryptAttachment(ciphertext, alteredMetadata);
      },
      /ATTACHMENT_INTEGRITY_ERROR/
    );

    // 4. Negative Security Invariant: Tampered ciphertext rejection
    const tamperedCiphertext = new Uint8Array(ciphertext);
    tamperedCiphertext[10] ^= 0xff; // Flip bits
    // Recompute sha256 so hash check passes, but AEAD MAC authentication fails
    const _s = _sodium;
    await _s.ready;
    const tamperedHash = _s.to_hex(_s.crypto_hash_sha256(tamperedCiphertext));
    const tamperedHashMetadata = { ...metadata, sha256: tamperedHash };

    await assert.rejects(
      async () => {
        await decryptAttachment(tamperedCiphertext, tamperedHashMetadata);
      },
      /ATTACHMENT_DECRYPTION_FAILED/
    );
  });

  it('Phase 7: Argon2id encrypted backup vault creation, restoration, and authentication boundaries', async () => {
    const backupData = {
      publicId: 'niz_id_11223344556677889900aabbccddeeff00112233',
      privateIdentityKeyBase64: Buffer.from('mock-private-identity-key-32b-str').toString('base64'),
      privateSignedPrekeyBase64: Buffer.from('mock-private-signed-prekey-32b-st').toString('base64'),
      contacts: [
        {
          counterpartPublicId: 'niz_id_99887766554433221100ffeeddccbbaa00112233',
          counterpartIdentityKey: Buffer.from('mock-counterpart-public-id-key--').toString('base64'),
          verified: true,
        },
      ],
      exportedAt: new Date().toISOString(),
    };

    const strongPassphrase = 'correct horse battery staple 2026';

    // 1. Create encrypted backup vault
    const vault = await createEncryptedBackup(strongPassphrase, backupData);

    assert.equal(vault.version, 1);
    assert.equal(vault.algorithm, 'argon2id-xchacha20poly1305');
    assert.equal(vault.kdf.salt.length, 32); // 16 bytes hex
    assert.equal(vault.nonce.length, 48); // 24 bytes hex
    assert.ok(vault.ciphertext.length > 50);

    // 2. Restore backup vault with correct passphrase
    const restored = await restoreEncryptedBackup(strongPassphrase, vault);
    assert.equal(restored.publicId, backupData.publicId);
    assert.equal(restored.privateIdentityKeyBase64, backupData.privateIdentityKeyBase64);
    assert.equal(restored.privateSignedPrekeyBase64, backupData.privateSignedPrekeyBase64);
    assert.equal(restored.contacts.length, 1);
    assert.equal(restored.contacts[0].counterpartPublicId, backupData.contacts[0].counterpartPublicId);
    assert.equal(restored.contacts[0].verified, true);

    // 3. Negative Security Invariant: Wrong passphrase rejection
    await assert.rejects(
      async () => {
        await restoreEncryptedBackup('incorrect-wrong-passphrase', vault);
      },
      /VAULT_RESTORE_FAILED/
    );

    // 4. Negative Security Invariant: Tampered vault ciphertext rejection
    const tamperedVault = {
      ...vault,
      ciphertext: Buffer.from('corrupted-tampered-ciphertext-payload-bytes-now-invalid').toString('base64'),
    };
    await assert.rejects(
      async () => {
        await restoreEncryptedBackup(strongPassphrase, tamperedVault);
      },
      /VAULT_RESTORE_FAILED/
    );

    // 5. Negative Security Invariant: Weak/short passphrase rejection (<8 chars)
    await assert.rejects(
      async () => {
        await createEncryptedBackup('short', backupData);
      },
      /Passphrase must be at least 8 characters long/
    );
  });
});
