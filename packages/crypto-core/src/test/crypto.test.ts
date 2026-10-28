import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createClientIdentity,
  verifyPrekeySignature,
  computeSafetyFingerprint,
  generatePermanentIdentityQrPayload,
  generateEphemeralInvitationQrPayload,
  parseNizQrPayload,
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
});
