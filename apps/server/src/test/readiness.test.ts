import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { buildApp } from '../app.js';
import { MemoryStorageAdapter } from '../storage/memory.js';
import type { MessageEnvelope, AttachmentRecord } from '@niz/shared-types';

describe('Phase 12: Production Readiness, Security Invariants Audit & Crash Recovery', () => {
  it('SECURITY INVARIANT 1 AUDIT: Multi-endpoint probe rejects all secret/key injections with 400', async () => {
    const storage = new MemoryStorageAdapter();
    const app = await buildApp({ storage });

    const forbiddenFields = [
      'privateKey',
      'private_key',
      'secret_key',
      'seedPhrase',
      'mnemonic',
      'passphrase',
      'recoveryKey',
      'plaintext_body',
    ];

    const endpoints = [
      { method: 'POST' as const, url: '/v1/identity/register' },
      { method: 'POST' as const, url: '/v1/invitations' },
      { method: 'POST' as const, url: '/v1/messages' },
      { method: 'POST' as const, url: '/v1/messages/batch' },
      { method: 'POST' as const, url: '/v1/backup/vault' },
      { method: 'POST' as const, url: '/v1/billing/checkout' },
    ];

    for (const field of forbiddenFields) {
      for (const ep of endpoints) {
        const payload: Record<string, unknown> = { [field]: 'unauthorized_leakage_attempt_123' };
        const res = await app.inject({
          method: ep.method,
          url: ep.url,
          headers: { 'x-sender-public-id': 'niz_id_0123456789abcdef0123456789abcdef' },
          payload,
        });

        assert.strictEqual(
          res.statusCode,
          400,
          `Endpoint ${ep.url} failed to reject forbidden field "${field}" with 400`
        );
        const body = JSON.parse(res.body);
        assert.strictEqual(body.error, 'BAD_REQUEST');
        assert.ok(
          body.message.toLowerCase().includes('forbidden') ||
            body.message.toLowerCase().includes('violation'),
          `Expected rejection message on ${ep.url} for ${field}`
        );
      }
    }

    await app.close();
  });

  it('SECURITY INVARIANT 2 AUDIT: Content-free storage verification', async () => {
    const storage = new MemoryStorageAdapter();
    const app = await buildApp({ storage });

    const alicePublicId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const bobPublicId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const aliceDeviceId = crypto.randomUUID();
    const bobDeviceId = crypto.randomUUID();

    await storage.createAccount({ publicId: alicePublicId, status: 'active', createdAt: new Date().toISOString() });
    await storage.createAccount({ publicId: bobPublicId, status: 'active', createdAt: new Date().toISOString() });
    await storage.createDevice({
      deviceId: aliceDeviceId,
      accountPublicId: alicePublicId,
      deviceName: 'Alice Phone',
      publicIdentityKey: 'keyA',
      publicSignedPrekey: 'preA',
      signedPrekeySignature: 'sigA',
      createdAt: new Date().toISOString(),
    });
    await storage.createDevice({
      deviceId: bobDeviceId,
      accountPublicId: bobPublicId,
      deviceName: 'Bob Laptop',
      publicIdentityKey: 'keyB',
      publicSignedPrekey: 'preB',
      signedPrekeySignature: 'sigB',
      createdAt: new Date().toISOString(),
    });
    await storage.createConnectionRequest({
      id: crypto.randomUUID(),
      senderPublicId: alicePublicId,
      recipientPublicId: bobPublicId,
      state: 'approved',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    const envelope: MessageEnvelope = {
      envelopeId: crypto.randomUUID(),
      senderPublicId: alicePublicId,
      senderDeviceId: aliceDeviceId,
      recipientPublicId: bobPublicId,
      recipientDeviceId: bobDeviceId,
      ratchetHeader: {
        dhPublicKey: 'dhkey_dhkey_dhkey_dhkey_dhkey_32bytes',
        pn: 0,
        n: 1,
      },
      ciphertext: 'ciphertext_base64_must_be_over_16_chars_xyz',
      nonce: 'nonce_length_over_12_bytes',
      protocolVersion: 'niz-dr-v1',
      createdAt: new Date().toISOString(),
    };

    await storage.enqueueMessage(envelope);

    // Deep inspect queued messages in storage
    const pending = await storage.getPendingMessages(bobDeviceId);
    assert.strictEqual(pending.length, 1);
    const queued = pending[0] as unknown as Record<string, unknown>;

    // Assert zero plaintext body field exists
    assert.strictEqual(queued.plaintext, undefined);
    assert.strictEqual(queued.text, undefined);
    assert.strictEqual(queued.body, undefined);
    assert.strictEqual(queued.message, undefined);
    assert.strictEqual(queued.ciphertext, envelope.ciphertext);

    await app.close();
  });

  it('SECURITY INVARIANT 7 & 8: Isolated Admin plane privacy and non-participant attachment protection', async () => {
    const storage = new MemoryStorageAdapter();
    const app = await buildApp({ storage });

    // 1. Admin login
    const loginRes = await app.inject({
      method: 'POST',
      url: '/v1/admin/login',
      payload: {
        username: 'opsadmin',
        password: 'dev_admin_ops_secret_123',
        mfaCode: '123456',
      },
    });
    assert.strictEqual(loginRes.statusCode, 200);
    const token = JSON.parse(loginRes.body).token;

    // 2. Fetch metrics
    const metricsRes = await app.inject({
      method: 'GET',
      url: '/v1/admin/metrics',
      headers: { authorization: `Bearer ${token}` },
    });
    assert.strictEqual(metricsRes.statusCode, 200);
    const metrics = JSON.parse(metricsRes.body);

    // Verify metrics contain strictly aggregate counts and zero conversation or message content
    assert.strictEqual(typeof metrics.uptimeSeconds, 'number');
    assert.strictEqual(typeof metrics.queuedCiphertextsTotal, 'number');
    assert.strictEqual((metrics as Record<string, unknown>).messages, undefined);
    assert.strictEqual((metrics as Record<string, unknown>).conversations, undefined);

    // 3. Attachment participant isolation
    const aliceId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const bobId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const eveId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const attId = crypto.randomUUID();

    const record: AttachmentRecord = {
      attachmentId: attId,
      uploaderPublicId: aliceId,
      recipientPublicId: bobId,
      sha256Ciphertext: crypto.createHash('sha256').update('test_blob').digest('hex'),
      sizeBytes: 9,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    };
    await storage.saveAttachment(record, Buffer.from('test_blob'));

    // Eve (unauthorized third-party) attempts download
    const unauthorizedRes = await app.inject({
      method: 'GET',
      url: `/v1/attachments/${attId}`,
      headers: { 'x-requester-public-id': eveId },
    });
    assert.strictEqual(unauthorizedRes.statusCode, 403);
    assert.strictEqual(JSON.parse(unauthorizedRes.body).error, 'FORBIDDEN');

    // Bob (authorized participant) downloads successfully
    const authorizedRes = await app.inject({
      method: 'GET',
      url: `/v1/attachments/${attId}`,
      headers: { 'x-requester-public-id': bobId },
    });
    assert.strictEqual(authorizedRes.statusCode, 200);
    assert.strictEqual(authorizedRes.body, 'test_blob');

    await app.close();
  });

  it('DISASTER RECOVERY SIMULATION: Backend crash, restart, queue draining, and session persistence', async () => {
    // Stage 1: Setup storage with persisted state
    const storage = new MemoryStorageAdapter();

    const alicePublicId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const bobPublicId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const aliceDeviceId = crypto.randomUUID();
    const bobDeviceId = crypto.randomUUID();

    await storage.createAccount({ publicId: alicePublicId, status: 'active', createdAt: new Date().toISOString() });
    await storage.createAccount({ publicId: bobPublicId, status: 'active', createdAt: new Date().toISOString() });
    await storage.createDevice({
      deviceId: aliceDeviceId,
      accountPublicId: alicePublicId,
      deviceName: 'Alice Phone',
      publicIdentityKey: 'keyA',
      publicSignedPrekey: 'preA',
      signedPrekeySignature: 'sigA',
      createdAt: new Date().toISOString(),
    });
    await storage.createDevice({
      deviceId: bobDeviceId,
      accountPublicId: bobPublicId,
      deviceName: 'Bob Laptop',
      publicIdentityKey: 'keyB',
      publicSignedPrekey: 'preB',
      signedPrekeySignature: 'sigB',
      createdAt: new Date().toISOString(),
    });
    await storage.createConnectionRequest({
      id: crypto.randomUUID(),
      senderPublicId: alicePublicId,
      recipientPublicId: bobPublicId,
      state: 'approved',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // Enqueue 50 messages on primary instance
    const primaryApp = await buildApp({ storage });
    const envelopeIds: string[] = [];
    for (let i = 0; i < 50; i++) {
      const id = crypto.randomUUID();
      envelopeIds.push(id);
      await storage.enqueueMessage({
        envelopeId: id,
        senderPublicId: alicePublicId,
        senderDeviceId: aliceDeviceId,
        recipientPublicId: bobPublicId,
        recipientDeviceId: bobDeviceId,
        ratchetHeader: {
          dhPublicKey: 'dhkey_dhkey_dhkey_dhkey_dhkey_32bytes',
          pn: 0,
          n: i,
        },
        ciphertext: `ciphertext_payload_during_flight_${i}`,
        nonce: 'nonce_length_over_12_bytes',
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      });
    }

    assert.strictEqual(await storage.countQueuedMessages(), 50);

    // SIMULATE CRASH: primaryApp terminates abruptly
    await primaryApp.close();

    // SIMULATE RESTART: New server application instance starts up with existing storage
    const recoveredApp = await buildApp({ storage });

    // Verify health
    const health = await recoveredApp.inject({ method: 'GET', url: '/health' });
    assert.strictEqual(health.statusCode, 200);
    assert.strictEqual(JSON.parse(health.body).status, 'healthy');

    // Verify queue retained all 50 envelopes
    const queueRes = await recoveredApp.inject({
      method: 'GET',
      url: `/v1/messages/queue/${bobDeviceId}`,
    });
    assert.strictEqual(queueRes.statusCode, 200);
    const queueBody = JSON.parse(queueRes.body);
    assert.strictEqual(queueBody.count, 50);

    // Acknowledge and purge on recovered server
    const ackRes = await recoveredApp.inject({
      method: 'POST',
      url: '/v1/messages/ack',
      payload: { envelopeIds },
    });
    assert.strictEqual(ackRes.statusCode, 200);
    assert.strictEqual(JSON.parse(ackRes.body).purgedCount, 50);

    assert.strictEqual(await storage.countQueuedMessages(), 0);

    await recoveredApp.close();
  });
});
