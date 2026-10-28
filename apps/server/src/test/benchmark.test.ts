import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { buildApp } from '../app.js';
import { MemoryStorageAdapter } from '../storage/memory.js';
import type { MessageEnvelope, PublicIdentity, PublicDevice } from '@niz/shared-types';

describe('Phase 10: Performance, Batch Ingestion & Queue Draining Benchmarks', () => {
  it('should efficiently ingest, paginate, and bulk-ack 200 message envelopes', async () => {
    const storage = new MemoryStorageAdapter();
    const app = await buildApp({ storage, rateLimitMax: 10000 });

    const alicePublicId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const bobPublicId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const aliceDeviceId = crypto.randomUUID();
    const bobDeviceId = crypto.randomUUID();

    // Register accounts and devices
    const aliceAccount: PublicIdentity = {
      publicId: alicePublicId,
      status: 'active',
      createdAt: new Date().toISOString(),
    };
    const bobAccount: PublicIdentity = {
      publicId: bobPublicId,
      status: 'active',
      createdAt: new Date().toISOString(),
    };
    await storage.createAccount(aliceAccount);
    await storage.createAccount(bobAccount);

    const aliceDevice: PublicDevice = {
      deviceId: aliceDeviceId,
      accountPublicId: alicePublicId,
      deviceName: 'Alice Phone',
      publicIdentityKey: crypto.randomBytes(32).toString('base64'),
      publicSignedPrekey: crypto.randomBytes(32).toString('base64'),
      signedPrekeySignature: crypto.randomBytes(64).toString('base64'),
      createdAt: new Date().toISOString(),
    };
    const bobDevice: PublicDevice = {
      deviceId: bobDeviceId,
      accountPublicId: bobPublicId,
      deviceName: 'Bob Laptop',
      publicIdentityKey: crypto.randomBytes(32).toString('base64'),
      publicSignedPrekey: crypto.randomBytes(32).toString('base64'),
      signedPrekeySignature: crypto.randomBytes(64).toString('base64'),
      createdAt: new Date().toISOString(),
    };
    await storage.createDevice(aliceDevice);
    await storage.createDevice(bobDevice);

    // Establish approved connection
    await storage.createConnectionRequest({
      id: crypto.randomUUID(),
      senderPublicId: alicePublicId,
      recipientPublicId: bobPublicId,
      state: 'approved',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // 1. Generate 200 ciphertext message envelopes
    const envelopes: MessageEnvelope[] = [];
    for (let i = 0; i < 200; i++) {
      envelopes.push({
        envelopeId: crypto.randomUUID(),
        senderPublicId: alicePublicId,
        senderDeviceId: aliceDeviceId,
        recipientPublicId: bobPublicId,
        recipientDeviceId: bobDeviceId,
        ratchetHeader: {
          dhPublicKey: crypto.randomBytes(32).toString('base64'),
          pn: 0,
          n: i,
        },
        ciphertext: crypto.randomBytes(64).toString('base64'),
        nonce: crypto.randomBytes(24).toString('base64'),
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      });
    }

    // Ingest via POST /v1/messages/batch
    const startTime = Date.now();
    const batchRes = await app.inject({
      method: 'POST',
      url: '/v1/messages/batch',
      payload: { envelopes },
    });
    const durationMs = Date.now() - startTime;

    assert.strictEqual(batchRes.statusCode, 202);
    const batchBody = JSON.parse(batchRes.body);
    assert.strictEqual(batchBody.success, true);
    assert.strictEqual(batchBody.count, 200);
    assert.strictEqual(batchBody.envelopeIds.length, 200);
    assert.ok(durationMs < 1000, `Batch ingestion took ${durationMs}ms, expected < 1000ms`);

    // 2. Paginate queue fetch with limit=50
    const pageRes = await app.inject({
      method: 'GET',
      url: `/v1/messages/queue/${bobDeviceId}?limit=50`,
    });
    assert.strictEqual(pageRes.statusCode, 200);
    const pageBody = JSON.parse(pageRes.body);
    assert.strictEqual(pageBody.count, 50);
    assert.strictEqual(pageBody.envelopes.length, 50);

    // 3. High-volume bulk ACK
    const allEnvelopeIds = envelopes.map((e) => e.envelopeId);
    const ackRes = await app.inject({
      method: 'POST',
      url: '/v1/messages/ack',
      payload: { envelopeIds: allEnvelopeIds },
    });
    assert.strictEqual(ackRes.statusCode, 200);
    const ackBody = JSON.parse(ackRes.body);
    assert.strictEqual(ackBody.success, true);
    assert.strictEqual(ackBody.purgedCount, 200);

    // Verify queue is now 0
    const countAfter = await storage.countQueuedMessages();
    assert.strictEqual(countAfter, 0);

    await app.close();
  });

  it('should handle 300 concurrent single message submissions without data race', async () => {
    const storage = new MemoryStorageAdapter();
    const app = await buildApp({ storage, rateLimitMax: 10000 });

    const alicePublicId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const bobPublicId = `niz_id_${crypto.randomBytes(16).toString('hex')}`;
    const aliceDeviceId = crypto.randomUUID();
    const bobDeviceId = crypto.randomUUID();

    await storage.createAccount({
      publicId: alicePublicId,
      status: 'active',
      createdAt: new Date().toISOString(),
    });
    await storage.createAccount({
      publicId: bobPublicId,
      status: 'active',
      createdAt: new Date().toISOString(),
    });

    await storage.createDevice({
      deviceId: aliceDeviceId,
      accountPublicId: alicePublicId,
      deviceName: 'Alice Dev',
      publicIdentityKey: 'keyA',
      publicSignedPrekey: 'preA',
      signedPrekeySignature: 'sigA',
      createdAt: new Date().toISOString(),
    });
    await storage.createDevice({
      deviceId: bobDeviceId,
      accountPublicId: bobPublicId,
      deviceName: 'Bob Dev',
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

    const requests = Array.from({ length: 300 }, (_, i) => ({
      envelopeId: crypto.randomUUID(),
      senderPublicId: alicePublicId,
      senderDeviceId: aliceDeviceId,
      recipientPublicId: bobPublicId,
      recipientDeviceId: bobDeviceId,
      ratchetHeader: {
        dhPublicKey: 'dhkey_dhkey_dhkey_dhkey_dhkey_32bytes',
        pn: 0,
        n: i,
      },
      ciphertext: `ciphertext_length_must_be_over_16_bytes_${i}`,
      nonce: 'nonce_length_over_12_bytes',
      protocolVersion: 'niz-dr-v1',
      createdAt: new Date().toISOString(),
    }));

    const responses = await Promise.all(
      requests.map((envelope) =>
        app.inject({
          method: 'POST',
          url: '/v1/messages',
          payload: envelope,
        })
      )
    );

    for (const res of responses) {
      assert.strictEqual(res.statusCode, 202);
    }

    const queuedCount = await storage.countQueuedMessages();
    assert.strictEqual(queuedCount, 300);

    // Purge all in one batch
    const purgeRes = await app.inject({
      method: 'POST',
      url: '/v1/messages/ack',
      payload: { envelopeIds: requests.map((r) => r.envelopeId) },
    });
    assert.strictEqual(purgeRes.statusCode, 200);
    assert.strictEqual(JSON.parse(purgeRes.body).purgedCount, 300);

    await app.close();
  });

  it('should reject batch containing private secrets immediately (invariant protection under load)', async () => {
    const storage = new MemoryStorageAdapter();
    const app = await buildApp({ storage, rateLimitMax: 10000 });

    const res = await app.inject({
      method: 'POST',
      url: '/v1/messages/batch',
      payload: {
        envelopes: [
          {
            envelopeId: crypto.randomUUID(),
            senderPublicId: 'niz_id_alice',
            senderDeviceId: 'dev_alice',
            recipientPublicId: 'niz_id_bob',
            recipientDeviceId: 'dev_bob',
            privateKey: 'secret_leak_attack',
            ratchetHeader: { dhPublicKey: 'dh', pn: 0, n: 0 },
            ciphertext: 'ct',
            nonce: 'nonce',
            protocolVersion: 'niz-dr-v1',
            createdAt: new Date().toISOString(),
          },
        ],
      },
    });

    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.error, 'BAD_REQUEST');
    assert.ok(body.message.toLowerCase().includes('forbidden'));

    await app.close();
  });
});
