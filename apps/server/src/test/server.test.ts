import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { WebSocket } from 'ws';
import { buildApp } from '../app.js';
import { MemoryStorageAdapter } from '../storage/memory.js';

describe('NIZ Chat Server & Security Invariants', () => {
  let app: FastifyInstance;
  let storage: MemoryStorageAdapter;

  before(async () => {
    storage = new MemoryStorageAdapter();
    app = await buildApp({ storage });
    await app.ready();
  });

  after(async () => {
    await app.close();
  });

  it('GET /health returns 200 with server status', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/health',
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.status, 'healthy');
    assert.equal(typeof body.uptimeSeconds, 'number');
    assert.equal(body.queuedMessagesTotal, 0);
  });

  it('POST /v1/identity/register registers public identity and device', async () => {
    const validPublicId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const deviceId = crypto.randomUUID();

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: validPublicId,
        device: {
          deviceId,
          publicIdentityKey: Buffer.from('mock-public-identity-key-32-bytes').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-public-prekey-32-bytes-long').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
          deviceName: 'Web Browser Alpha',
        },
      },
    });

    assert.equal(res.statusCode, 201);
    const body = JSON.parse(res.body);
    assert.equal(body.success, true);
    assert.equal(body.publicId, validPublicId);
    assert.equal(body.deviceId, deviceId);
  });

  it('SECURITY INVARIANT 1: Rejects payload with private key or secret fields', async () => {
    const validPublicId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const deviceId = crypto.randomUUID();

    // Attacker or buggy client attempting to upload private key
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: validPublicId,
        device: {
          deviceId,
          publicIdentityKey: Buffer.from('mock-public-identity-key-32-bytes').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-public-prekey-32-bytes-long').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
          private_key: 'super-secret-private-key-leak', // FORBIDDEN
        },
      },
    });

    assert.equal(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert.equal(body.error, 'BAD_REQUEST');
    assert.match(body.message, /SECURITY INVARIANT VIOLATION/);
  });

  it('Ephemeral Invitations: Lifecycle, expiry, and single-use enforcement', async () => {
    const creatorPublicId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const deviceId = crypto.randomUUID();

    // Register creator
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: creatorPublicId,
        device: {
          deviceId,
          publicIdentityKey: Buffer.from('mock-public-identity-key-32-bytes').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-public-prekey-32-bytes-long').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // Create 1-hour single-use invitation
    const createRes = await app.inject({
      method: 'POST',
      url: '/v1/invitations',
      payload: {
        creatorPublicId,
        expiresInSeconds: 3600,
        isSingleUse: true,
      },
    });

    assert.equal(createRes.statusCode, 201);
    const invData = JSON.parse(createRes.body);
    assert.ok(invData.invitationToken);
    assert.equal(invData.isSingleUse, true);

    // Resolve invitation
    const resolveRes = await app.inject({
      method: 'POST',
      url: '/v1/invitations/resolve',
      payload: {
        invitationToken: invData.invitationToken,
      },
    });
    assert.equal(resolveRes.statusCode, 200);
    const resolved = JSON.parse(resolveRes.body);
    assert.equal(resolved.valid, true);
    assert.equal(resolved.creatorPublicId, creatorPublicId);

    // Revocation test: Creator revokes the invitation
    const revokeRes = await app.inject({
      method: 'POST',
      url: `/v1/invitations/${invData.invitationId}/revoke`,
      headers: { 'x-sender-public-id': creatorPublicId },
    });
    assert.equal(revokeRes.statusCode, 200);

    // Resolving after revocation must fail closed
    const resolveAfterRevoke = await app.inject({
      method: 'POST',
      url: '/v1/invitations/resolve',
      payload: {
        invitationToken: invData.invitationToken,
      },
    });
    assert.equal(resolveAfterRevoke.statusCode, 400);
    assert.equal(JSON.parse(resolveAfterRevoke.body).reason, 'revoked');
  });

  it('Single-use invitation prevents replay and concurrent reuse', async () => {
    const creatorPublicId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const deviceId = crypto.randomUUID();

    // Register creator
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: creatorPublicId,
        device: {
          deviceId,
          publicIdentityKey: Buffer.from('mock-creator-identity-key-32-bytes').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-creator-prekey-32-bytes-long').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // Create single-use invitation
    const createRes = await app.inject({
      method: 'POST',
      url: '/v1/invitations',
      payload: {
        creatorPublicId,
        expiresInSeconds: 1800,
        isSingleUse: true,
      },
    });
    const { invitationToken } = JSON.parse(createRes.body);

    // Register user 1
    const user1PublicId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: user1PublicId,
        device: {
          deviceId: crypto.randomUUID(),
          publicIdentityKey: Buffer.from('mock-user1-identity-key-32-bytes--').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-user1-prekey-32-bytes-long---').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // User 1 uses token to send connection request -> succeeds
    const conn1 = await app.inject({
      method: 'POST',
      url: '/v1/connection-requests',
      headers: { 'x-sender-public-id': user1PublicId },
      payload: {
        recipientPublicId: creatorPublicId,
        invitationToken,
      },
    });
    assert.equal(conn1.statusCode, 201);

    // Register user 2
    const user2PublicId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: user2PublicId,
        device: {
          deviceId: crypto.randomUUID(),
          publicIdentityKey: Buffer.from('mock-user2-identity-key-32-bytes--').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-user2-prekey-32-bytes-long---').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // User 2 attempts to reuse the single-use token -> fails with 400!
    const conn2 = await app.inject({
      method: 'POST',
      url: '/v1/connection-requests',
      headers: { 'x-sender-public-id': user2PublicId },
      payload: {
        recipientPublicId: creatorPublicId,
        invitationToken,
      },
    });
    assert.equal(conn2.statusCode, 400);
    assert.equal(JSON.parse(conn2.body).error, 'INVITATION_ALREADY_REDEEMED');
  });

  it('SECURITY INVARIANT 3: Recipient approval required before messaging', async () => {
    const aliceId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const bobId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const aliceDeviceId = crypto.randomUUID();
    const bobDeviceId = crypto.randomUUID();

    // Register Alice
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: aliceId,
        device: {
          deviceId: aliceDeviceId,
          publicIdentityKey: Buffer.from('alice-public-identity-key-32-bytes').toString('base64'),
          publicSignedPrekey: Buffer.from('alice-public-prekey-32-bytes-long').toString('base64'),
          signedPrekeySignature: Buffer.from('alice-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // Register Bob
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: bobId,
        device: {
          deviceId: bobDeviceId,
          publicIdentityKey: Buffer.from('bob-public-identity-key-32-bytes-').toString('base64'),
          publicSignedPrekey: Buffer.from('bob-public-prekey-32-bytes-long-').toString('base64'),
          signedPrekeySignature: Buffer.from('bob-signature-64-bytes-long-padding-bytes-for-test-').toString('base64'),
        },
      },
    });

    // Alice attempts to send a message to Bob BEFORE connection approval
    const unauthorizedMsgRes = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        envelopeId: crypto.randomUUID(),
        senderPublicId: aliceId,
        senderDeviceId: aliceDeviceId,
        recipientPublicId: bobId,
        recipientDeviceId: bobDeviceId,
        ratchetHeader: {
          dhPublicKey: Buffer.from('ratchet-ephemeral-dh-key-32-bytes').toString('base64'),
          pn: 0,
          n: 0,
        },
        ciphertext: Buffer.from('opaque-encrypted-ciphertext-bytes').toString('base64'),
        nonce: Buffer.from('12-byte-nonce-here').toString('base64'),
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      },
    });

    // Must be rejected with 403 Forbidden!
    assert.equal(unauthorizedMsgRes.statusCode, 403);
    const unauthBody = JSON.parse(unauthorizedMsgRes.body);
    assert.equal(unauthBody.error, 'FORBIDDEN');

    // Now Alice sends a connection request to Bob
    const connReqRes = await app.inject({
      method: 'POST',
      url: '/v1/connection-requests',
      headers: { 'x-sender-public-id': aliceId },
      payload: { recipientPublicId: bobId },
    });
    assert.equal(connReqRes.statusCode, 201);
    const reqData = JSON.parse(connReqRes.body);

    // Bob approves the connection
    const approveRes = await app.inject({
      method: 'POST',
      url: '/v1/connection-requests/decision',
      headers: { 'x-recipient-public-id': bobId },
      payload: {
        requestId: reqData.requestId,
        decision: 'approve',
      },
    });
    assert.equal(approveRes.statusCode, 200);

    // Now Alice sends the message again — it must succeed (202 Accepted)
    const envelopeId = crypto.randomUUID();
    const authorizedMsgRes = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        envelopeId,
        senderPublicId: aliceId,
        senderDeviceId: aliceDeviceId,
        recipientPublicId: bobId,
        recipientDeviceId: bobDeviceId,
        ratchetHeader: {
          dhPublicKey: Buffer.from('ratchet-ephemeral-dh-key-32-bytes').toString('base64'),
          pn: 0,
          n: 0,
        },
        ciphertext: Buffer.from('opaque-encrypted-ciphertext-bytes').toString('base64'),
        nonce: Buffer.from('12-byte-nonce-here').toString('base64'),
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      },
    });

    assert.equal(authorizedMsgRes.statusCode, 202);

    // Bob fetches his queued messages
    const queueRes = await app.inject({
      method: 'GET',
      url: `/v1/messages/queue/${bobDeviceId}`,
    });
    assert.equal(queueRes.statusCode, 200);
    const queueData = JSON.parse(queueRes.body);
    assert.equal(queueData.envelopes.length, 1);
    assert.equal(queueData.envelopes[0].envelopeId, envelopeId);

    // Bob acknowledges message receipt -> server purges ciphertext
    const ackRes = await app.inject({
      method: 'POST',
      url: '/v1/messages/ack',
      payload: { envelopeIds: [envelopeId] },
    });
    assert.equal(ackRes.statusCode, 200);
    assert.equal(JSON.parse(ackRes.body).purgedCount, 1);

    // Verify queue is now empty
    const emptyQueueRes = await app.inject({
      method: 'GET',
      url: `/v1/messages/queue/${bobDeviceId}`,
    });
    assert.equal(JSON.parse(emptyQueueRes.body).envelopes.length, 0);
  });

  it('Phase 3: Contact lifecycle, blocking, unblocking, removal, and abuse reporting', async () => {
    const userA = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const userB = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const devA = crypto.randomUUID();
    const devB = crypto.randomUUID();

    // Register User A
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: userA,
        device: {
          deviceId: devA,
          publicIdentityKey: Buffer.from('mock-userA-identity-key-32-bytes').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-userA-prekey-32-bytes-long').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // Register User B
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: userB,
        device: {
          deviceId: devB,
          publicIdentityKey: Buffer.from('mock-userB-identity-key-32-bytes').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-userB-prekey-32-bytes-long').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // A requests B
    const reqRes = await app.inject({
      method: 'POST',
      url: '/v1/connection-requests',
      headers: { 'x-sender-public-id': userA },
      payload: { recipientPublicId: userB },
    });
    const { requestId } = JSON.parse(reqRes.body);

    // B approves A
    await app.inject({
      method: 'POST',
      url: '/v1/connection-requests/decision',
      headers: { 'x-recipient-public-id': userB },
      payload: { requestId, decision: 'approve' },
    });

    // Check contact list for user A
    const listA = await app.inject({
      method: 'GET',
      url: `/v1/contacts/${userA}`,
    });
    assert.equal(listA.statusCode, 200);
    const contactsA = JSON.parse(listA.body).contacts;
    assert.equal(contactsA.length, 1);
    assert.equal(contactsA[0].counterpartPublicId, userB);
    assert.equal(contactsA[0].state, 'approved');

    // B blocks A
    const blockRes = await app.inject({
      method: 'POST',
      url: '/v1/contacts/block',
      headers: { 'x-sender-public-id': userB },
      payload: { targetPublicId: userA },
    });
    assert.equal(blockRes.statusCode, 200);

    // A tries to message B while blocked -> MUST fail with 403 Forbidden!
    const blockedMsgRes = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        envelopeId: crypto.randomUUID(),
        senderPublicId: userA,
        senderDeviceId: devA,
        recipientPublicId: userB,
        recipientDeviceId: devB,
        ratchetHeader: {
          dhPublicKey: Buffer.from('ratchet-ephemeral-dh-key-32-bytes').toString('base64'),
          pn: 0,
          n: 0,
        },
        ciphertext: Buffer.from('opaque-encrypted-ciphertext-bytes').toString('base64'),
        nonce: Buffer.from('12-byte-nonce-here').toString('base64'),
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      },
    });
    assert.equal(blockedMsgRes.statusCode, 403);

    // B unblocks A
    const unblockRes = await app.inject({
      method: 'POST',
      url: '/v1/contacts/unblock',
      headers: { 'x-sender-public-id': userB },
      payload: { targetPublicId: userA },
    });
    assert.equal(unblockRes.statusCode, 200);
    assert.equal(JSON.parse(unblockRes.body).state, 'approved');

    // A reports B for spam
    const reportRes = await app.inject({
      method: 'POST',
      url: '/v1/reports',
      headers: { 'x-sender-public-id': userA },
      payload: {
        reportedPublicId: userB,
        category: 'spam',
        reason: 'Unsolicited promotional requests',
      },
    });
    assert.equal(reportRes.statusCode, 201);
    assert.ok(JSON.parse(reportRes.body).reportId);

    // B removes contact A
    const removeRes = await app.inject({
      method: 'DELETE',
      url: `/v1/contacts/${userA}`,
      headers: { 'x-sender-public-id': userB },
    });
    assert.equal(removeRes.statusCode, 200);
    assert.equal(JSON.parse(removeRes.body).removed, true);

    // After removal, messaging must be rejected with 403 Forbidden!
    const postRemovalMsgRes = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        envelopeId: crypto.randomUUID(),
        senderPublicId: userA,
        senderDeviceId: devA,
        recipientPublicId: userB,
        recipientDeviceId: devB,
        ratchetHeader: {
          dhPublicKey: Buffer.from('ratchet-ephemeral-dh-key-32-bytes').toString('base64'),
          pn: 0,
          n: 0,
        },
        ciphertext: Buffer.from('opaque-encrypted-ciphertext-bytes').toString('base64'),
        nonce: Buffer.from('12-byte-nonce-here').toString('base64'),
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      },
    });
    assert.equal(postRemovalMsgRes.statusCode, 403);
  });

  it('Phase 4: Real-time WebSocket delivery of ciphertext envelopes', async () => {
    // Start listening on dynamic port for WebSocket tests
    await app.listen({ port: 0, host: '127.0.0.1' });
    const port = (app.server.address() as { port: number }).port;

    const aliceId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const bobId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const aliceDevId = crypto.randomUUID();
    const bobDevId = crypto.randomUUID();

    // Register Alice & Bob
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: aliceId,
        device: {
          deviceId: aliceDevId,
          publicIdentityKey: Buffer.from('mock-alice-identity-key-32-bytes').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-alice-prekey-32-bytes-long').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: bobId,
        device: {
          deviceId: bobDevId,
          publicIdentityKey: Buffer.from('mock-bob-identity-key-32-bytes--').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-bob-prekey-32-bytes-long---').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // Establish approved connection
    const reqRes = await app.inject({
      method: 'POST',
      url: '/v1/connection-requests',
      headers: { 'x-sender-public-id': aliceId },
      payload: { recipientPublicId: bobId },
    });
    const { requestId } = JSON.parse(reqRes.body);

    await app.inject({
      method: 'POST',
      url: '/v1/connection-requests/decision',
      headers: { 'x-recipient-public-id': bobId },
      payload: { requestId, decision: 'approve' },
    });

    // Bob connects to WebSocket
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/ws?deviceId=${bobDevId}`);
    await new Promise((resolve, reject) => {
      ws.on('open', resolve);
      ws.on('error', reject);
    });

    // Set up message reception listener
    const receivedPromise = new Promise<Record<string, unknown>>((resolve) => {
      ws.on('message', (data) => {
        resolve(JSON.parse(data.toString()));
      });
    });

    // Alice sends a ciphertext envelope
    const envelopeId = crypto.randomUUID();
    const sendRes = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        envelopeId,
        senderPublicId: aliceId,
        senderDeviceId: aliceDevId,
        recipientPublicId: bobId,
        recipientDeviceId: bobDevId,
        ratchetHeader: {
          dhPublicKey: Buffer.from('alice-ratchet-dh-pubkey-32-bytes').toString('base64'),
          pn: 0,
          n: 0,
        },
        ciphertext: Buffer.from('realtime-encrypted-ciphertext-envelope').toString('base64'),
        nonce: Buffer.from('24-byte-nonce-for-xchacha').toString('base64'),
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      },
    });
    assert.equal(sendRes.statusCode, 202);

    // Bob's WebSocket must immediately receive the envelope
    const wsMessage = await receivedPromise;
    assert.equal(wsMessage.type, 'ciphertext_envelope');
    const receivedEnvelope = (wsMessage as { envelope: { envelopeId: string } }).envelope;
    assert.equal(receivedEnvelope.envelopeId, envelopeId);

    ws.close();
  });
});
