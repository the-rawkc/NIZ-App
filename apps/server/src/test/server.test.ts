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

  it('Phase 5: Admin login with mandatory MFA and RBAC privilege separation', async () => {
    // 1. Login with invalid password
    const badPass = await app.inject({
      method: 'POST',
      url: '/v1/admin/login',
      payload: { username: 'opsadmin', password: 'wrongpassword', mfaCode: '123456' },
    });
    assert.equal(badPass.statusCode, 401);

    // 2. Login with invalid MFA code format (< 6 chars rejected by validation schema)
    const badMfa = await app.inject({
      method: 'POST',
      url: '/v1/admin/login',
      payload: { username: 'opsadmin', password: 'dev_admin_ops_secret_123', mfaCode: '123' },
    });
    assert.equal(badMfa.statusCode, 400);

    // 3. Login with valid credentials and valid 6-digit MFA
    const loginRes = await app.inject({
      method: 'POST',
      url: '/v1/admin/login',
      payload: { username: 'opsadmin', password: 'dev_admin_ops_secret_123', mfaCode: '654321' },
    });
    assert.equal(loginRes.statusCode, 200);
    const { token: opsToken } = JSON.parse(loginRes.body);
    assert.ok(opsToken);

    // 4. Operations Admin can access aggregate metrics
    const metricsRes = await app.inject({
      method: 'GET',
      url: '/v1/admin/metrics',
      headers: { authorization: `Bearer ${opsToken}` },
    });
    assert.equal(metricsRes.statusCode, 200);
    assert.equal(JSON.parse(metricsRes.body).status, 'healthy');

    // 5. Operations Admin CANNOT access audit logs (Requires SECURITY_AUDITOR or SUPER_ADMIN)
    const forbiddenAudit = await app.inject({
      method: 'GET',
      url: '/v1/admin/audit-logs',
      headers: { authorization: `Bearer ${opsToken}` },
    });
    assert.equal(forbiddenAudit.statusCode, 403);

    // 6. Security Auditor logs in with MFA
    const auditorLogin = await app.inject({
      method: 'POST',
      url: '/v1/admin/login',
      payload: { username: 'auditor', password: 'dev_admin_auditor_secret_123', mfaCode: '112233' },
    });
    const { token: auditorToken } = JSON.parse(auditorLogin.body);

    // Auditor can access audit logs
    const auditRes = await app.inject({
      method: 'GET',
      url: '/v1/admin/audit-logs',
      headers: { authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(auditRes.statusCode, 200);
    assert.ok(Array.isArray(JSON.parse(auditRes.body).auditLogs));
  });

  it('Phase 5 SECURITY INVARIANT: Feature flags cannot disable core security invariants', async () => {
    // Product Admin logs in
    const loginRes = await app.inject({
      method: 'POST',
      url: '/v1/admin/login',
      payload: { username: 'productadmin', password: 'dev_admin_product_secret_123', mfaCode: '998877' },
    });
    const { token: prodToken } = JSON.parse(loginRes.body);

    // 1. Attempt to disable E2EE -> Must fail closed with 400 Bad Request!
    const disableE2eeRes = await app.inject({
      method: 'POST',
      url: '/v1/admin/feature-flags',
      headers: { authorization: `Bearer ${prodToken}` },
      payload: { key: 'enforce_e2ee', enabled: false },
    });
    assert.equal(disableE2eeRes.statusCode, 400);
    assert.equal(JSON.parse(disableE2eeRes.body).error, 'SECURITY_INVARIANT_VIOLATION');

    // 2. Attempt to disable contact approval requirement -> Must fail closed with 400!
    const disableApprovalRes = await app.inject({
      method: 'POST',
      url: '/v1/admin/feature-flags',
      headers: { authorization: `Bearer ${prodToken}` },
      payload: { key: 'enforce_contact_approval', enabled: false },
    });
    assert.equal(disableApprovalRes.statusCode, 400);
    assert.equal(JSON.parse(disableApprovalRes.body).error, 'SECURITY_INVARIANT_VIOLATION');

    // 3. Toggling a normal non-security experiment flag -> Succeeds
    const normalFlagRes = await app.inject({
      method: 'POST',
      url: '/v1/admin/feature-flags',
      headers: { authorization: `Bearer ${prodToken}` },
      payload: { key: 'experimental_voice_notes', enabled: true, rolloutPercentage: 25 },
    });
    assert.equal(normalFlagRes.statusCode, 200);
    assert.equal(JSON.parse(normalFlagRes.body).enabled, true);
  });

  it('Phase 5: User account closure permanently purges server records (FR-020)', async () => {
    const userToClose = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const devId = crypto.randomUUID();

    // Register user
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: userToClose,
        device: {
          deviceId: devId,
          publicIdentityKey: Buffer.from('mock-to-close-identity-key-32b').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-to-close-prekey-32b-long-').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // Close account
    const deleteRes = await app.inject({
      method: 'DELETE',
      url: `/v1/identity/${userToClose}`,
      headers: { 'x-sender-public-id': userToClose },
    });
    assert.equal(deleteRes.statusCode, 200);
    assert.equal(JSON.parse(deleteRes.body).purged, true);

    // Verify devices list is now empty
    const devicesRes = await app.inject({
      method: 'GET',
      url: `/v1/identity/${userToClose}/devices`,
    });
    assert.equal(JSON.parse(devicesRes.body).devices.length, 0);
  });

  it('Phase 6: Encrypted attachment upload and download between approved contacts', async () => {
    const aliceId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const bobId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const devA = crypto.randomUUID();
    const devB = crypto.randomUUID();

    // Register Alice & Bob
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: aliceId,
        device: {
          deviceId: devA,
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
          deviceId: devB,
          publicIdentityKey: Buffer.from('mock-bob-identity-key-32-bytes--').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-bob-prekey-32-bytes-long--').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // Establish mutual approval
    const reqRes = await app.inject({
      method: 'POST',
      url: '/v1/connection-requests',
      headers: { 'x-sender-public-id': aliceId },
      payload: {
        recipientPublicId: bobId,
      },
    });
    const { requestId } = JSON.parse(reqRes.body);

    await app.inject({
      method: 'POST',
      url: '/v1/connection-requests/decision',
      headers: { 'x-recipient-public-id': bobId },
      payload: { requestId, decision: 'approve' },
    });

    // 1. Alice creates encrypted mock ciphertext buffer
    const mockCiphertext = Buffer.from('XChaCha20-Poly1305 encrypted opaque binary data for image or PDF');
    const sha256Hash = crypto.createHash('sha256').update(mockCiphertext).digest('hex');

    // 2. Alice uploads attachment
    const uploadRes = await app.inject({
      method: 'POST',
      url: '/v1/attachments/upload',
      headers: {
        'content-type': 'application/octet-stream',
        'x-sender-public-id': aliceId,
        'x-recipient-public-id': bobId,
        'x-ciphertext-sha256': sha256Hash,
      },
      payload: mockCiphertext,
    });

    assert.equal(uploadRes.statusCode, 201);
    const uploadData = JSON.parse(uploadRes.body);
    assert.ok(uploadData.attachmentId);
    assert.equal(uploadData.sizeBytes, mockCiphertext.length);
    assert.equal(uploadData.downloadUrl, `/v1/attachments/${uploadData.attachmentId}`);

    // 3. Bob downloads attachment
    const downloadRes = await app.inject({
      method: 'GET',
      url: uploadData.downloadUrl,
      headers: {
        'x-requester-public-id': bobId,
      },
    });

    assert.equal(downloadRes.statusCode, 200);
    assert.equal(downloadRes.headers['content-type'], 'application/octet-stream');
    assert.equal(downloadRes.headers['x-ciphertext-sha256'], sha256Hash);
    assert.deepEqual(downloadRes.rawPayload, mockCiphertext);

    // 4. Participant deletes attachment
    const delRes = await app.inject({
      method: 'DELETE',
      url: uploadData.downloadUrl,
      headers: {
        'x-requester-public-id': aliceId,
      },
    });
    assert.equal(delRes.statusCode, 204);

    // 5. Subsequent download returns 404
    const notFoundRes = await app.inject({
      method: 'GET',
      url: uploadData.downloadUrl,
      headers: {
        'x-requester-public-id': bobId,
      },
    });
    assert.equal(notFoundRes.statusCode, 404);
  });

  it('Phase 6 SECURITY INVARIANTS: Attachment security policies & error boundaries', async () => {
    const unapprovedSender = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const targetRecipient = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const thirdParty = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const blob = Buffer.from('Mock encrypted bytes');
    const hash = crypto.createHash('sha256').update(blob).digest('hex');

    // 1. Upload to unapproved recipient -> 403 Forbidden
    const unapprovedUploadRes = await app.inject({
      method: 'POST',
      url: '/v1/attachments/upload',
      headers: {
        'content-type': 'application/octet-stream',
        'x-sender-public-id': unapprovedSender,
        'x-recipient-public-id': targetRecipient,
        'x-ciphertext-sha256': hash,
      },
      payload: blob,
    });
    assert.equal(unapprovedUploadRes.statusCode, 403);
    assert.equal(JSON.parse(unapprovedUploadRes.body).error, 'RECIPIENT_APPROVAL_REQUIRED');

    // 2. Upload with mismatched SHA-256 hash -> 400 Bad Request
    // Manually register and connect users to test hash mismatch
    await storage.createAccount({ publicId: unapprovedSender, createdAt: new Date().toISOString(), status: 'active' });
    await storage.createAccount({ publicId: targetRecipient, createdAt: new Date().toISOString(), status: 'active' });
    const connReqId = crypto.randomUUID();
    await storage.createConnectionRequest({
      id: connReqId,
      senderPublicId: unapprovedSender,
      recipientPublicId: targetRecipient,
      state: 'approved',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    const mismatchRes = await app.inject({
      method: 'POST',
      url: '/v1/attachments/upload',
      headers: {
        'content-type': 'application/octet-stream',
        'x-sender-public-id': unapprovedSender,
        'x-recipient-public-id': targetRecipient,
        'x-ciphertext-sha256': '0'.repeat(64),
      },
      payload: blob,
    });
    assert.equal(mismatchRes.statusCode, 400);
    assert.equal(JSON.parse(mismatchRes.body).error, 'HASH_MISMATCH');

    // 3. Unauthorized third-party download rejection -> 403 Forbidden
    const validUploadRes = await app.inject({
      method: 'POST',
      url: '/v1/attachments/upload',
      headers: {
        'content-type': 'application/octet-stream',
        'x-sender-public-id': unapprovedSender,
        'x-recipient-public-id': targetRecipient,
        'x-ciphertext-sha256': hash,
      },
      payload: blob,
    });
    assert.equal(validUploadRes.statusCode, 201);
    const { downloadUrl } = JSON.parse(validUploadRes.body);

    const unauthorizedDownloadRes = await app.inject({
      method: 'GET',
      url: downloadUrl,
      headers: {
        'x-requester-public-id': thirdParty,
      },
    });
    assert.equal(unauthorizedDownloadRes.statusCode, 403);
    assert.equal(JSON.parse(unauthorizedDownloadRes.body).error, 'FORBIDDEN');

    // 4. Over-limit payload size -> 413 Payload Too Large
    const oversizedBlob = Buffer.alloc(25 * 1024 * 1024 + 1024); // 25MB + 1KB
    const oversizedHash = crypto.createHash('sha256').update(oversizedBlob).digest('hex');
    const oversizeRes = await app.inject({
      method: 'POST',
      url: '/v1/attachments/upload',
      headers: {
        'content-type': 'application/octet-stream',
        'x-sender-public-id': unapprovedSender,
        'x-recipient-public-id': targetRecipient,
        'x-ciphertext-sha256': oversizedHash,
      },
      payload: oversizedBlob,
    });
    assert.equal(oversizeRes.statusCode, 413);
    assert.equal(JSON.parse(oversizeRes.body).error, 'PAYLOAD_TOO_LARGE');
  });

  it('Phase 7: Multi-device linking, listing, and device revocation with queue purge', async () => {
    const userId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const primaryDevId = crypto.randomUUID();
    const secondaryDevId = crypto.randomUUID();

    // 1. Register Primary Device
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: userId,
        device: {
          deviceId: primaryDevId,
          publicIdentityKey: Buffer.from('mock-primary-identity-key-32b--').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-primary-signed-prekey-32b-').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
          deviceName: 'Primary Laptop',
        },
      },
    });

    // 2. Link Secondary Device
    const linkRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/devices/link',
      headers: { 'x-sender-public-id': userId },
      payload: {
        publicId: userId,
        device: {
          deviceId: secondaryDevId,
          publicIdentityKey: Buffer.from('mock-secondary-identity-key-32b').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-secondary-prekey-32b-long-').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
          deviceName: 'Mobile Phone',
        },
      },
    });
    assert.equal(linkRes.statusCode, 201);

    // 3. List devices -> 2 active devices
    const listRes = await app.inject({
      method: 'GET',
      url: `/v1/identity/${userId}/devices`,
    });
    assert.equal(listRes.statusCode, 200);
    const devices = JSON.parse(listRes.body).devices;
    assert.equal(devices.length, 2);

    // 4. Enqueue a message targeted at the secondary device
    const envId = crypto.randomUUID();
    await storage.enqueueMessage({
      envelopeId: envId,
      senderPublicId: `niz_id_${crypto.randomBytes(20).toString('hex')}`,
      senderDeviceId: crypto.randomUUID(),
      recipientPublicId: userId,
      recipientDeviceId: secondaryDevId,
      ratchetHeader: { dhPublicKey: 'mock', pn: 0, n: 0 },
      ciphertext: 'opaque-ciphertext',
      nonce: 'opaque-nonce',
      protocolVersion: 'niz-dr-v1',
      createdAt: new Date().toISOString(),
    });

    // Verify message is in queue for secondary device
    const pendingBefore = await storage.getPendingMessages(secondaryDevId);
    assert.equal(pendingBefore.length, 1);

    // 5. Revoke Secondary Device
    const revokeRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/devices/revoke',
      headers: { 'x-sender-public-id': userId },
      payload: { deviceId: secondaryDevId },
    });
    assert.equal(revokeRes.statusCode, 200);
    assert.equal(JSON.parse(revokeRes.body).revokedDeviceId, secondaryDevId);

    // 6. Verify queue for revoked device is immediately purged
    const pendingAfter = await storage.getPendingMessages(secondaryDevId);
    assert.equal(pendingAfter.length, 0);

    // 7. Negative Security Invariant: Unauthorized device linking rejection
    const unauthLinkRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/devices/link',
      headers: { 'x-sender-public-id': 'niz_id_attacker' },
      payload: {
        publicId: userId,
        device: {
          deviceId: crypto.randomUUID(),
          publicIdentityKey: 'mock',
          publicSignedPrekey: 'mock',
          signedPrekeySignature: 'mock',
        },
      },
    });
    assert.equal(unauthLinkRes.statusCode, 401);
  });

  it('Phase 7: Zero-Knowledge encrypted backup vault sync and secret rejection', async () => {
    const userId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const devId = crypto.randomUUID();

    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: userId,
        device: {
          deviceId: devId,
          publicIdentityKey: Buffer.from('mock-user-identity-key-32b-str-').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-user-signed-prekey-32b-str').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    const mockVault = {
      version: 1,
      algorithm: 'argon2id-xchacha20poly1305',
      kdf: {
        salt: '0123456789abcdef0123456789abcdef',
        opslimit: 2,
        memlimit: 67108864,
        alg: 2,
      },
      ciphertext: Buffer.from('encrypted-vault-opaque-ciphertext-bytes').toString('base64'),
      nonce: 'abcdef0123456789abcdef0123456789abcdef0123456789',
      createdAt: new Date().toISOString(),
    };

    // 1. Sync encrypted backup vault
    const syncRes = await app.inject({
      method: 'POST',
      url: '/v1/backup/vault',
      headers: { 'x-sender-public-id': userId },
      payload: mockVault,
    });
    assert.equal(syncRes.statusCode, 200);

    // 2. Retrieve synced backup vault
    const getVaultRes = await app.inject({
      method: 'GET',
      url: '/v1/backup/vault',
      headers: { 'x-sender-public-id': userId },
    });
    assert.equal(getVaultRes.statusCode, 200);
    assert.equal(JSON.parse(getVaultRes.body).vault.ciphertext, mockVault.ciphertext);

    // 3. SECURITY INVARIANT: Rejects vault payload containing private keys or passphrases
    const secretLeakRes = await app.inject({
      method: 'POST',
      url: '/v1/backup/vault',
      headers: { 'x-sender-public-id': userId },
      payload: {
        ...mockVault,
        passphrase: 'super_secret_plaintext_password_leak',
      },
    });
    assert.equal(secretLeakRes.statusCode, 400);

    // 4. Account closure purges backup vault
    await app.inject({
      method: 'DELETE',
      url: `/v1/identity/${userId}`,
      headers: { 'x-sender-public-id': userId },
    });

    const postDeleteVaultRes = await app.inject({
      method: 'GET',
      url: '/v1/backup/vault',
      headers: { 'x-sender-public-id': userId },
    });
    assert.equal(JSON.parse(postDeleteVaultRes.body).vault, null);
  });

  it('Phase 8: Subscription plans, sandbox checkout, webhooks, and E2EE preservation', async () => {
    const userId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const devId = crypto.randomUUID();

    // Register user
    await app.inject({
      method: 'POST',
      url: '/v1/identity/register',
      payload: {
        publicId: userId,
        device: {
          deviceId: devId,
          publicIdentityKey: Buffer.from('mock-billing-identity-key-32b-st').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-billing-signed-prekey-32b-s').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });

    // 1. Default subscription state is FREE tier
    const subRes = await app.inject({
      method: 'GET',
      url: '/v1/billing/subscription',
      headers: { 'x-sender-public-id': userId },
    });
    assert.equal(subRes.statusCode, 200);
    const subData = JSON.parse(subRes.body);
    assert.equal(subData.tier, 'FREE');
    assert.equal(subData.status, 'free');
    assert.equal(subData.maxDevices, 3);
    assert.equal(subData.maxAttachmentSizeBytes, 25 * 1024 * 1024);

    // 2. Simulated sandbox checkout upgrade to PRO
    const checkoutRes = await app.inject({
      method: 'POST',
      url: '/v1/billing/checkout',
      headers: { 'x-sender-public-id': userId },
      payload: { tier: 'PRO' },
    });
    assert.equal(checkoutRes.statusCode, 200);
    const checkoutData = JSON.parse(checkoutRes.body);
    assert.equal(checkoutData.tier, 'PRO');
    assert.equal(checkoutData.simulated, true);
    assert.ok(checkoutData.sessionId.startsWith('sbx_sess_'));

    // Verify upgraded quotas
    const proSubRes = await app.inject({
      method: 'GET',
      url: '/v1/billing/subscription',
      headers: { 'x-sender-public-id': userId },
    });
    assert.equal(proSubRes.statusCode, 200);
    const proData = JSON.parse(proSubRes.body);
    assert.equal(proData.tier, 'PRO');
    assert.equal(proData.status, 'active');
    assert.equal(proData.maxDevices, 10);
    assert.equal(proData.maxAttachmentSizeBytes, 100 * 1024 * 1024);

    // 3. Webhook simulation: subscription canceled
    const webhookRes = await app.inject({
      method: 'POST',
      url: '/v1/billing/webhook',
      payload: {
        eventType: 'customer.subscription.deleted',
        publicId: userId,
        timestamp: new Date().toISOString(),
      },
    });
    assert.equal(webhookRes.statusCode, 200);
    assert.equal(JSON.parse(webhookRes.body).received, true);

    // Verify downgrade to FREE
    const downgradedSubRes = await app.inject({
      method: 'GET',
      url: '/v1/billing/subscription',
      headers: { 'x-sender-public-id': userId },
    });
    const downgradedData = JSON.parse(downgradedSubRes.body);
    assert.equal(downgradedData.tier, 'FREE');
    assert.equal(downgradedData.status, 'canceled');

    // 4. SECURITY INVARIANT: Canceled/downgraded account NEVER loses E2EE capability
    // Can still link devices and send encrypted Double Ratchet envelopes
    const newDevId = crypto.randomUUID();
    const linkDevRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/devices/link',
      headers: { 'x-sender-public-id': userId },
      payload: {
        publicId: userId,
        device: {
          deviceId: newDevId,
          publicIdentityKey: Buffer.from('mock-new-device-id-key-32b-str--').toString('base64'),
          publicSignedPrekey: Buffer.from('mock-new-device-prekey-32b-str--').toString('base64'),
          signedPrekeySignature: Buffer.from('mock-signature-64-bytes-long-padding-bytes-for-test').toString('base64'),
        },
      },
    });
    assert.equal(linkDevRes.statusCode, 201);

    // 5. User cancels subscription endpoint
    const cancelRes = await app.inject({
      method: 'POST',
      url: '/v1/billing/cancel',
      headers: { 'x-sender-public-id': userId },
    });
    assert.equal(cancelRes.statusCode, 200);

    // 6. Admin metrics include subscription counts
    const adminLoginRes = await app.inject({
      method: 'POST',
      url: '/v1/admin/login',
      payload: {
        username: 'opsadmin',
        password: 'dev_admin_ops_secret_123',
        mfaCode: '654321',
      },
    });
    const { token: adminToken } = JSON.parse(adminLoginRes.body);

    const metricsRes = await app.inject({
      method: 'GET',
      url: '/v1/admin/metrics',
      headers: { authorization: `Bearer ${adminToken}` },
    });
    assert.equal(metricsRes.statusCode, 200);
    const metricsData = JSON.parse(metricsRes.body);
    assert.ok(metricsData.subscriptions);
    assert.ok(typeof metricsData.subscriptions.free === 'number');
    assert.ok(typeof metricsData.subscriptions.pro === 'number');
  });
});
