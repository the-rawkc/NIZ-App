import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import type pg from 'pg';
import { PostgresStorageAdapter } from '../storage/postgres.js';

/**
 * Mock PostgreSQL Pool for verifying PostgresStorageAdapter SQL queries,
 * parameter bindings, and domain contract enforcement without external database lock-in.
 */
function createMockPool(): pg.Pool & { executedQueries: Array<{ text: string; values?: any[] }> } {
  const executedQueries: Array<{ text: string; values?: any[] }> = [];
  const state = {
    accounts: new Map<string, any>(),
    devices: new Map<string, any>(),
    invitations: new Map<string, any>(),
    connectionRequests: new Map<string, any>(),
    attachments: new Map<string, any>(),
    vaults: new Map<string, any>(),
    subscriptions: new Map<string, any>(),
    featureFlags: new Map<string, any>([
      [
        'enforce_e2ee',
        {
          key: 'enforce_e2ee',
          enabled: true,
          description: 'Enforce End-to-End Encryption',
          rolloutPercentage: 100,
          isSecurityInvariant: true,
        },
      ],
    ]),
    queue: new Map<string, any>(),
  };

  const mockPool = {
    executedQueries,
    async query(text: string, values?: any[]): Promise<any> {
      executedQueries.push({ text: text.trim(), values });
      const normalized = text.trim().toLowerCase();

      // Accounts
      if (normalized.startsWith('insert into accounts')) {
        const [publicId, status, createdAt] = values!;
        state.accounts.set(publicId, { publicId, status, createdAt });
        return { rowCount: 1, rows: [] };
      }
      if (normalized.startsWith('select public_id as "publicid", status, created_at as "createdat"') && normalized.includes('from accounts')) {
        const [publicId] = values!;
        const acc = state.accounts.get(publicId);
        return { rowCount: acc ? 1 : 0, rows: acc ? [acc] : [] };
      }
      if (normalized.startsWith('delete from accounts')) {
        const [publicId] = values!;
        const deleted = state.accounts.delete(publicId);
        return { rowCount: deleted ? 1 : 0, rows: [] };
      }

      // Devices
      if (normalized.startsWith('insert into devices')) {
        const [deviceId, accountPublicId, publicIdentityKey, publicSignedPrekey, signedPrekeySignature, deviceName, createdAt] = values!;
        state.devices.set(deviceId, {
          deviceId,
          accountPublicId,
          publicIdentityKey,
          publicSignedPrekey,
          signedPrekeySignature,
          deviceName,
          createdAt,
          revokedAt: null,
        });
        return { rowCount: 1, rows: [] };
      }
      if (normalized.startsWith('select device_id as "deviceid"') && normalized.includes('from devices where device_id = $1')) {
        const [deviceId] = values!;
        const dev = state.devices.get(deviceId);
        return { rowCount: dev ? 1 : 0, rows: dev ? [dev] : [] };
      }
      if (normalized.startsWith('select device_id as "deviceid"') && normalized.includes('from devices where account_public_id = $1')) {
        const [accId] = values!;
        const devs = Array.from(state.devices.values()).filter((d) => d.accountPublicId === accId);
        return { rowCount: devs.length, rows: devs };
      }
      if (normalized.startsWith('update devices set revoked_at = current_timestamp')) {
        const [deviceId] = values!;
        const dev = state.devices.get(deviceId);
        if (dev && !dev.revokedAt) {
          dev.revokedAt = new Date().toISOString();
          return { rowCount: 1, rows: [] };
        }
        return { rowCount: 0, rows: [] };
      }

      // Feature Flags
      if (normalized.startsWith('select key, enabled, description') && normalized.includes('where key = $1')) {
        const [key] = values!;
        const flag = state.featureFlags.get(key);
        return { rowCount: flag ? 1 : 0, rows: flag ? [flag] : [] };
      }
      if (normalized.startsWith('select key, enabled, description') && normalized.includes('from feature_flags order by key asc')) {
        return { rowCount: state.featureFlags.size, rows: Array.from(state.featureFlags.values()) };
      }
      if (normalized.startsWith('update feature_flags set enabled = $1')) {
        const [enabled, pct, key] = values!;
        const flag = state.featureFlags.get(key);
        if (flag) {
          flag.enabled = enabled;
          flag.rolloutPercentage = pct;
          return { rowCount: 1, rows: [] };
        }
        return { rowCount: 0, rows: [] };
      }

      // Subscriptions
      if (normalized.startsWith('select public_id as "publicid", tier, status') && normalized.includes('from subscriptions where public_id = $1')) {
        const [publicId] = values!;
        const sub = state.subscriptions.get(publicId);
        return { rowCount: sub ? 1 : 0, rows: sub ? [sub] : [] };
      }
      if (normalized.startsWith('insert into subscriptions')) {
        const [publicId, tier, status, currentPeriodEnd, cancelAtPeriodEnd, maxDevices, maxAttachmentSizeBytes, retentionDays, createdAt, updatedAt] = values!;
        const record = {
          publicId,
          tier,
          status,
          currentPeriodEnd,
          cancelAtPeriodEnd,
          maxDevices,
          maxAttachmentSizeBytes,
          retentionDays,
          createdAt,
          updatedAt,
        };
        state.subscriptions.set(publicId, record);
        return { rowCount: 1, rows: [] };
      }
      if (normalized.startsWith('update subscriptions set tier = $1')) {
        const [tier, status, currentPeriodEnd, cancelAtPeriodEnd, maxDevices, maxAttachmentSizeBytes, retentionDays, publicId] = values!;
        const sub = state.subscriptions.get(publicId);
        if (sub) {
          Object.assign(sub, { tier, status, currentPeriodEnd, cancelAtPeriodEnd, maxDevices, maxAttachmentSizeBytes, retentionDays });
          return { rowCount: 1, rows: [] };
        }
        return { rowCount: 0, rows: [] };
      }

      // Message Queue
      if (normalized.startsWith('insert into message_queue')) {
        const [envelopeId, senderPublicId, senderDeviceId, recipientPublicId, recipientDeviceId, dhPublicKey, pn, n, ciphertext, nonce, protocolVersion, createdAt] = values!;
        state.queue.set(envelopeId, {
          envelopeId,
          senderPublicId,
          senderDeviceId,
          recipientPublicId,
          recipientDeviceId,
          dhPublicKey,
          pn,
          n,
          ciphertext,
          nonce,
          protocolVersion,
          createdAt,
        });
        return { rowCount: 1, rows: [] };
      }
      if (normalized.startsWith('delete from message_queue where recipient_device_id = $1')) {
        const [deviceId] = values!;
        let count = 0;
        for (const [id, env] of state.queue.entries()) {
          if (env.recipientDeviceId === deviceId) {
            state.queue.delete(id);
            count++;
          }
        }
        return { rowCount: count, rows: [] };
      }
      if (normalized.startsWith('select count(*) as count from message_queue')) {
        return { rowCount: 1, rows: [{ count: state.queue.size }] };
      }

      // Fallback
      return { rowCount: 0, rows: [] };
    },
    async end() {},
  } as unknown as pg.Pool & { executedQueries: Array<{ text: string; values?: any[] }> };

  return mockPool;
}

describe('Phase 9: Production PostgreSQL Storage Adapter & Invariant Enforcement', () => {
  it('PostgresStorageAdapter executes parameterized SQL and enforces domain contracts', async () => {
    const mockPool = createMockPool();
    const adapter = new PostgresStorageAdapter(mockPool);

    const publicId = `niz_id_${crypto.randomBytes(20).toString('hex')}`;
    const deviceId = crypto.randomUUID();

    // 1. Create account
    await adapter.createAccount({
      publicId,
      status: 'active',
      createdAt: new Date().toISOString(),
    });

    const acc = await adapter.getAccount(publicId);
    assert.ok(acc);
    assert.equal(acc?.publicId, publicId);

    // 2. Register Device
    await adapter.createDevice({
      deviceId,
      accountPublicId: publicId,
      publicIdentityKey: 'mock-identity-key-base64',
      publicSignedPrekey: 'mock-prekey-base64',
      signedPrekeySignature: 'mock-signature-base64',
      deviceName: 'Postgres Unit Device',
      createdAt: new Date().toISOString(),
    });

    const dev = await adapter.getDevice(deviceId);
    assert.ok(dev);
    assert.equal(dev?.deviceId, deviceId);

    const list = await adapter.listDevices(publicId);
    assert.equal(list.length, 1);
    assert.equal(list[0].deviceId, deviceId);

    // 3. Queue a message and revoke device
    await adapter.enqueueMessage({
      envelopeId: crypto.randomUUID(),
      senderPublicId: `niz_id_sender`,
      senderDeviceId: crypto.randomUUID(),
      recipientPublicId: publicId,
      recipientDeviceId: deviceId,
      ratchetHeader: { dhPublicKey: 'mock', pn: 0, n: 0 },
      ciphertext: 'ciphertext',
      nonce: 'nonce',
      protocolVersion: 'niz-dr-v1',
      createdAt: new Date().toISOString(),
    });

    const countBefore = await adapter.countQueuedMessages();
    assert.equal(countBefore, 1);

    const revoked = await adapter.revokeDevice(deviceId);
    assert.equal(revoked, true);

    const countAfter = await adapter.countQueuedMessages();
    assert.equal(countAfter, 0); // Purged on revocation

    // 4. Subscription tier quotas
    const sub = await adapter.getSubscription(publicId);
    assert.equal(sub.tier, 'FREE');
    assert.equal(sub.maxDevices, 3);
    assert.equal(sub.maxAttachmentSizeBytes, 25 * 1024 * 1024);

    const upgraded = await adapter.updateSubscription(publicId, { tier: 'PRO' });
    assert.equal(upgraded.tier, 'PRO');
    assert.equal(upgraded.maxDevices, 10);
    assert.equal(upgraded.maxAttachmentSizeBytes, 100 * 1024 * 1024);

    // 5. Security Invariant Protection: Rejects disabling invariant
    await assert.rejects(
      async () => {
        await adapter.updateFeatureFlag('enforce_e2ee', false);
      },
      /SECURITY INVARIANT VIOLATION/
    );

    // 6. Delete account
    const deleted = await adapter.deleteAccount(publicId);
    assert.equal(deleted, true);

    const deletedAcc = await adapter.getAccount(publicId);
    assert.equal(deletedAcc, null);
  });
});
