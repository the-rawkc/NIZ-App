import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import type {
  PublicIdentity,
  PublicDevice,
  InvitationRecord,
  ConnectionRequest,
  ConnectionState,
  ContactSummary,
  ReportAbuseRecord,
  FeatureFlag,
  AdminAuditEvent,
  MessageEnvelope,
  AttachmentRecord,
  EncryptedBackupVault,
  SubscriptionRecord,
  SubscriptionMetrics,
} from '@niz/shared-types';
import type { IStorageAdapter } from './interface.js';

const { Pool } = pg;

export class PostgresStorageAdapter implements IStorageAdapter {
  private pool: pg.Pool;

  constructor(poolOrConfig?: pg.Pool | pg.PoolConfig | string) {
    if (poolOrConfig && typeof poolOrConfig === 'object' && 'query' in poolOrConfig) {
      this.pool = poolOrConfig as pg.Pool;
    } else if (typeof poolOrConfig === 'string') {
      const useSsl =
        !poolOrConfig.includes('localhost') && !poolOrConfig.includes('127.0.0.1');
      this.pool = new Pool({
        connectionString: poolOrConfig,
        ssl: useSsl ? { rejectUnauthorized: false } : undefined,
      });
    } else if (poolOrConfig) {
      this.pool = new Pool(poolOrConfig as pg.PoolConfig);
    } else {
      const connStr =
        process.env.DATABASE_URL ||
        'postgresql://niz_admin:niz_dev_secret_change_in_prod@localhost:5432/niz_chat';
      const useSsl =
        process.env.DATABASE_SSL === 'true' ||
        (!!process.env.DATABASE_URL &&
          !process.env.DATABASE_URL.includes('localhost') &&
          !process.env.DATABASE_URL.includes('127.0.0.1'));

      this.pool = new Pool({
        connectionString: connStr,
        ssl: useSsl ? { rejectUnauthorized: false } : undefined,
      });
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async initializeSchema(): Promise<void> {
    try {
      const candidates = [
        path.resolve(process.cwd(), 'src/db/init.sql'),
        path.resolve(process.cwd(), 'dist/db/init.sql'),
        path.resolve(process.cwd(), 'apps/server/src/db/init.sql'),
        path.resolve(process.cwd(), 'db/init.sql'),
      ];
      for (const p of candidates) {
        if (fs.existsSync(p)) {
          const sql = fs.readFileSync(p, 'utf-8');
          await this.pool.query(sql);
          break;
        }
      }
    } catch {
      // In mock/test environments without real DB, fail gracefully
    }
  }

  // Identity & Devices
  async createAccount(account: PublicIdentity): Promise<void> {
    await this.pool.query(
      `INSERT INTO accounts (public_id, status, created_at, updated_at)
       VALUES ($1, $2, $3, $3)
       ON CONFLICT (public_id) DO NOTHING`,
      [account.publicId, account.status, account.createdAt]
    );
  }

  async getAccount(publicId: string): Promise<PublicIdentity | null> {
    const res = await this.pool.query(
      `SELECT public_id AS "publicId", status, created_at AS "createdAt"
       FROM accounts WHERE public_id = $1`,
      [publicId]
    );
    return res.rows[0] || null;
  }

  async createDevice(device: PublicDevice): Promise<void> {
    await this.pool.query(
      `INSERT INTO devices (device_id, account_public_id, public_identity_key, public_signed_prekey, signed_prekey_signature, device_name, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (device_id) DO NOTHING`,
      [
        device.deviceId,
        device.accountPublicId,
        device.publicIdentityKey,
        device.publicSignedPrekey,
        device.signedPrekeySignature,
        device.deviceName || null,
        device.createdAt,
      ]
    );
  }

  async getDevice(deviceId: string): Promise<PublicDevice | null> {
    const res = await this.pool.query(
      `SELECT device_id AS "deviceId", account_public_id AS "accountPublicId",
              public_identity_key AS "publicIdentityKey", public_signed_prekey AS "publicSignedPrekey",
              signed_prekey_signature AS "signedPrekeySignature", device_name AS "deviceName",
              created_at AS "createdAt", revoked_at AS "revokedAt"
       FROM devices WHERE device_id = $1`,
      [deviceId]
    );
    return res.rows[0] || null;
  }

  async listDevices(accountPublicId: string): Promise<PublicDevice[]> {
    const res = await this.pool.query(
      `SELECT device_id AS "deviceId", account_public_id AS "accountPublicId",
              public_identity_key AS "publicIdentityKey", public_signed_prekey AS "publicSignedPrekey",
              signed_prekey_signature AS "signedPrekeySignature", device_name AS "deviceName",
              created_at AS "createdAt", revoked_at AS "revokedAt"
       FROM devices WHERE account_public_id = $1
       ORDER BY created_at ASC`,
      [accountPublicId]
    );
    return res.rows;
  }

  async revokeDevice(deviceId: string): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE devices SET revoked_at = CURRENT_TIMESTAMP WHERE device_id = $1 AND revoked_at IS NULL`,
      [deviceId]
    );
    // Purge queued messages addressed to revoked device
    await this.pool.query(
      `DELETE FROM message_queue WHERE recipient_device_id = $1`,
      [deviceId]
    );
    return (res.rowCount ?? 0) > 0;
  }

  // Invitations
  async createInvitation(invitation: InvitationRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO invitations (id, creator_public_id, token_hash, is_single_use, is_revoked, redemption_count, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        invitation.id,
        invitation.creatorPublicId,
        invitation.tokenHash,
        invitation.isSingleUse,
        invitation.isRevoked,
        invitation.redemptionCount,
        invitation.expiresAt,
        invitation.createdAt,
      ]
    );
  }

  async getInvitationByHash(tokenHash: string): Promise<InvitationRecord | null> {
    const res = await this.pool.query(
      `SELECT id, creator_public_id AS "creatorPublicId", token_hash AS "tokenHash",
              is_single_use AS "isSingleUse", is_revoked AS "isRevoked",
              redemption_count AS "redemptionCount", expires_at AS "expiresAt",
              created_at AS "createdAt"
       FROM invitations WHERE token_hash = $1`,
      [tokenHash]
    );
    return res.rows[0] || null;
  }

  async markInvitationRedeemed(id: string): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE invitations SET redemption_count = redemption_count + 1 WHERE id = $1`,
      [id]
    );
    return (res.rowCount ?? 0) > 0;
  }

  async revokeInvitation(id: string, creatorPublicId: string): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE invitations SET is_revoked = TRUE WHERE id = $1 AND creator_public_id = $2`,
      [id, creatorPublicId]
    );
    return (res.rowCount ?? 0) > 0;
  }

  // Connection Requests & Contacts
  async createConnectionRequest(request: ConnectionRequest): Promise<void> {
    await this.pool.query(
      `INSERT INTO connection_requests (id, sender_public_id, recipient_public_id, state, safety_number_fingerprint, originated_invitation_id, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        request.id,
        request.senderPublicId,
        request.recipientPublicId,
        request.state,
        request.safetyNumberFingerprint || null,
        request.originatedInvitationId || null,
        request.createdAt,
        request.updatedAt,
      ]
    );
  }

  async getConnectionRequest(id: string): Promise<ConnectionRequest | null> {
    const res = await this.pool.query(
      `SELECT id, sender_public_id AS "senderPublicId", recipient_public_id AS "recipientPublicId",
              state, safety_number_fingerprint AS "safetyNumberFingerprint",
              originated_invitation_id AS "originatedInvitationId",
              created_at AS "createdAt", updated_at AS "updatedAt"
       FROM connection_requests WHERE id = $1`,
      [id]
    );
    return res.rows[0] || null;
  }

  async updateConnectionState(
    id: string,
    state: ConnectionState,
    recipientPublicId: string
  ): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE connection_requests
       SET state = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2 AND recipient_public_id = $3`,
      [state, id, recipientPublicId]
    );
    return (res.rowCount ?? 0) > 0;
  }

  async listIncomingRequests(recipientPublicId: string): Promise<ConnectionRequest[]> {
    const res = await this.pool.query(
      `SELECT id, sender_public_id AS "senderPublicId", recipient_public_id AS "recipientPublicId",
              state, safety_number_fingerprint AS "safetyNumberFingerprint",
              originated_invitation_id AS "originatedInvitationId",
              created_at AS "createdAt", updated_at AS "updatedAt"
       FROM connection_requests
       WHERE recipient_public_id = $1 AND state = 'pending'
       ORDER BY created_at DESC`,
      [recipientPublicId]
    );
    return res.rows;
  }

  async listContacts(userPublicId: string): Promise<ContactSummary[]> {
    const res = await this.pool.query(
      `SELECT cr.id,
              CASE WHEN cr.sender_public_id = $1 THEN cr.recipient_public_id ELSE cr.sender_public_id END AS "counterpartPublicId",
              cr.state,
              cr.safety_number_fingerprint AS "safetyNumberFingerprint",
              cr.updated_at AS "updatedAt",
              d.public_identity_key AS "counterpartIdentityKey"
       FROM connection_requests cr
       LEFT JOIN LATERAL (
         SELECT public_identity_key
         FROM devices
         WHERE account_public_id = CASE WHEN cr.sender_public_id = $1 THEN cr.recipient_public_id ELSE cr.sender_public_id END
         ORDER BY created_at ASC
         LIMIT 1
       ) d ON TRUE
       WHERE cr.sender_public_id = $1 OR cr.recipient_public_id = $1`,
      [userPublicId]
    );
    return res.rows;
  }

  async setContactState(userA: string, userB: string, state: ConnectionState): Promise<boolean> {
    const res = await this.pool.query(
      `UPDATE connection_requests
       SET state = $1, updated_at = CURRENT_TIMESTAMP
       WHERE (sender_public_id = $2 AND recipient_public_id = $3)
          OR (sender_public_id = $3 AND recipient_public_id = $2)`,
      [state, userA, userB]
    );
    return (res.rowCount ?? 0) > 0;
  }

  async removeContact(userA: string, userB: string): Promise<boolean> {
    const res = await this.pool.query(
      `DELETE FROM connection_requests
       WHERE (sender_public_id = $1 AND recipient_public_id = $2)
          OR (sender_public_id = $2 AND recipient_public_id = $1)`,
      [userA, userB]
    );
    return (res.rowCount ?? 0) > 0;
  }

  async areConnected(userA: string, userB: string): Promise<boolean> {
    const res = await this.pool.query(
      `SELECT 1 FROM connection_requests
       WHERE ((sender_public_id = $1 AND recipient_public_id = $2)
          OR (sender_public_id = $2 AND recipient_public_id = $1))
         AND state = 'approved'
       LIMIT 1`,
      [userA, userB]
    );
    return res.rows.length > 0;
  }

  // Abuse Reports
  async recordAbuseReport(report: ReportAbuseRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO abuse_reports (id, reporter_public_id, reported_public_id, category, reason, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        report.reportId,
        report.reporterPublicId,
        report.reportedPublicId,
        report.category,
        report.reason || null,
        report.createdAt,
      ]
    );
  }

  // Data Deletion (FR-020)
  async deleteAccount(publicId: string): Promise<boolean> {
    // Delete account; Foreign keys cascading cleans devices, invites, requests, attachments, vaults, subscriptions
    const res = await this.pool.query(
      `DELETE FROM accounts WHERE public_id = $1`,
      [publicId]
    );
    // Purge queued messages
    await this.pool.query(
      `DELETE FROM message_queue WHERE sender_public_id = $1 OR recipient_public_id = $1`,
      [publicId]
    );
    return (res.rowCount ?? 0) > 0;
  }

  // Feature Flags & Admin Audit
  async getFeatureFlag(key: string): Promise<FeatureFlag | null> {
    const res = await this.pool.query(
      `SELECT key, enabled, description, rollout_percentage AS "rolloutPercentage", is_security_invariant AS "isSecurityInvariant"
       FROM feature_flags WHERE key = $1`,
      [key]
    );
    return res.rows[0] || null;
  }

  async listFeatureFlags(): Promise<FeatureFlag[]> {
    const res = await this.pool.query(
      `SELECT key, enabled, description, rollout_percentage AS "rolloutPercentage", is_security_invariant AS "isSecurityInvariant"
       FROM feature_flags ORDER BY key ASC`
    );
    return res.rows;
  }

  async updateFeatureFlag(key: string, enabled: boolean, rolloutPercentage?: number): Promise<boolean> {
    const current = await this.getFeatureFlag(key);
    if (!current) return false;

    // INVARIANT: Critical security invariants can NEVER be disabled
    if (current.isSecurityInvariant && !enabled) {
      throw new Error(`SECURITY INVARIANT VIOLATION: Cannot disable core security invariant "${key}"`);
    }

    const pct = typeof rolloutPercentage === 'number' ? rolloutPercentage : current.rolloutPercentage;
    const res = await this.pool.query(
      `UPDATE feature_flags
       SET enabled = $1, rollout_percentage = $2, updated_at = CURRENT_TIMESTAMP
       WHERE key = $3`,
      [enabled, pct, key]
    );
    return (res.rowCount ?? 0) > 0;
  }

  async recordAdminAuditEvent(event: AdminAuditEvent): Promise<void> {
    await this.pool.query(
      `INSERT INTO admin_audit_events (event_id, admin_id, action, target_resource, timestamp, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        event.eventId,
        event.adminId,
        event.action,
        event.targetResource,
        event.timestamp,
        JSON.stringify({
          role: event.role,
          reason: event.reason,
          ipAddressMasked: event.ipAddressMasked,
        }),
      ]
    );
  }

  async listAdminAuditEvents(): Promise<AdminAuditEvent[]> {
    const res = await this.pool.query(
      `SELECT event_id AS "eventId", admin_id AS "adminId", action, target_resource AS "targetResource",
              timestamp, details
       FROM admin_audit_events ORDER BY timestamp DESC`
    );
    return res.rows.map((row) => ({
      eventId: row.eventId,
      adminId: row.adminId,
      action: row.action,
      targetResource: row.targetResource,
      timestamp: row.timestamp,
      role: row.details?.role || 'SUPER_ADMIN',
      reason: row.details?.reason,
      ipAddressMasked: row.details?.ipAddressMasked,
    }));
  }

  // Encrypted Attachments
  async saveAttachment(record: AttachmentRecord, blob: Buffer): Promise<void> {
    await this.pool.query(
      `INSERT INTO encrypted_attachments (attachment_id, uploader_public_id, recipient_public_id, size_bytes, sha256_ciphertext, storage_path, blob_data, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        record.attachmentId,
        record.uploaderPublicId,
        record.recipientPublicId,
        record.sizeBytes,
        record.sha256Ciphertext,
        `/attachments/${record.attachmentId}`,
        blob,
        record.createdAt,
        record.expiresAt,
      ]
    );
  }

  async getAttachment(attachmentId: string): Promise<{ record: AttachmentRecord; data: Buffer } | null> {
    const res = await this.pool.query(
      `SELECT attachment_id AS "attachmentId", uploader_public_id AS "uploaderPublicId",
              recipient_public_id AS "recipientPublicId", size_bytes AS "sizeBytes",
              sha256_ciphertext AS "sha256Ciphertext", created_at AS "createdAt",
              expires_at AS "expiresAt", blob_data
       FROM encrypted_attachments WHERE attachment_id = $1`,
      [attachmentId]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      record: {
        attachmentId: row.attachmentId,
        uploaderPublicId: row.uploaderPublicId,
        recipientPublicId: row.recipientPublicId,
        sizeBytes: Number(row.sizeBytes),
        sha256Ciphertext: row.sha256Ciphertext,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
      },
      data: Buffer.from(row.blob_data || []),
    };
  }

  async deleteAttachment(attachmentId: string): Promise<boolean> {
    const res = await this.pool.query(
      `DELETE FROM encrypted_attachments WHERE attachment_id = $1`,
      [attachmentId]
    );
    return (res.rowCount ?? 0) > 0;
  }

  // Encrypted Backup Vaults
  async saveBackupVault(accountPublicId: string, vault: EncryptedBackupVault): Promise<void> {
    await this.pool.query(
      `INSERT INTO encrypted_backup_vaults (account_public_id, version, algorithm, kdf_salt, kdf_opslimit, kdf_memlimit, kdf_alg, ciphertext, nonce, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (account_public_id) DO UPDATE SET
         version = EXCLUDED.version,
         algorithm = EXCLUDED.algorithm,
         kdf_salt = EXCLUDED.kdf_salt,
         kdf_opslimit = EXCLUDED.kdf_opslimit,
         kdf_memlimit = EXCLUDED.kdf_memlimit,
         kdf_alg = EXCLUDED.kdf_alg,
         ciphertext = EXCLUDED.ciphertext,
         nonce = EXCLUDED.nonce,
         created_at = EXCLUDED.created_at`,
      [
        accountPublicId,
        vault.version,
        vault.algorithm,
        vault.kdf.salt,
        vault.kdf.opslimit,
        vault.kdf.memlimit,
        vault.kdf.alg,
        vault.ciphertext,
        vault.nonce,
        vault.createdAt,
      ]
    );
  }

  async getBackupVault(accountPublicId: string): Promise<EncryptedBackupVault | null> {
    const res = await this.pool.query(
      `SELECT version, algorithm, kdf_salt, kdf_opslimit, kdf_memlimit, kdf_alg, ciphertext, nonce, created_at AS "createdAt"
       FROM encrypted_backup_vaults WHERE account_public_id = $1`,
      [accountPublicId]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      version: row.version,
      algorithm: row.algorithm,
      kdf: {
        salt: row.kdf_salt,
        opslimit: Number(row.kdf_opslimit),
        memlimit: Number(row.kdf_memlimit),
        alg: Number(row.kdf_alg),
      },
      ciphertext: row.ciphertext,
      nonce: row.nonce,
      createdAt: row.createdAt,
    };
  }

  // Subscriptions & Billing
  async getSubscription(publicId: string): Promise<SubscriptionRecord> {
    const res = await this.pool.query(
      `SELECT public_id AS "publicId", tier, status, current_period_end AS "currentPeriodEnd",
              cancel_at_period_end AS "cancelAtPeriodEnd", max_devices AS "maxDevices",
              max_attachment_size_bytes AS "maxAttachmentSizeBytes", retention_days AS "retentionDays",
              created_at AS "createdAt", updated_at AS "updatedAt"
       FROM subscriptions WHERE public_id = $1`,
      [publicId]
    );
    if (res.rows.length > 0) {
      const row = res.rows[0];
      return {
        ...row,
        maxDevices: Number(row.maxDevices),
        maxAttachmentSizeBytes: Number(row.maxAttachmentSizeBytes),
        retentionDays: Number(row.retentionDays),
      };
    }

    // Default FREE record
    const defaultSub: SubscriptionRecord = {
      publicId,
      tier: 'FREE',
      status: 'free',
      currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      cancelAtPeriodEnd: false,
      maxDevices: 3,
      maxAttachmentSizeBytes: 25 * 1024 * 1024,
      retentionDays: 14,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await this.pool.query(
      `INSERT INTO subscriptions (public_id, tier, status, current_period_end, cancel_at_period_end, max_devices, max_attachment_size_bytes, retention_days, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (public_id) DO NOTHING`,
      [
        defaultSub.publicId,
        defaultSub.tier,
        defaultSub.status,
        defaultSub.currentPeriodEnd,
        defaultSub.cancelAtPeriodEnd,
        defaultSub.maxDevices,
        defaultSub.maxAttachmentSizeBytes,
        defaultSub.retentionDays,
        defaultSub.createdAt,
        defaultSub.updatedAt,
      ]
    );

    return defaultSub;
  }

  async updateSubscription(
    publicId: string,
    update: Partial<SubscriptionRecord>
  ): Promise<SubscriptionRecord> {
    const existing = await this.getSubscription(publicId);
    const tier = update.tier || existing.tier;

    let maxDevices = 3;
    let maxAttachmentSizeBytes = 25 * 1024 * 1024;
    let retentionDays = 14;

    if (tier === 'PRO') {
      maxDevices = 10;
      maxAttachmentSizeBytes = 100 * 1024 * 1024;
      retentionDays = 30;
    } else if (tier === 'BUSINESS') {
      maxDevices = 100;
      maxAttachmentSizeBytes = 500 * 1024 * 1024;
      retentionDays = 90;
    }

    const updated: SubscriptionRecord = {
      ...existing,
      ...update,
      tier,
      maxDevices,
      maxAttachmentSizeBytes,
      retentionDays,
      updatedAt: new Date().toISOString(),
    };

    await this.pool.query(
      `UPDATE subscriptions
       SET tier = $1, status = $2, current_period_end = $3, cancel_at_period_end = $4,
           max_devices = $5, max_attachment_size_bytes = $6, retention_days = $7, updated_at = CURRENT_TIMESTAMP
       WHERE public_id = $8`,
      [
        updated.tier,
        updated.status,
        updated.currentPeriodEnd,
        updated.cancelAtPeriodEnd,
        updated.maxDevices,
        updated.maxAttachmentSizeBytes,
        updated.retentionDays,
        publicId,
      ]
    );

    return updated;
  }

  async getSubscriptionMetrics(): Promise<SubscriptionMetrics> {
    const res = await this.pool.query(
      `SELECT tier, count(*) as count
       FROM subscriptions
       WHERE status IN ('active', 'trialing')
       GROUP BY tier`
    );

    let pro = 0;
    let business = 0;
    for (const row of res.rows) {
      if (row.tier === 'PRO') pro = Number(row.count);
      if (row.tier === 'BUSINESS') business = Number(row.count);
    }

    const totalAccountsRes = await this.pool.query(`SELECT count(*) as count FROM accounts`);
    const totalAccounts = Number(totalAccountsRes.rows[0]?.count || 0);
    const free = Math.max(0, totalAccounts - (pro + business));

    return {
      free,
      pro,
      business,
      totalSubscribers: pro + business,
    };
  }

  // Ciphertext Message Queue
  async enqueueMessage(envelope: MessageEnvelope): Promise<void> {
    await this.pool.query(
      `INSERT INTO message_queue (envelope_id, sender_public_id, sender_device_id, recipient_public_id, recipient_device_id, ratchet_dh_key, ratchet_pn, ratchet_n, ciphertext, nonce, protocol_version, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        envelope.envelopeId,
        envelope.senderPublicId,
        envelope.senderDeviceId,
        envelope.recipientPublicId,
        envelope.recipientDeviceId,
        envelope.ratchetHeader.dhPublicKey,
        envelope.ratchetHeader.pn,
        envelope.ratchetHeader.n,
        envelope.ciphertext,
        envelope.nonce,
        envelope.protocolVersion,
        envelope.createdAt,
      ]
    );
  }

  async enqueueBatchMessages(envelopes: MessageEnvelope[]): Promise<void> {
    if (envelopes.length === 0) return;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      for (const envelope of envelopes) {
        await client.query(
          `INSERT INTO message_queue (envelope_id, sender_public_id, sender_device_id, recipient_public_id, recipient_device_id, ratchet_dh_key, ratchet_pn, ratchet_n, ciphertext, nonce, protocol_version, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
          [
            envelope.envelopeId,
            envelope.senderPublicId,
            envelope.senderDeviceId,
            envelope.recipientPublicId,
            envelope.recipientDeviceId,
            envelope.ratchetHeader.dhPublicKey,
            envelope.ratchetHeader.pn,
            envelope.ratchetHeader.n,
            envelope.ciphertext,
            envelope.nonce,
            envelope.protocolVersion,
            envelope.createdAt,
          ]
        );
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async getPendingMessages(recipientDeviceId: string, limit?: number): Promise<MessageEnvelope[]> {
    let query = `SELECT envelope_id AS "envelopeId", sender_public_id AS "senderPublicId",
              sender_device_id AS "senderDeviceId", recipient_public_id AS "recipientPublicId",
              recipient_device_id AS "recipientDeviceId", ratchet_dh_key AS "dhPublicKey",
              ratchet_pn AS "pn", ratchet_n AS "n", ciphertext, nonce,
              protocol_version AS "protocolVersion", created_at AS "createdAt"
       FROM message_queue
       WHERE recipient_device_id = $1
       ORDER BY created_at ASC`;
    const params: unknown[] = [recipientDeviceId];
    if (typeof limit === 'number' && limit > 0) {
      query += ` LIMIT $2`;
      params.push(limit);
    }
    const res = await this.pool.query(query, params);

    return res.rows.map((row) => ({
      envelopeId: row.envelopeId,
      senderPublicId: row.senderPublicId,
      senderDeviceId: row.senderDeviceId,
      recipientPublicId: row.recipientPublicId,
      recipientDeviceId: row.recipientDeviceId,
      ratchetHeader: {
        dhPublicKey: row.dhPublicKey,
        pn: row.pn,
        n: row.n,
      },
      ciphertext: row.ciphertext,
      nonce: row.nonce,
      protocolVersion: row.protocolVersion,
      createdAt: row.createdAt,
    }));
  }

  async acknowledgeMessages(envelopeIds: string[]): Promise<number> {
    if (envelopeIds.length === 0) return 0;
    const res = await this.pool.query(
      `DELETE FROM message_queue WHERE envelope_id = ANY($1::uuid[])`,
      [envelopeIds]
    );
    return res.rowCount ?? 0;
  }

  async countQueuedMessages(): Promise<number> {
    const res = await this.pool.query(`SELECT count(*) as count FROM message_queue`);
    return Number(res.rows[0]?.count || 0);
  }
}
