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
} from '@niz/shared-types';
import type { IStorageAdapter } from './interface.js';

export class MemoryStorageAdapter implements IStorageAdapter {
  private accounts = new Map<string, PublicIdentity>();
  private devices = new Map<string, PublicDevice>();
  private invitations = new Map<string, InvitationRecord>();
  private connectionRequests = new Map<string, ConnectionRequest>();
  private abuseReports: ReportAbuseRecord[] = [];
  private messageQueue = new Map<string, MessageEnvelope>();
  private attachments = new Map<string, { record: AttachmentRecord; data: Buffer }>();
  private auditEvents: AdminAuditEvent[] = [];
  private featureFlags = new Map<string, FeatureFlag>([
    [
      'enforce_e2ee',
      {
        key: 'enforce_e2ee',
        enabled: true,
        description: 'Enforce End-to-End Encryption on all messages',
        rolloutPercentage: 100,
        isSecurityInvariant: true,
      },
    ],
    [
      'enforce_contact_approval',
      {
        key: 'enforce_contact_approval',
        enabled: true,
        description: 'Require mutual approval before messaging by default',
        rolloutPercentage: 100,
        isSecurityInvariant: true,
      },
    ],
    [
      'experimental_voice_notes',
      {
        key: 'experimental_voice_notes',
        enabled: false,
        description: 'Opt-in preview of encrypted voice notes',
        rolloutPercentage: 0,
        isSecurityInvariant: false,
      },
    ],
  ]);

  // Identity & Devices
  async createAccount(account: PublicIdentity): Promise<void> {
    this.accounts.set(account.publicId, { ...account });
  }

  async getAccount(publicId: string): Promise<PublicIdentity | null> {
    return this.accounts.get(publicId) || null;
  }

  async createDevice(device: PublicDevice): Promise<void> {
    this.devices.set(device.deviceId, { ...device });
  }

  async getDevice(deviceId: string): Promise<PublicDevice | null> {
    return this.devices.get(deviceId) || null;
  }

  async listDevices(accountPublicId: string): Promise<PublicDevice[]> {
    return Array.from(this.devices.values()).filter(
      (d) => d.accountPublicId === accountPublicId && !d.revokedAt
    );
  }

  async revokeDevice(deviceId: string): Promise<boolean> {
    const dev = this.devices.get(deviceId);
    if (!dev) return false;
    dev.revokedAt = new Date().toISOString();
    return true;
  }

  // Invitations
  async createInvitation(invitation: InvitationRecord): Promise<void> {
    this.invitations.set(invitation.id, { ...invitation });
  }

  async getInvitationByHash(tokenHash: string): Promise<InvitationRecord | null> {
    for (const inv of this.invitations.values()) {
      if (inv.tokenHash === tokenHash) {
        return inv;
      }
    }
    return null;
  }

  async markInvitationRedeemed(id: string): Promise<boolean> {
    const inv = this.invitations.get(id);
    if (!inv) return false;
    inv.redemptionCount += 1;
    return true;
  }

  async revokeInvitation(id: string, creatorPublicId: string): Promise<boolean> {
    const inv = this.invitations.get(id);
    if (!inv || inv.creatorPublicId !== creatorPublicId) return false;
    inv.isRevoked = true;
    return true;
  }

  // Connection Requests
  async createConnectionRequest(request: ConnectionRequest): Promise<void> {
    this.connectionRequests.set(request.id, { ...request });
  }

  async getConnectionRequest(id: string): Promise<ConnectionRequest | null> {
    return this.connectionRequests.get(id) || null;
  }

  async updateConnectionState(
    id: string,
    state: ConnectionRequest['state'],
    recipientPublicId: string
  ): Promise<boolean> {
    const req = this.connectionRequests.get(id);
    if (!req || req.recipientPublicId !== recipientPublicId) return false;
    req.state = state;
    req.updatedAt = new Date().toISOString();
    return true;
  }

  async listIncomingRequests(recipientPublicId: string): Promise<ConnectionRequest[]> {
    return Array.from(this.connectionRequests.values()).filter(
      (r) => r.recipientPublicId === recipientPublicId && r.state === 'pending'
    );
  }

  async areConnected(userA: string, userB: string): Promise<boolean> {
    for (const req of this.connectionRequests.values()) {
      if (
        req.state === 'approved' &&
        ((req.senderPublicId === userA && req.recipientPublicId === userB) ||
          (req.senderPublicId === userB && req.recipientPublicId === userA))
      ) {
        return true;
      }
    }
    return false;
  }

  async listContacts(userPublicId: string): Promise<ContactSummary[]> {
    const contacts: ContactSummary[] = [];

    for (const req of this.connectionRequests.values()) {
      let counterpartId: string | null = null;
      if (req.senderPublicId === userPublicId) {
        counterpartId = req.recipientPublicId;
      } else if (req.recipientPublicId === userPublicId) {
        counterpartId = req.senderPublicId;
      }

      if (counterpartId) {
        // Find counterpart's public identity key from devices
        const counterpartDevices = await this.listDevices(counterpartId);
        const counterpartIdentityKey = counterpartDevices[0]?.publicIdentityKey;

        contacts.push({
          id: req.id,
          counterpartPublicId: counterpartId,
          state: req.state,
          counterpartIdentityKey,
          safetyNumberFingerprint: req.safetyNumberFingerprint,
          updatedAt: req.updatedAt,
        });
      }
    }

    return contacts;
  }

  async setContactState(userA: string, userB: string, state: ConnectionState): Promise<boolean> {
    for (const req of this.connectionRequests.values()) {
      if (
        (req.senderPublicId === userA && req.recipientPublicId === userB) ||
        (req.senderPublicId === userB && req.recipientPublicId === userA)
      ) {
        req.state = state;
        req.updatedAt = new Date().toISOString();
        return true;
      }
    }
    return false;
  }

  async removeContact(userA: string, userB: string): Promise<boolean> {
    for (const [id, req] of this.connectionRequests.entries()) {
      if (
        (req.senderPublicId === userA && req.recipientPublicId === userB) ||
        (req.senderPublicId === userB && req.recipientPublicId === userA)
      ) {
        this.connectionRequests.delete(id);
        return true;
      }
    }
    return false;
  }

  async recordAbuseReport(report: ReportAbuseRecord): Promise<void> {
    this.abuseReports.push({ ...report });
  }

  async deleteAccount(publicId: string): Promise<boolean> {
    if (!this.accounts.has(publicId)) return false;

    // Delete account
    this.accounts.delete(publicId);

    // Delete devices
    for (const [devId, dev] of this.devices.entries()) {
      if (dev.accountPublicId === publicId) {
        this.devices.delete(devId);
      }
    }

    // Invalidate invitations
    for (const [invId, inv] of this.invitations.entries()) {
      if (inv.creatorPublicId === publicId) {
        this.invitations.delete(invId);
      }
    }

    // Delete connections
    for (const [reqId, req] of this.connectionRequests.entries()) {
      if (req.senderPublicId === publicId || req.recipientPublicId === publicId) {
        this.connectionRequests.delete(reqId);
      }
    }

    // Purge queued messages
    for (const [envId, env] of this.messageQueue.entries()) {
      if (env.senderPublicId === publicId || env.recipientPublicId === publicId) {
        this.messageQueue.delete(envId);
      }
    }

    // Purge encrypted attachments
    for (const [attId, item] of this.attachments.entries()) {
      if (item.record.uploaderPublicId === publicId || item.record.recipientPublicId === publicId) {
        this.attachments.delete(attId);
      }
    }

    return true;
  }

  async getFeatureFlag(key: string): Promise<FeatureFlag | null> {
    return this.featureFlags.get(key) || null;
  }

  async listFeatureFlags(): Promise<FeatureFlag[]> {
    return Array.from(this.featureFlags.values());
  }

  async updateFeatureFlag(key: string, enabled: boolean, rolloutPercentage?: number): Promise<boolean> {
    const flag = this.featureFlags.get(key);
    if (!flag) return false;

    // INVARIANT: Critical security invariants can NEVER be disabled
    if (flag.isSecurityInvariant && !enabled) {
      throw new Error(`SECURITY INVARIANT VIOLATION: Cannot disable core security invariant "${key}"`);
    }

    flag.enabled = enabled;
    if (typeof rolloutPercentage === 'number') {
      flag.rolloutPercentage = rolloutPercentage;
    }
    return true;
  }

  async recordAdminAuditEvent(event: AdminAuditEvent): Promise<void> {
    this.auditEvents.push({ ...event });
  }

  async listAdminAuditEvents(): Promise<AdminAuditEvent[]> {
    return [...this.auditEvents];
  }

  // Ciphertext Message Queue
  async enqueueMessage(envelope: MessageEnvelope): Promise<void> {
    this.messageQueue.set(envelope.envelopeId, { ...envelope });
  }

  async getPendingMessages(recipientDeviceId: string): Promise<MessageEnvelope[]> {
    return Array.from(this.messageQueue.values()).filter(
      (env) => env.recipientDeviceId === recipientDeviceId
    );
  }

  async acknowledgeMessages(envelopeIds: string[]): Promise<number> {
    let purged = 0;
    for (const id of envelopeIds) {
      if (this.messageQueue.delete(id)) {
        purged++;
      }
    }
    return purged;
  }

  async countQueuedMessages(): Promise<number> {
    return this.messageQueue.size;
  }

  // Encrypted Attachments
  async saveAttachment(record: AttachmentRecord, blob: Buffer): Promise<void> {
    this.attachments.set(record.attachmentId, {
      record: { ...record },
      data: Buffer.from(blob),
    });
  }

  async getAttachment(attachmentId: string): Promise<{ record: AttachmentRecord; data: Buffer } | null> {
    const item = this.attachments.get(attachmentId);
    if (!item) return null;
    return {
      record: { ...item.record },
      data: Buffer.from(item.data),
    };
  }

  async deleteAttachment(attachmentId: string): Promise<boolean> {
    return this.attachments.delete(attachmentId);
  }
}
