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

export interface IStorageAdapter {
  // Identity & Devices
  createAccount(account: PublicIdentity): Promise<void>;
  getAccount(publicId: string): Promise<PublicIdentity | null>;
  createDevice(device: PublicDevice): Promise<void>;
  getDevice(deviceId: string): Promise<PublicDevice | null>;
  listDevices(accountPublicId: string): Promise<PublicDevice[]>;
  revokeDevice(deviceId: string): Promise<boolean>;

  // Invitations
  createInvitation(invitation: InvitationRecord): Promise<void>;
  getInvitationByHash(tokenHash: string): Promise<InvitationRecord | null>;
  markInvitationRedeemed(id: string): Promise<boolean>;
  revokeInvitation(id: string, creatorPublicId: string): Promise<boolean>;

  // Connection Requests & Contacts
  createConnectionRequest(request: ConnectionRequest): Promise<void>;
  getConnectionRequest(id: string): Promise<ConnectionRequest | null>;
  updateConnectionState(
    id: string,
    state: ConnectionState,
    recipientPublicId: string
  ): Promise<boolean>;
  listIncomingRequests(recipientPublicId: string): Promise<ConnectionRequest[]>;
  listContacts(userPublicId: string): Promise<ContactSummary[]>;
  setContactState(userA: string, userB: string, state: ConnectionState): Promise<boolean>;
  removeContact(userA: string, userB: string): Promise<boolean>;
  areConnected(userA: string, userB: string): Promise<boolean>;

  // Abuse Reports
  recordAbuseReport(report: ReportAbuseRecord): Promise<void>;

  // Data Deletion
  deleteAccount(publicId: string): Promise<boolean>;

  // Feature Flags & Admin Audit
  getFeatureFlag(key: string): Promise<FeatureFlag | null>;
  listFeatureFlags(): Promise<FeatureFlag[]>;
  updateFeatureFlag(key: string, enabled: boolean, rolloutPercentage?: number): Promise<boolean>;
  recordAdminAuditEvent(event: AdminAuditEvent): Promise<void>;
  listAdminAuditEvents(): Promise<AdminAuditEvent[]>;

  // Encrypted Attachments (Opaque ciphertext blobs only)
  saveAttachment(record: AttachmentRecord, blob: Buffer): Promise<void>;
  getAttachment(attachmentId: string): Promise<{ record: AttachmentRecord; data: Buffer } | null>;
  deleteAttachment(attachmentId: string): Promise<boolean>;

  // Encrypted Backup Vaults (Zero-knowledge ciphertext only)
  saveBackupVault(accountPublicId: string, vault: EncryptedBackupVault): Promise<void>;
  getBackupVault(accountPublicId: string): Promise<EncryptedBackupVault | null>;

  // Subscriptions & Billing (Phase 8)
  getSubscription(publicId: string): Promise<SubscriptionRecord>;
  updateSubscription(publicId: string, update: Partial<SubscriptionRecord>): Promise<SubscriptionRecord>;
  getSubscriptionMetrics(): Promise<SubscriptionMetrics>;

  // Ciphertext Message Queue
  enqueueMessage(envelope: MessageEnvelope): Promise<void>;
  getPendingMessages(recipientDeviceId: string): Promise<MessageEnvelope[]>;
  acknowledgeMessages(envelopeIds: string[]): Promise<number>;
  countQueuedMessages(): Promise<number>;
}
