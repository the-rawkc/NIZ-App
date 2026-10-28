import type {
  PublicIdentity,
  PublicDevice,
  InvitationRecord,
  ConnectionRequest,
  MessageEnvelope,
} from '@niz/shared-types';
import type { IStorageAdapter } from './interface.js';

export class MemoryStorageAdapter implements IStorageAdapter {
  private accounts = new Map<string, PublicIdentity>();
  private devices = new Map<string, PublicDevice>();
  private invitations = new Map<string, InvitationRecord>();
  private connectionRequests = new Map<string, ConnectionRequest>();
  private messageQueue = new Map<string, MessageEnvelope>();

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
}
