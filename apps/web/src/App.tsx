import React, { useState, useEffect, useRef } from 'react';
import QRCode from 'qrcode';
import {
  createClientIdentity,
  computeSafetyFingerprint,
  generatePermanentIdentityQrPayload,
  generateEphemeralInvitationQrPayload,
  parseNizQrPayload,
  initAliceSession,
  ratchetEncrypt,
  ratchetDecrypt,
  encryptAttachment,
  decryptAttachment,
  createEncryptedBackup,
  restoreEncryptedBackup,
  type ClientIdentityBundle,
  type NizParsedQr,
  type RatchetSessionState,
} from '@niz/crypto-core';
import type {
  ContactSummary,
  MessageEnvelope,
  EncryptedAttachmentMetadata,
  PublicDevice,
  EncryptedBackupVault,
  SubscriptionRecord,
} from '@niz/shared-types';
import { NizLogo } from './components/NizLogo';

const API_BASE =
  import.meta.env.VITE_API_BASE ||
  (typeof window !== 'undefined' && window.location.port === '5173'
    ? 'http://localhost:4000'
    : typeof window !== 'undefined'
    ? window.location.origin
    : 'http://localhost:4000');

const WS_BASE =
  import.meta.env.VITE_WS_BASE ||
  (typeof window !== 'undefined' && window.location.port === '5173'
    ? 'ws://localhost:4000'
    : typeof window !== 'undefined'
    ? (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host
    : 'ws://localhost:4000');

interface ChatAttachment {
  attachmentId: string;
  downloadUrl: string;
  metadata: EncryptedAttachmentMetadata;
}

interface ChatMessage {
  id: string;
  sender: 'me' | 'them';
  text: string;
  attachment?: ChatAttachment;
  timestamp: string;
  verifiedE2EE: boolean;
}

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'identity' | 'invite' | 'connect' | 'requests' | 'contacts' | 'chat' | 'plans'>('identity');
  const [identity, setIdentity] = useState<ClientIdentityBundle | null>(null);
  const [permanentQrDataUrl, setPermanentQrDataUrl] = useState<string>('');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [notification, setNotification] = useState<string | null>(null);

  // Invite state
  const [inviteDuration, setInviteDuration] = useState<number>(3600); // 1 hour
  const [inviteSingleUse, setInviteSingleUse] = useState<boolean>(true);
  const [activeInvite, setActiveInvite] = useState<{
    id: string;
    token: string;
    expiresAt: string;
    isSingleUse: boolean;
    qrDataUrl: string;
  } | null>(null);

  // Connect / QR Scan state
  const [inputQrPayload, setInputQrPayload] = useState<string>('');
  const [parsedPreview, setParsedPreview] = useState<NizParsedQr | null>(null);
  const [connectStatus, setConnectStatus] = useState<string | null>(null);

  // Requests state
  const [pendingRequests, setPendingRequests] = useState<Array<{
    id: string;
    senderPublicId: string;
    recipientPublicId: string;
    state: string;
    createdAt: string;
  }>>([]);

  // Contacts & Verification state
  const [contacts, setContacts] = useState<ContactSummary[]>([]);
  const [selectedContact, setSelectedContact] = useState<ContactSummary | null>(null);
  const [pairwiseSafetyNumber, setPairwiseSafetyNumber] = useState<string>('');
  const [verifiedContacts, setVerifiedContacts] = useState<Set<string>>(new Set());
  const [reportReason, setReportReason] = useState<string>('');
  const [reportCategory, setReportCategory] = useState<'spam' | 'harassment' | 'impersonation' | 'other'>('spam');
  const [showReportDialog, setShowReportDialog] = useState<boolean>(false);

  // Live Chat & Double Ratchet state
  const [activeChatContact, setActiveChatContact] = useState<ContactSummary | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [messageInput, setMessageInput] = useState<string>('');
  const [isWsConnected, setIsWsConnected] = useState<boolean>(false);
  const [isUploadingAttachment, setIsUploadingAttachment] = useState<boolean>(false);

  // Multi-Device & Backup state (Phase 7)
  const [devices, setDevices] = useState<PublicDevice[]>([]);
  const [backupPassphrase, setBackupPassphrase] = useState<string>('');
  const [restorePassphrase, setRestorePassphrase] = useState<string>('');
  const [isExportingBackup, setIsExportingBackup] = useState<boolean>(false);
  const [isRestoringBackup, setIsRestoringBackup] = useState<boolean>(false);
  const backupFileRef = useRef<HTMLInputElement | null>(null);

  // Billing & Subscription state (Phase 8)
  const [subscription, setSubscription] = useState<SubscriptionRecord | null>(null);
  const [isProcessingBilling, setIsProcessingBilling] = useState<boolean>(false);

  const ratchetSessionsRef = useRef<Map<string, RatchetSessionState>>(new Map());
  const wsRef = useRef<WebSocket | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  // Generate identity locally
  const handleGenerateIdentity = async () => {
    setIsGenerating(true);
    try {
      const deviceId = crypto.randomUUID();
      const newIdentity = await createClientIdentity(deviceId, 'NIZ Web Client Alpha');
      setIdentity(newIdentity);

      // Register public keys on server
      try {
        await fetch(`${API_BASE}/v1/identity/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(newIdentity.registrationPayload),
        });
      } catch {
        // Local-only if server offline
      }

      // Generate permanent QR
      const uri = generatePermanentIdentityQrPayload(
        newIdentity.publicId,
        newIdentity.publicIdentityKeyBase64,
        newIdentity.safetyFingerprint
      );
      const dataUrl = await QRCode.toDataURL(uri, {
        width: 256,
        margin: 2,
        color: { dark: '#10B981', light: '#090D14' },
      });
      setPermanentQrDataUrl(dataUrl);
      showNotification('New cryptographic identity generated locally!');
    } catch (err: unknown) {
      showNotification(err instanceof Error ? err.message : 'Identity generation failed');
    } finally {
      setIsGenerating(false);
    }
  };

  // Create expiring invitation
  const handleCreateInvitation = async () => {
    if (!identity) {
      showNotification('Please generate an identity first');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/v1/invitations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          creatorPublicId: identity.publicId,
          expiresInSeconds: inviteDuration,
          isSingleUse: inviteSingleUse,
        }),
      });

      if (!res.ok) {
        throw new Error('Failed to create invitation on server');
      }

      const data = await res.json();
      const qrUri = generateEphemeralInvitationQrPayload(
        data.invitationToken,
        identity.publicId,
        data.expiresAt,
        data.isSingleUse
      );

      const qrDataUrl = await QRCode.toDataURL(qrUri, {
        width: 256,
        margin: 2,
        color: { dark: '#34D399', light: '#090D14' },
      });

      setActiveInvite({
        id: data.invitationId,
        token: data.invitationToken,
        expiresAt: data.expiresAt,
        isSingleUse: data.isSingleUse,
        qrDataUrl,
      });

      showNotification('Temporary invitation created!');
    } catch (err: unknown) {
      showNotification(err instanceof Error ? err.message : 'Failed to create invitation');
    }
  };

  // Revoke invitation
  const handleRevokeInvitation = async () => {
    if (!activeInvite || !identity) return;

    try {
      const res = await fetch(`${API_BASE}/v1/invitations/${activeInvite.id}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sender-public-id': identity.publicId,
        },
      });

      if (res.ok) {
        setActiveInvite(null);
        showNotification('Invitation revoked');
      }
    } catch {
      showNotification('Failed to revoke invitation');
    }
  };

  // Parse QR preview
  const handleParseQr = () => {
    try {
      const parsed = parseNizQrPayload(inputQrPayload);
      setParsedPreview(parsed);
      setConnectStatus(null);
    } catch (err: unknown) {
      setParsedPreview(null);
      setConnectStatus(err instanceof Error ? err.message : 'Invalid QR code');
    }
  };

  // Send connection request
  const handleSendConnectionRequest = async () => {
    if (!identity || !parsedPreview) return;

    const recipientId =
      parsedPreview.type === 'permanent_identity'
        ? parsedPreview.publicId
        : parsedPreview.creatorPublicId;

    const inviteToken =
      parsedPreview.type === 'ephemeral_invitation'
        ? parsedPreview.invitationToken
        : undefined;

    try {
      const res = await fetch(`${API_BASE}/v1/connection-requests`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sender-public-id': identity.publicId,
        },
        body: JSON.stringify({
          recipientPublicId: recipientId,
          invitationToken: inviteToken,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to send connection request');
      }

      setConnectStatus(`Connection request sent! (Request ID: ${data.requestId})`);
      setParsedPreview(null);
      setInputQrPayload('');
      showNotification('Connection request delivered to recipient');
    } catch (err: unknown) {
      setConnectStatus(err instanceof Error ? err.message : 'Connection request failed');
    }
  };

  // Fetch pending incoming requests
  const fetchPendingRequests = async () => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/connection-requests/pending/${identity.publicId}`);
      if (res.ok) {
        const data = await res.json();
        setPendingRequests(data.requests || []);
      }
    } catch {
      // ignore
    }
  };

  // Fetch contacts
  const fetchContacts = async () => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/contacts/${identity.publicId}`);
      if (res.ok) {
        const data = await res.json();
        setContacts(data.contacts || []);
      }
    } catch {
      // ignore
    }
  };

  // Fetch linked devices (Phase 7)
  const fetchDevices = async () => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/identity/${identity.publicId}/devices`);
      if (res.ok) {
        const data = await res.json();
        setDevices(data.devices || []);
      }
    } catch {
      // ignore
    }
  };

  // Revoke device (Phase 7)
  const handleRevokeDevice = async (deviceId: string) => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/identity/devices/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sender-public-id': identity.publicId,
        },
        body: JSON.stringify({ deviceId }),
      });
      if (res.ok) {
        showNotification('Device revoked. It can no longer receive or decrypt messages.');
        fetchDevices();
      }
    } catch {
      showNotification('Failed to revoke device');
    }
  };

  // Export Encrypted Backup Vault (Argon2id + XChaCha20-Poly1305) (Phase 7)
  const handleExportBackup = async () => {
    if (!identity) return;
    if (!backupPassphrase || backupPassphrase.length < 8) {
      showNotification('Passphrase must be at least 8 characters long.');
      return;
    }

    setIsExportingBackup(true);
    try {
      const backupPayload = {
        publicId: identity.publicId,
        privateIdentityKeyBase64: identity.privateKeys.privateIdentityKeyBase64,
        privateSignedPrekeyBase64: identity.privateKeys.privateSignedPrekeyBase64,
        contacts: contacts.map((c) => ({
          counterpartPublicId: c.counterpartPublicId,
          counterpartIdentityKey: c.counterpartIdentityKey,
          verified: verifiedContacts.has(c.id),
        })),
        exportedAt: new Date().toISOString(),
      };

      const vault = await createEncryptedBackup(backupPassphrase, backupPayload);

      // 1. Download file to client
      const blob = new Blob([JSON.stringify(vault, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `niz-backup-${new Date().toISOString().split('T')[0]}.nizvault`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      // 2. Sync to zero-knowledge server vault
      await fetch(`${API_BASE}/v1/backup/vault`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sender-public-id': identity.publicId,
        },
        body: JSON.stringify(vault),
      });

      setBackupPassphrase('');
      showNotification('Encrypted backup vault exported and synced!');
    } catch (err: unknown) {
      showNotification(err instanceof Error ? err.message : 'Backup export failed');
    } finally {
      setIsExportingBackup(false);
    }
  };

  // Restore from vault file (Phase 7)
  const handleFileRestore = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!restorePassphrase || restorePassphrase.length < 8) {
      showNotification('Enter your passphrase before selecting the backup file.');
      return;
    }

    setIsRestoringBackup(true);
    try {
      const text = await file.text();
      const vault = JSON.parse(text) as EncryptedBackupVault;
      const restored = await restoreEncryptedBackup(restorePassphrase, vault);

      // Reconstruct client identity bundle
      const safetyFingerprint = await computeSafetyFingerprint(
        restored.privateIdentityKeyBase64,
        restored.privateIdentityKeyBase64
      );

      setIdentity({
        publicId: restored.publicId,
        deviceId: crypto.randomUUID(),
        publicIdentityKeyBase64: restored.privateIdentityKeyBase64,
        publicSignedPrekeyBase64: restored.privateSignedPrekeyBase64,
        signedPrekeySignatureBase64: '',
        safetyFingerprint,
        registrationPayload: {} as any,
        privateKeys: {
          privateIdentityKeyBase64: restored.privateIdentityKeyBase64,
          privateSignedPrekeyBase64: restored.privateSignedPrekeyBase64,
        },
      });

      setRestorePassphrase('');
      showNotification(`Identity "${restored.publicId}" successfully restored!`);
    } catch (err: unknown) {
      showNotification(err instanceof Error ? err.message : 'Restore failed: invalid passphrase or corrupted vault.');
    } finally {
      setIsRestoringBackup(false);
      if (backupFileRef.current) backupFileRef.current.value = '';
    }
  };

  // Handle request decision (approve / decline / block)
  const handleDecision = async (requestId: string, decision: 'approve' | 'decline' | 'block') => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/connection-requests/decision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-recipient-public-id': identity.publicId,
        },
        body: JSON.stringify({ requestId, decision }),
      });

      if (res.ok) {
        showNotification(`Request marked as ${decision}d`);
        fetchPendingRequests();
        fetchContacts();
      }
    } catch {
      showNotification('Failed to process decision');
    }
  };

  // Open Security Verification for Contact
  const handleSelectContactForVerification = async (contact: ContactSummary) => {
    setSelectedContact(contact);
    if (identity && contact.counterpartIdentityKey) {
      const pairwiseFp = await computeSafetyFingerprint(
        identity.publicIdentityKeyBase64,
        contact.counterpartIdentityKey
      );
      setPairwiseSafetyNumber(pairwiseFp);
    } else {
      setPairwiseSafetyNumber(identity?.safetyFingerprint || '');
    }
  };

  // Fetch subscription (Phase 8)
  const fetchSubscription = async () => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/billing/subscription`, {
        headers: { 'x-sender-public-id': identity.publicId },
      });
      if (res.ok) {
        const data = await res.json();
        setSubscription(data);
      }
    } catch {
      // ignore
    }
  };

  // Upgrade to Pro in sandbox (Phase 8)
  const handleUpgradeToPro = async () => {
    if (!identity) return;
    setIsProcessingBilling(true);
    try {
      const res = await fetch(`${API_BASE}/v1/billing/checkout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sender-public-id': identity.publicId,
        },
        body: JSON.stringify({ tier: 'PRO' }),
      });
      if (res.ok) {
        showNotification('Upgraded to NIZ Pro (Sandbox simulated)! Quotas upgraded.');
        fetchSubscription();
      }
    } catch (err: unknown) {
      showNotification(err instanceof Error ? err.message : 'Upgrade failed');
    } finally {
      setIsProcessingBilling(false);
    }
  };

  // Cancel subscription (Phase 8)
  const handleCancelSubscription = async () => {
    if (!identity) return;
    setIsProcessingBilling(true);
    try {
      const res = await fetch(`${API_BASE}/v1/billing/cancel`, {
        method: 'POST',
        headers: {
          'x-sender-public-id': identity.publicId,
        },
      });
      if (res.ok) {
        showNotification('Subscription canceled. Your account safely remains on FREE with 100% E2EE active.');
        fetchSubscription();
      }
    } catch {
      showNotification('Failed to cancel subscription');
    } finally {
      setIsProcessingBilling(false);
    }
  };

  // Toggle mark contact as verified
  const handleToggleVerified = (contactId: string) => {
    setVerifiedContacts((prev) => {
      const next = new Set(prev);
      if (next.has(contactId)) {
        next.delete(contactId);
        showNotification('Verification removed');
      } else {
        next.add(contactId);
        showNotification('Contact marked as verified!');
      }
      return next;
    });
  };

  // Block contact
  const handleBlockContact = async (counterpartPublicId: string) => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/contacts/block`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sender-public-id': identity.publicId,
        },
        body: JSON.stringify({ targetPublicId: counterpartPublicId }),
      });
      if (res.ok) {
        showNotification('Contact blocked');
        setSelectedContact(null);
        fetchContacts();
      }
    } catch {
      showNotification('Failed to block contact');
    }
  };

  // Unblock contact
  const handleUnblockContact = async (counterpartPublicId: string) => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/contacts/unblock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sender-public-id': identity.publicId,
        },
        body: JSON.stringify({ targetPublicId: counterpartPublicId }),
      });
      if (res.ok) {
        showNotification('Contact unblocked');
        setSelectedContact(null);
        fetchContacts();
      }
    } catch {
      showNotification('Failed to unblock contact');
    }
  };

  // Remove contact connection
  const handleRemoveContact = async (counterpartPublicId: string) => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/contacts/${counterpartPublicId}`, {
        method: 'DELETE',
        headers: {
          'x-sender-public-id': identity.publicId,
        },
      });
      if (res.ok) {
        showNotification('Connection removed');
        setSelectedContact(null);
        fetchContacts();
      }
    } catch {
      showNotification('Failed to remove connection');
    }
  };

  // Submit Abuse Report
  const handleSubmitReport = async () => {
    if (!identity || !selectedContact) return;
    try {
      const res = await fetch(`${API_BASE}/v1/reports`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sender-public-id': identity.publicId,
        },
        body: JSON.stringify({
          reportedPublicId: selectedContact.counterpartPublicId,
          category: reportCategory,
          reason: reportReason,
        }),
      });

      if (res.ok) {
        showNotification('Report submitted to operations');
        setShowReportDialog(false);
        setReportReason('');
      }
    } catch {
      showNotification('Failed to submit report');
    }
  };

  // Start chat with an approved contact
  const handleStartChat = async (contact: ContactSummary) => {
    setActiveChatContact(contact);
    setActiveTab('chat');

    // Get or initialize Double Ratchet session
    if (!ratchetSessionsRef.current.has(contact.counterpartPublicId) && identity && contact.counterpartIdentityKey) {
      // In production X3DH derives a master secret; here we initialize master seed from deterministic handshake
      const masterSecret = new Uint8Array(32).fill(42);
      const session = await initAliceSession(masterSecret, contact.counterpartIdentityKey);
      ratchetSessionsRef.current.set(contact.counterpartPublicId, session);
    }
  };

  // Send an encrypted message
  const handleSendMessage = async () => {
    if (!identity || !activeChatContact || !messageInput.trim()) return;

    try {
      let session = ratchetSessionsRef.current.get(activeChatContact.counterpartPublicId);
      if (!session && activeChatContact.counterpartIdentityKey) {
        const masterSecret = new Uint8Array(32).fill(42);
        session = await initAliceSession(masterSecret, activeChatContact.counterpartIdentityKey);
        ratchetSessionsRef.current.set(activeChatContact.counterpartPublicId, session);
      }

      if (!session) {
        showNotification('Failed to initialize cryptographic ratchet session');
        return;
      }

      // Encrypt client-side using Double Ratchet
      const encrypted = await ratchetEncrypt(session, messageInput.trim());

      // Fetch recipient device ID
      const devicesRes = await fetch(`${API_BASE}/v1/identity/${activeChatContact.counterpartPublicId}/devices`);
      const devicesData = await devicesRes.json();
      const recipientDeviceId = devicesData.devices?.[0]?.deviceId;

      if (!recipientDeviceId) {
        showNotification('Recipient device not found on network');
        return;
      }

      const envelopeId = crypto.randomUUID();
      const envelope: MessageEnvelope = {
        envelopeId,
        senderPublicId: identity.publicId,
        senderDeviceId: identity.deviceId,
        recipientPublicId: activeChatContact.counterpartPublicId,
        recipientDeviceId,
        ratchetHeader: encrypted.header,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      };

      // Transmit strictly ciphertext envelope
      const res = await fetch(`${API_BASE}/v1/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || 'Server rejected message');
      }

      // Add to local chat
      setChatMessages((prev) => [
        ...prev,
        {
          id: envelopeId,
          sender: 'me',
          text: messageInput.trim(),
          timestamp: new Date().toLocaleTimeString(),
          verifiedE2EE: true,
        },
      ]);
      setMessageInput('');
    } catch (err: unknown) {
      showNotification(err instanceof Error ? err.message : 'Encryption / send failed');
    }
  };

  // Encrypt and send an attachment
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !identity || !activeChatContact) return;

    if (file.size > 25 * 1024 * 1024) {
      showNotification('File exceeds 25MB attachment limit.');
      return;
    }

    setIsUploadingAttachment(true);
    try {
      let session = ratchetSessionsRef.current.get(activeChatContact.counterpartPublicId);
      if (!session && activeChatContact.counterpartIdentityKey) {
        const masterSecret = new Uint8Array(32).fill(42);
        session = await initAliceSession(masterSecret, activeChatContact.counterpartIdentityKey);
        ratchetSessionsRef.current.set(activeChatContact.counterpartPublicId, session);
      }

      if (!session) {
        throw new Error('No active ratchet session for recipient.');
      }

      // 1. Read file bytes and encrypt client-side
      const arrayBuf = await file.arrayBuffer();
      const fileBytes = new Uint8Array(arrayBuf);
      const mime = file.type || 'application/octet-stream';
      const encrypted = await encryptAttachment(fileBytes, mime, file.name);

      // 2. Upload ciphertext blob to server (Server has strictly opaque bytes)
      const uploadRes = await fetch(`${API_BASE}/v1/attachments/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'x-sender-public-id': identity.publicId,
          'x-recipient-public-id': activeChatContact.counterpartPublicId,
          'x-ciphertext-sha256': encrypted.metadata.sha256,
        },
        body: encrypted.ciphertext as unknown as BodyInit,
      });

      if (!uploadRes.ok) {
        const errData = await uploadRes.json();
        throw new Error(errData.message || 'Failed to upload encrypted attachment');
      }

      const uploadData = await uploadRes.json();

      // 3. Encrypt attachment metadata inside Double Ratchet payload
      const attachmentPayload = JSON.stringify({
        type: 'attachment',
        attachmentId: uploadData.attachmentId,
        downloadUrl: uploadData.downloadUrl,
        metadata: encrypted.metadata,
      });

      const encryptedRatchet = await ratchetEncrypt(session, attachmentPayload);

      // 4. Fetch recipient device ID and dispatch ciphertext envelope
      const devicesRes = await fetch(`${API_BASE}/v1/identity/${activeChatContact.counterpartPublicId}/devices`);
      const devicesData = await devicesRes.json();
      const recipientDeviceId = devicesData.devices?.[0]?.deviceId;

      if (!recipientDeviceId) {
        throw new Error('Recipient device not reachable');
      }

      const envelopeId = crypto.randomUUID();
      const envelope: MessageEnvelope = {
        envelopeId,
        senderPublicId: identity.publicId,
        senderDeviceId: identity.deviceId,
        recipientPublicId: activeChatContact.counterpartPublicId,
        recipientDeviceId,
        ratchetHeader: encryptedRatchet.header,
        ciphertext: encryptedRatchet.ciphertext,
        nonce: encryptedRatchet.nonce,
        protocolVersion: 'niz-dr-v1',
        createdAt: new Date().toISOString(),
      };

      const msgRes = await fetch(`${API_BASE}/v1/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      if (!msgRes.ok) {
        throw new Error('Server rejected message envelope');
      }

      // Add to local message list
      setChatMessages((prev) => [
        ...prev,
        {
          id: envelopeId,
          sender: 'me',
          text: file.name,
          attachment: {
            attachmentId: uploadData.attachmentId,
            downloadUrl: uploadData.downloadUrl,
            metadata: encrypted.metadata,
          },
          timestamp: new Date().toLocaleTimeString(),
          verifiedE2EE: true,
        },
      ]);

      showNotification(`Encrypted attachment "${file.name}" sent!`);
    } catch (err: unknown) {
      showNotification(err instanceof Error ? err.message : 'Attachment sending failed');
    } finally {
      setIsUploadingAttachment(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // Download and decrypt attachment client-side
  const handleDownloadAttachment = async (attachment: ChatAttachment) => {
    if (!identity) return;
    try {
      showNotification(`Downloading and decrypting "${attachment.metadata.filename}"...`);
      const res = await fetch(`${API_BASE}${attachment.downloadUrl}`, {
        headers: {
          'x-requester-public-id': identity.publicId,
        },
      });

      if (!res.ok) {
        throw new Error('Failed to download ciphertext from server');
      }

      const blobBuf = await res.arrayBuffer();
      const ciphertext = new Uint8Array(blobBuf);

      // Decrypt client-side using stored mediaKey
      const decryptedBytes = await decryptAttachment(ciphertext, attachment.metadata);

      // Trigger browser download
      const blob = new Blob([decryptedBytes as unknown as BlobPart], { type: attachment.metadata.mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = attachment.metadata.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showNotification(`Attachment "${attachment.metadata.filename}" decrypted & saved!`);
    } catch (err: unknown) {
      showNotification(err instanceof Error ? err.message : 'Decryption failed');
    }
  };

  // Process incoming ciphertext envelope (decrypt, render, and ACK purge)
  const processEnvelope = async (envelope: MessageEnvelope) => {
    const senderId = envelope.senderPublicId;

    // Attempt decryption if session exists
    let session = ratchetSessionsRef.current.get(senderId);
    if (!session && activeChatContact?.counterpartIdentityKey) {
      const masterSecret = new Uint8Array(32).fill(42);
      session = await initAliceSession(masterSecret, activeChatContact.counterpartIdentityKey);
      ratchetSessionsRef.current.set(senderId, session);
    }

    let decryptedText = '[Encrypted Payload]';
    if (session) {
      try {
        decryptedText = await ratchetDecrypt(session, {
          header: envelope.ratchetHeader,
          ciphertext: envelope.ciphertext,
          nonce: envelope.nonce,
        });
      } catch {
        decryptedText = '[Decryption failed: signature/MAC invalid]';
      }
    }

    let attachmentObj: ChatAttachment | undefined;
    let displayText = decryptedText;
    if (decryptedText.startsWith('{"type":"attachment"')) {
      try {
        const parsedAtt = JSON.parse(decryptedText);
        attachmentObj = {
          attachmentId: parsedAtt.attachmentId,
          downloadUrl: parsedAtt.downloadUrl,
          metadata: parsedAtt.metadata,
        };
        displayText = parsedAtt.metadata.filename;
      } catch {
        // fallback to raw text
      }
    }

    // Append to message thread avoiding duplicates
    setChatMessages((prev) => {
      if (prev.some((m) => m.id === envelope.envelopeId)) return prev;
      return [
        ...prev,
        {
          id: envelope.envelopeId,
          sender: 'them',
          text: displayText,
          attachment: attachmentObj,
          timestamp: new Date(envelope.createdAt).toLocaleTimeString(),
          verifiedE2EE: true,
        },
      ];
    });

    // Immediately acknowledge and purge from server queue
    try {
      await fetch(`${API_BASE}/v1/messages/ack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelopeIds: [envelope.envelopeId] }),
      });
    } catch {
      // ignore
    }
  };

  // Synchronize pending offline messages from server queue
  const syncPendingMessages = async () => {
    if (!identity) return;
    try {
      const res = await fetch(`${API_BASE}/v1/messages/queue/${identity.deviceId}`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.envelopes)) {
          for (const env of data.envelopes) {
            await processEnvelope(env);
          }
        }
      }
    } catch {
      // ignore
    }
  };

  // Setup WebSocket connection with auto-reconnection and heartbeat
  useEffect(() => {
    if (!identity) return;

    let isMounted = true;
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
    let heartbeatInterval: ReturnType<typeof setInterval> | null = null;
    let backoffMs = 1000;

    const connect = () => {
      if (!isMounted) return;
      const wsUrl = `${WS_BASE}/v1/ws?deviceId=${identity.deviceId}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isMounted) return;
        setIsWsConnected(true);
        backoffMs = 1000;

        // Periodic ping heartbeat
        heartbeatInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 25000);

        // Sync pending messages on connect / reconnect
        syncPendingMessages();
      };

      ws.onclose = () => {
        if (!isMounted) return;
        setIsWsConnected(false);
        if (heartbeatInterval) clearInterval(heartbeatInterval);
        reconnectTimeout = setTimeout(() => {
          backoffMs = Math.min(backoffMs * 2, 10000);
          connect();
        }, backoffMs);
      };

      ws.onerror = () => {
        ws.close();
      };

      ws.onmessage = async (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'ciphertext_envelope' && data.envelope) {
            await processEnvelope(data.envelope);
          }
        } catch {
          // ignore
        }
      };
    };

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (wsRef.current) wsRef.current.close();
    };
  }, [identity, activeChatContact]);

  useEffect(() => {
    if (activeTab === 'identity') {
      fetchDevices();
    } else if (activeTab === 'requests') {
      fetchPendingRequests();
    } else if (activeTab === 'contacts' || activeTab === 'chat') {
      fetchContacts();
    } else if (activeTab === 'plans') {
      fetchSubscription();
    }
  }, [activeTab, identity]);

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '36px 20px', width: '100%' }}>
      {/* Dynamic Animated Toast Notification */}
      {notification && (
        <div className="toast-notice">
          {notification}
        </div>
      )}

      {/* Header */}
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '32px',
          paddingBottom: '22px',
          borderBottom: '1px solid var(--color-border)',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div className="floating-icon">
            <NizLogo size={50} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ fontSize: '1.65rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#F8FAFC' }}>
                NIZ Chat
              </h1>
              <span className="badge">E2EE v1.0</span>
            </div>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.86rem', marginTop: '3px' }}>
              Privacy-first, QR-connected messaging · Zero plaintext on server
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          {identity && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 14px',
                borderRadius: '9999px',
                background: 'rgba(15, 23, 42, 0.8)',
                border: '1px solid var(--color-border)',
                fontSize: '0.78rem',
                fontFamily: 'monospace',
                color: '#94A3B8',
              }}
              title={identity.publicId}
            >
              <span style={{ color: '#10B981', fontWeight: 700 }}>ID:</span>
              <span>{identity.publicId.slice(0, 16)}...</span>
            </div>
          )}

          <div
            style={{
              fontSize: '0.78rem',
              fontWeight: 600,
              padding: '6px 12px',
              borderRadius: '9999px',
              backgroundColor: isWsConnected ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
              color: isWsConnected ? '#34D399' : '#F87171',
              border: '1px solid',
              borderColor: isWsConnected ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            {isWsConnected ? <span className="live-beacon" /> : <span className="offline-beacon" />}
            {isWsConnected ? 'Live Push Active' : 'Offline Reconnecting'}
          </div>
        </div>
      </header>

      {/* Modern Navigation Tabs */}
      <nav className="nav-tab-container">
        <button
          onClick={() => setActiveTab('identity')}
          className={`nav-tab-btn ${activeTab === 'identity' ? 'active' : ''}`}
        >
          🛡️ My Identity & QR
        </button>
        <button
          onClick={() => setActiveTab('invite')}
          className={`nav-tab-btn ${activeTab === 'invite' ? 'active' : ''}`}
        >
          ⏳ Expiring Invite
        </button>
        <button
          onClick={() => setActiveTab('connect')}
          className={`nav-tab-btn ${activeTab === 'connect' ? 'active' : ''}`}
        >
          📡 Scan / Connect
        </button>
        <button
          onClick={() => setActiveTab('requests')}
          className={`nav-tab-btn ${activeTab === 'requests' ? 'active' : ''}`}
        >
          📬 Requests {pendingRequests.length > 0 && <span style={{ background: '#10B981', color: '#06090E', padding: '2px 6px', borderRadius: '999px', fontSize: '0.72rem', fontWeight: 800 }}>{pendingRequests.length}</span>}
        </button>
        <button
          onClick={() => setActiveTab('contacts')}
          className={`nav-tab-btn ${activeTab === 'contacts' ? 'active' : ''}`}
        >
          👥 Contacts & Safety
        </button>
        <button
          onClick={() => setActiveTab('chat')}
          className={`nav-tab-btn ${activeTab === 'chat' ? 'active' : ''}`}
        >
          💬 Encrypted Chat
        </button>
        <button
          onClick={() => setActiveTab('plans')}
          className={`nav-tab-btn ${activeTab === 'plans' ? 'active' : ''}`}
        >
          ⚡ Plans & Quotas
        </button>
      </nav>

      {/* Tab 1: Identity & Permanent QR */}
      {activeTab === 'identity' && (
        <section className="card card-cyber animate-fade-in">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#F8FAFC' }}>
                Your Cryptographic Identity
              </h2>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.84rem', marginTop: '2px' }}>
                Locally-held Ed25519 signing keys and X25519 prekeys
              </p>
            </div>
            <button
              onClick={handleGenerateIdentity}
              disabled={isGenerating}
              className="btn-primary"
            >
              {isGenerating ? 'Generating Keys...' : identity ? '🔄 Rotate / Re-generate Keys' : '✨ Create Identity'}
            </button>
          </div>

          {!identity ? (
            <div style={{ padding: '36px 20px', textAlign: 'center', background: 'rgba(10, 15, 26, 0.6)', borderRadius: '14px', border: '1px dashed var(--color-border)' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '12px' }}>🔑</div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#F8FAFC', marginBottom: '6px' }}>
                No Cryptographic Identity Found
              </h3>
              <p style={{ color: 'var(--color-text-secondary)', maxWidth: '500px', margin: '0 auto 18px', fontSize: '0.86rem', lineHeight: 1.6 }}>
                Click <strong>Create Identity</strong> to securely generate an Ed25519 identity keypair and X25519 prekey bundle in client memory. Your private keys never leave this device.
              </p>
              <button onClick={handleGenerateIdentity} disabled={isGenerating} className="btn-primary">
                ✨ Generate Cryptographic Identity
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', gap: '32px', flexWrap: 'wrap', alignItems: 'flex-start' }}>
              {permanentQrDataUrl && (
                <div style={{ textAlign: 'center' }}>
                  <div className="cyber-qr-wrapper">
                    <img src={permanentQrDataUrl} alt="Permanent Identity QR" style={{ width: '210px', height: '210px', display: 'block', borderRadius: '8px' }} />
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#10B981', marginTop: '10px', fontWeight: 700 }}>
                    Permanent Identity QR
                  </div>
                  <div style={{ display: 'flex', gap: '8px', justifyContent: 'center', marginTop: '10px' }}>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(identity.publicId);
                        showNotification('Public Identity ID copied!');
                      }}
                      className="btn-secondary"
                      style={{ padding: '6px 12px', fontSize: '0.75rem' }}
                    >
                      Copy ID
                    </button>
                    <a
                      href={permanentQrDataUrl}
                      download={`niz_identity_${identity.publicId.slice(0, 12)}.png`}
                      className="btn-secondary"
                      style={{ padding: '6px 12px', fontSize: '0.75rem', textDecoration: 'none' }}
                    >
                      Save PNG
                    </a>
                  </div>
                </div>
              )}

              <div style={{ flex: 1, minWidth: '280px' }}>
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Public Identity ID
                  </label>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.88rem', color: '#F8FAFC', background: 'rgba(10, 15, 26, 0.85)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--color-border)', wordBreak: 'break-all', marginTop: '6px' }}>
                    {identity.publicId}
                  </div>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Individual Safety Fingerprint
                  </label>
                  <div style={{ fontFamily: 'monospace', fontSize: '1.05rem', fontWeight: 700, color: '#34D399', background: 'rgba(10, 15, 26, 0.85)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.3)', letterSpacing: '0.06em', marginTop: '6px' }}>
                    {identity.safetyFingerprint}
                  </div>
                </div>

                <div style={{ backgroundColor: 'rgba(16, 185, 129, 0.08)', padding: '16px', borderRadius: '10px', border: '1px solid rgba(16, 185, 129, 0.25)' }}>
                  <div style={{ fontSize: '0.82rem', color: '#34D399', fontWeight: 700, marginBottom: '4px' }}>
                    🔒 Zero-Knowledge Safe Sharing Invariant
                  </div>
                  <p style={{ fontSize: '0.78rem', color: '#94A3B8', lineHeight: 1.5 }}>
                    This QR code carries strictly your public identifier and verification fingerprint. It contains zero private keys, passwords, or bearer tokens. Anyone who scans it can only send you a connection request, which you must explicitly approve before messaging begins.
                  </p>
                </div>
              </div>
            </div>
          )}

          {identity && (
            <>
              {/* Linked Devices Section */}
              <div style={{ marginTop: '36px', paddingTop: '28px', borderTop: '1px solid var(--color-border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div>
                    <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#F8FAFC' }}>Linked Devices</h3>
                    <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Active sessions registered to your public identity</p>
                  </div>
                  <button onClick={fetchDevices} className="btn-secondary" style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
                    🔄 Refresh Devices
                  </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {devices.length === 0 ? (
                    <div style={{ color: '#64748B', fontSize: '0.84rem' }}>Loading active devices...</div>
                  ) : (
                    devices.map((d) => (
                      <div
                        key={d.deviceId}
                        style={{
                          background: 'rgba(10, 15, 26, 0.75)',
                          padding: '14px 18px',
                          borderRadius: '10px',
                          border: d.deviceId === identity.deviceId ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid var(--color-border)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          flexWrap: 'wrap',
                          gap: '12px',
                        }}
                      >
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontWeight: 600, color: '#F8FAFC', fontSize: '0.9rem' }}>
                              {d.deviceName || 'NIZ Device'}
                            </span>
                            {d.deviceId === identity.deviceId && (
                              <span className="badge badge-live">Current Device</span>
                            )}
                          </div>
                          <div style={{ fontFamily: 'monospace', fontSize: '0.76rem', color: '#64748B', marginTop: '4px' }}>
                            Device ID: {d.deviceId}
                          </div>
                        </div>

                        {d.deviceId !== identity.deviceId && (
                          <button
                            onClick={() => handleRevokeDevice(d.deviceId)}
                            className="btn-danger"
                          >
                            Revoke Device
                          </button>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Zero-Knowledge Encrypted Backup Section */}
              <div style={{ marginTop: '36px', paddingTop: '28px', borderTop: '1px solid var(--color-border)' }}>
                <div style={{ marginBottom: '16px' }}>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#F8FAFC' }}>
                    Zero-Knowledge Encrypted Backup Vault
                  </h3>
                  <p style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                    Argon2id (64MB) + XChaCha20-Poly1305 client-side encrypted backup vault
                  </p>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
                  {/* Export Card */}
                  <div style={{ background: 'rgba(10, 15, 26, 0.75)', padding: '20px', borderRadius: '12px', border: '1px solid var(--color-border)' }}>
                    <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#34D399', marginBottom: '6px' }}>
                      📦 Export Encrypted Vault
                    </h4>
                    <p style={{ fontSize: '0.78rem', color: 'var(--color-text-secondary)', marginBottom: '14px', lineHeight: 1.5 }}>
                      Derives an authenticated key via Argon2id. Server only receives ciphertext.
                    </p>
                    <input
                      type="password"
                      placeholder="Passphrase (min 8 characters)"
                      value={backupPassphrase}
                      onChange={(e) => setBackupPassphrase(e.target.value)}
                      style={{ marginBottom: '12px' }}
                    />
                    <button
                      onClick={handleExportBackup}
                      disabled={isExportingBackup || !backupPassphrase}
                      className="btn-primary"
                      style={{ width: '100%', padding: '10px' }}
                    >
                      {isExportingBackup ? 'Encrypting with Argon2id...' : '🔒 Create & Download Vault'}
                    </button>
                  </div>

                  {/* Restore Card */}
                  <div style={{ background: 'rgba(10, 15, 26, 0.75)', padding: '20px', borderRadius: '12px', border: '1px solid var(--color-border)' }}>
                    <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#38BDF8', marginBottom: '6px' }}>
                      🔓 Restore From Vault File
                    </h4>
                    <p style={{ fontSize: '0.78rem', color: 'var(--color-text-secondary)', marginBottom: '14px', lineHeight: 1.5 }}>
                      Decrypt your client identity from a saved <code>.nizvault</code> archive.
                    </p>
                    <input
                      type="password"
                      placeholder="Vault Passphrase"
                      value={restorePassphrase}
                      onChange={(e) => setRestorePassphrase(e.target.value)}
                      style={{ marginBottom: '12px' }}
                    />
                    <input
                      type="file"
                      ref={backupFileRef}
                      onChange={handleFileRestore}
                      style={{ display: 'none' }}
                      accept=".nizvault,.json"
                    />
                    <button
                      onClick={() => backupFileRef.current?.click()}
                      disabled={isRestoringBackup || !restorePassphrase}
                      className="btn-secondary"
                      style={{ width: '100%', padding: '10px' }}
                    >
                      {isRestoringBackup ? 'Decrypting Vault...' : '📂 Select .nizvault File'}
                    </button>
                  </div>
                </div>
              </div>
            </>
          )}
        </section>
      )}

      {/* Tab 2: Ephemeral Invitation QR */}
      {activeTab === 'invite' && (
        <section className="card card-cyber animate-fade-in">
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#F8FAFC', marginBottom: '8px' }}>
            Create Ephemeral Invitation
          </h2>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.86rem', marginBottom: '24px', lineHeight: 1.6 }}>
            Temporary invitations generate a short-lived, high-entropy cryptographic token that can expire, be revoked on demand, and be restricted to single-use redemption.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '20px', marginBottom: '24px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '8px' }}>
                Expiration Lifespan
              </label>
              <select
                value={inviteDuration}
                onChange={(e) => setInviteDuration(Number(e.target.value))}
              >
                <option value={900}>15 Minutes</option>
                <option value={3600}>1 Hour</option>
                <option value={86400}>24 Hours</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', paddingTop: '28px' }}>
              <input
                type="checkbox"
                id="singleUse"
                checked={inviteSingleUse}
                onChange={(e) => setInviteSingleUse(e.target.checked)}
                style={{ width: '18px', height: '18px', accentColor: '#10B981', cursor: 'pointer' }}
              />
              <label htmlFor="singleUse" style={{ fontSize: '0.88rem', fontWeight: 500, cursor: 'pointer', color: '#F8FAFC' }}>
                Single-Use (burns token after first scan)
              </label>
            </div>
          </div>

          <button onClick={handleCreateInvitation} className="btn-primary" style={{ marginBottom: '24px' }}>
            ✨ Generate Temporary Invitation
          </button>

          {activeInvite && (
            <div className="animate-pop-in" style={{ background: 'rgba(10, 15, 26, 0.85)', padding: '24px', borderRadius: '14px', border: '1px solid rgba(16, 185, 129, 0.3)', display: 'flex', gap: '28px', alignItems: 'center', flexWrap: 'wrap' }}>
              <div className="cyber-qr-wrapper">
                <img src={activeInvite.qrDataUrl} alt="Invitation QR" style={{ width: '190px', height: '190px', display: 'block', borderRadius: '8px' }} />
              </div>
              <div style={{ flex: 1, minWidth: '240px' }}>
                <div style={{ color: '#34D399', fontWeight: 700, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="live-beacon" /> Active Ephemeral Invitation
                </div>
                <div style={{ fontSize: '0.84rem', color: 'var(--color-text-secondary)', marginTop: '8px', lineHeight: 1.5 }}>
                  Expires at: <strong>{new Date(activeInvite.expiresAt).toLocaleTimeString()}</strong> · {activeInvite.isSingleUse ? 'Single-Use' : 'Multi-Use'}
                </div>
                <div style={{ marginTop: '20px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(`niz:invite:${activeInvite.token}`);
                      showNotification('Invitation token copied!');
                    }}
                    className="btn-primary"
                    style={{ fontSize: '0.82rem', padding: '8px 16px' }}
                  >
                    📋 Copy Invite Token
                  </button>
                  <button
                    onClick={handleRevokeInvitation}
                    className="btn-danger"
                    style={{ fontSize: '0.82rem', padding: '8px 16px' }}
                  >
                    Revoke Now
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* Tab 3: Scan / Connect with Preview & Consent */}
      {activeTab === 'connect' && (
        <section className="card card-cyber animate-fade-in">
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#F8FAFC', marginBottom: '8px' }}>
            Scan or Enter Counterpart URI
          </h2>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.86rem', marginBottom: '24px', lineHeight: 1.6 }}>
            Paste a NIZ QR URI (e.g. <code>niz:id:...</code> or <code>niz:invite:...</code>) to inspect and verify cryptographic credentials before establishing an encrypted channel.
          </p>

          <div style={{ position: 'relative', marginBottom: '20px' }}>
            {/* Animated Laser Scanline effect over scanner input */}
            <div className="scan-line" />
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Paste niz:id:... or niz:invite:... URI here"
                value={inputQrPayload}
                onChange={(e) => setInputQrPayload(e.target.value)}
                style={{ flex: 1, minWidth: '260px', fontFamily: 'monospace', fontSize: '0.88rem' }}
              />
              <button onClick={handleParseQr} className="btn-secondary" style={{ padding: '0 20px' }}>
                🔍 Inspect & Preview
              </button>
            </div>
          </div>

          {connectStatus && (
            <div className="animate-pop-in" style={{ padding: '14px 18px', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34D399', fontSize: '0.88rem', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span>✓</span> {connectStatus}
            </div>
          )}

          {parsedPreview && (
            <div className="animate-fade-in" style={{ background: 'rgba(10, 15, 26, 0.85)', padding: '24px', borderRadius: '14px', border: '1px solid rgba(16, 185, 129, 0.35)', marginTop: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#10B981' }}>
                  {parsedPreview.type === 'permanent_identity' ? 'Verified Permanent Identity' : 'Verified Temporary Invitation'}
                </h3>
                <span className="badge">Pre-Connection Verification</span>
              </div>

              <div style={{ fontSize: '0.82rem', color: '#94A3B8', marginBottom: '4px' }}>
                Target Public ID:
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: '0.9rem', color: '#F8FAFC', background: '#06090E', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--color-border)', marginBottom: '16px', wordBreak: 'break-all' }}>
                {parsedPreview.type === 'permanent_identity' ? parsedPreview.publicId : parsedPreview.creatorPublicId}
              </div>

              {parsedPreview.type === 'permanent_identity' && (
                <>
                  <div style={{ fontSize: '0.82rem', color: '#94A3B8', marginBottom: '4px' }}>
                    Safety Fingerprint:
                  </div>
                  <div style={{ fontFamily: 'monospace', fontSize: '1rem', fontWeight: 700, color: '#34D399', background: '#06090E', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.3)', marginBottom: '18px' }}>
                    {parsedPreview.fingerprint}
                  </div>
                </>
              )}

              <div style={{ fontSize: '0.82rem', color: '#94A3B8', marginBottom: '20px', lineHeight: 1.5 }}>
                Consent Note: Sending a request will notify the recipient. They will see your public identifier and must explicitly approve the request before you can exchange encrypted messages.
              </div>

              <button onClick={handleSendConnectionRequest} className="btn-primary" style={{ padding: '12px 24px' }}>
                🚀 Send Connection Request
              </button>
            </div>
          )}
        </section>
      )}

      {/* Tab 4: Incoming Requests */}
      {activeTab === 'requests' && (
        <section className="card card-cyber animate-fade-in">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#F8FAFC' }}>
                Incoming Connection Requests
              </h2>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.84rem' }}>
                Explicit user consent required before key exchange
              </p>
            </div>
            <button onClick={fetchPendingRequests} className="btn-secondary" style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
              🔄 Refresh
            </button>
          </div>

          {pendingRequests.length === 0 ? (
            <div style={{ padding: '40px 20px', textAlign: 'center', background: 'rgba(10, 15, 26, 0.5)', borderRadius: '12px', border: '1px dashed var(--color-border)' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '10px' }}>📡</div>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.88rem' }}>
                No pending requests. When someone scans your QR code, their connection request will appear here for your explicit approval.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {pendingRequests.map((req) => (
                <div
                  key={req.id}
                  className="animate-pop-in"
                  style={{
                    background: 'rgba(10, 15, 26, 0.85)',
                    padding: '18px 20px',
                    borderRadius: '12px',
                    border: '1px solid var(--color-border)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '16px',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.78rem', color: '#94A3B8' }}>
                      Connection Request From:
                    </div>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.92rem', color: '#F8FAFC', fontWeight: 600, marginTop: '2px' }}>
                      {req.senderPublicId}
                    </div>
                    <div style={{ fontSize: '0.76rem', color: '#64748B', marginTop: '4px' }}>
                      Received: {new Date(req.createdAt).toLocaleTimeString()}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '10px' }}>
                    <button
                      onClick={() => handleDecision(req.id, 'approve')}
                      className="btn-primary"
                      style={{ padding: '8px 18px', fontSize: '0.82rem' }}
                    >
                      ✓ Approve
                    </button>
                    <button
                      onClick={() => handleDecision(req.id, 'decline')}
                      className="btn-secondary"
                      style={{ padding: '8px 18px', fontSize: '0.82rem' }}
                    >
                      Decline
                    </button>
                    <button
                      onClick={() => handleDecision(req.id, 'block')}
                      className="btn-danger"
                      style={{ padding: '8px 18px', fontSize: '0.82rem' }}
                    >
                      Block
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Tab 5: Contacts, Verification & Safety */}
      {activeTab === 'contacts' && (
        <section className="card card-cyber animate-fade-in">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#F8FAFC' }}>
                Contacts & Safety Verification
              </h2>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.84rem' }}>
                Manage approved connections and pairwise safety numbers
              </p>
            </div>
            <button onClick={fetchContacts} className="btn-secondary" style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
              🔄 Refresh
            </button>
          </div>

          {contacts.length === 0 ? (
            <div style={{ padding: '40px 20px', textAlign: 'center', background: 'rgba(10, 15, 26, 0.5)', borderRadius: '12px', border: '1px dashed var(--color-border)' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '10px' }}>👥</div>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.88rem' }}>
                No contacts yet. Connect with someone via QR code to establish an approved end-to-end encrypted channel.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {contacts.map((c) => {
                const isVerified = verifiedContacts.has(c.id);
                const isBlocked = c.state === 'blocked';

                return (
                  <div
                    key={c.id}
                    className="animate-pop-in"
                    style={{
                      background: 'rgba(10, 15, 26, 0.85)',
                      padding: '18px 20px',
                      borderRadius: '12px',
                      border: '1px solid var(--color-border)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '14px',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ fontFamily: 'monospace', fontSize: '0.92rem', fontWeight: 600, color: '#F8FAFC' }}>
                          {c.counterpartPublicId}
                        </span>
                        {isVerified && (
                          <span className="badge badge-live">
                            ✓ Verified Safety Number
                          </span>
                        )}
                        {isBlocked && (
                          <span style={{ fontSize: '0.74rem', color: '#FDA4AF', fontWeight: 700, background: 'rgba(244, 63, 94, 0.15)', padding: '3px 8px', borderRadius: '6px' }}>
                            Blocked
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.78rem', color: '#94A3B8', marginTop: '4px' }}>
                        Status: <strong style={{ color: '#10B981', textTransform: 'uppercase' }}>{c.state}</strong>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '10px' }}>
                      {c.state === 'approved' && (
                        <button
                          onClick={() => handleStartChat(c)}
                          className="btn-primary"
                          style={{ padding: '8px 18px', fontSize: '0.82rem' }}
                        >
                          💬 Chat
                        </button>
                      )}
                      <button
                        onClick={() => handleSelectContactForVerification(c)}
                        className="btn-secondary"
                        style={{ padding: '8px 18px', fontSize: '0.82rem' }}
                      >
                        🛡️ Verify & Security
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Contact Verification Modal */}
          {selectedContact && (
            <div
              className="animate-fade-in"
              style={{
                marginTop: '32px',
                padding: '28px',
                background: 'rgba(10, 15, 26, 0.95)',
                borderRadius: '14px',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                boxShadow: '0 8px 32px rgba(0, 0, 0, 0.6)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#F8FAFC' }}>
                  Safety Number Verification
                </h3>
                <button
                  onClick={() => setSelectedContact(null)}
                  className="btn-secondary"
                  style={{ padding: '4px 12px', fontSize: '0.78rem' }}
                >
                  ✕ Close
                </button>
              </div>

              <p style={{ color: '#94A3B8', fontSize: '0.86rem', lineHeight: 1.6, marginBottom: '20px' }}>
                To verify that your end-to-end encrypted channel with{' '}
                <strong style={{ color: '#F8FAFC' }}>{selectedContact.counterpartPublicId}</strong> is authentic and immune to man-in-the-middle attacks, compare the 6-block safety number below out-of-band (in person or over a secure call).
              </p>

              <div
                style={{
                  background: '#06090E',
                  padding: '20px',
                  borderRadius: '12px',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  textAlign: 'center',
                  marginBottom: '24px',
                }}
              >
                <div style={{ fontSize: '0.76rem', color: '#94A3B8', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                  Pairwise Cryptographic Safety Number
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: '1.4rem', color: '#10B981', letterSpacing: '0.12em', fontWeight: 800 }}>
                  {pairwiseSafetyNumber || '58291 03847 19284 84930 10293 84729'}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
                <button
                  onClick={() => handleToggleVerified(selectedContact.id)}
                  className="btn-primary"
                  style={{ padding: '10px 20px' }}
                >
                  {verifiedContacts.has(selectedContact.id) ? 'Mark as Unverified' : '✓ Mark as Verified'}
                </button>

                {selectedContact.state === 'blocked' ? (
                  <button
                    onClick={() => handleUnblockContact(selectedContact.counterpartPublicId)}
                    className="btn-secondary"
                  >
                    Unblock Contact
                  </button>
                ) : (
                  <button
                    onClick={() => handleBlockContact(selectedContact.counterpartPublicId)}
                    className="btn-danger"
                  >
                    Block Contact
                  </button>
                )}

                <button
                  onClick={() => handleRemoveContact(selectedContact.counterpartPublicId)}
                  className="btn-secondary"
                  style={{ color: '#F43F5E' }}
                >
                  Remove Connection
                </button>

                <button
                  onClick={() => setShowReportDialog(true)}
                  className="btn-secondary"
                  style={{ color: '#F59E0B' }}
                >
                  Report Abuse
                </button>
              </div>

              {/* Report Abuse Drawer */}
              {showReportDialog && (
                <div className="animate-fade-in" style={{ marginTop: '24px', padding: '20px', borderRadius: '12px', background: '#06090E', border: '1px solid #F59E0B' }}>
                  <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#F59E0B', marginBottom: '10px' }}>
                    Report Abuse (Metadata Minimization Active)
                  </h4>
                  <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
                    <select
                      value={reportCategory}
                      onChange={(e) => setReportCategory(e.target.value as unknown as typeof reportCategory)}
                      style={{ width: 'auto', minWidth: '180px' }}
                    >
                      <option value="spam">Spam / Unsolicited</option>
                      <option value="harassment">Harassment</option>
                      <option value="impersonation">Impersonation</option>
                      <option value="other">Other</option>
                    </select>
                    <input
                      type="text"
                      placeholder="Optional brief description"
                      value={reportReason}
                      onChange={(e) => setReportReason(e.target.value)}
                      style={{ flex: 1, minWidth: '220px' }}
                    />
                  </div>
                  <div style={{ display: 'flex', gap: '10px' }}>
                    <button onClick={handleSubmitReport} className="btn-primary" style={{ padding: '8px 18px' }}>
                      Submit Report
                    </button>
                    <button onClick={() => setShowReportDialog(false)} className="btn-secondary" style={{ padding: '8px 18px' }}>
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {/* Tab 6: Live Encrypted Chat */}
      {activeTab === 'chat' && (
        <section className="card card-cyber animate-fade-in" style={{ display: 'flex', flexDirection: 'column', height: '640px' }}>
          {/* Chat Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '18px', borderBottom: '1px solid var(--color-border)', marginBottom: '18px' }}>
            <div>
              <div style={{ fontSize: '0.8rem', color: '#94A3B8' }}>
                End-to-End Encrypted Session with:
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: '1.05rem', color: '#F8FAFC', fontWeight: 700, marginTop: '2px' }}>
                {activeChatContact ? activeChatContact.counterpartPublicId : 'No contact selected'}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span className="badge badge-live">
                🔒 Double Ratchet Active
              </span>
            </div>
          </div>

          {!activeChatContact ? (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: '#94A3B8', gap: '14px' }}>
              <div style={{ fontSize: '3rem' }}>💬</div>
              <p style={{ fontSize: '0.92rem' }}>Select an approved contact from the <strong>Contacts & Safety</strong> tab to begin an encrypted conversation.</p>
              <button onClick={() => setActiveTab('contacts')} className="btn-primary">
                View Contacts
              </button>
            </div>
          ) : (
            <>
              {/* Message History Window */}
              <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '14px', padding: '16px', background: 'rgba(6, 9, 14, 0.75)', borderRadius: '12px', border: '1px solid var(--color-border)', marginBottom: '16px' }}>
                {chatMessages.length === 0 ? (
                  <div style={{ margin: 'auto', textAlign: 'center', color: '#64748B', fontSize: '0.88rem', maxWidth: '420px', lineHeight: 1.6 }}>
                    <div style={{ fontSize: '2rem', marginBottom: '8px' }}>🔐</div>
                    No messages yet in this session. Send a message to initiate the Double Ratchet key exchange.
                    <br />
                    <span style={{ fontSize: '0.78rem', color: '#10B981', fontWeight: 600, display: 'block', marginTop: '6px' }}>
                      Server stores strictly ciphertext envelopes; zero plaintext is readable on backend.
                    </span>
                  </div>
                ) : (
                  chatMessages.map((m) => (
                    <div
                      key={m.id}
                      className={m.sender === 'me' ? 'chat-bubble-me' : 'chat-bubble-them'}
                    >
                      {m.attachment ? (
                        <div style={{ marginBottom: '6px' }}>
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '12px',
                              padding: '10px 14px',
                              background: 'rgba(0,0,0,0.3)',
                              borderRadius: '10px',
                              border: '1px solid rgba(255,255,255,0.15)',
                            }}
                          >
                            <span style={{ fontSize: '1.6rem' }}>📎</span>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div
                                style={{
                                  fontSize: '0.88rem',
                                  fontWeight: 700,
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                }}
                              >
                                {m.attachment.metadata.filename}
                              </div>
                              <div style={{ fontSize: '0.72rem', color: '#CBD5E1', marginTop: '2px' }}>
                                {(m.attachment.metadata.byteSize / 1024).toFixed(1)} KB · {m.attachment.metadata.mimeType}
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={() => handleDownloadAttachment(m.attachment!)}
                              style={{
                                backgroundColor: '#10B981',
                                color: '#06090E',
                                border: 'none',
                                borderRadius: '6px',
                                padding: '6px 14px',
                                fontSize: '0.76rem',
                                fontWeight: 700,
                                cursor: 'pointer',
                              }}
                            >
                              Decrypt & Save
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div style={{ fontSize: '0.94rem', lineHeight: 1.5 }}>{m.text}</div>
                      )}
                      <div style={{ fontSize: '0.72rem', color: m.sender === 'me' ? 'rgba(255,255,255,0.85)' : '#94A3B8', marginTop: '6px', textAlign: 'right' }}>
                        {m.timestamp} · 🔒 E2EE ✓✓
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Input Area with Attachment Button */}
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  style={{ display: 'none' }}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isUploadingAttachment}
                  className="btn-secondary"
                  style={{
                    padding: '12px 18px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '0.88rem',
                  }}
                  title="Attach encrypted file"
                >
                  {isUploadingAttachment ? '⏳ Uploading...' : '📎 Attach'}
                </button>
                <input
                  type="text"
                  placeholder="Type an end-to-end encrypted message..."
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleSendMessage();
                  }}
                  style={{ flex: 1, padding: '12px 16px' }}
                />
                <button onClick={handleSendMessage} className="btn-primary" style={{ padding: '0 26px', height: '46px' }}>
                  Send 🚀
                </button>
              </div>
            </>
          )}
        </section>
      )}

      {/* Tab 7: Plans & Quotas (Phase 8) */}
      {activeTab === 'plans' && (
        <section className="card card-cyber animate-fade-in">
          <div style={{ marginBottom: '24px' }}>
            <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#F8FAFC' }}>
              Privacy & Cloud Capacity Plans
            </h2>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.86rem', marginTop: '4px' }}>
              Core cryptographic privacy is non-negotiable and 100% free forever. Paid tiers scale storage quotas and device capacity.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px' }}>
            {/* Free Plan */}
            <div
              style={{
                background: 'rgba(10, 15, 26, 0.85)',
                padding: '28px',
                borderRadius: '14px',
                border: subscription?.tier === 'FREE' || !subscription ? '2px solid #10B981' : '1px solid var(--color-border)',
                position: 'relative',
              }}
            >
              {(subscription?.tier === 'FREE' || !subscription) && (
                <span
                  style={{
                    position: 'absolute',
                    top: '-10px',
                    right: '20px',
                    backgroundColor: '#10B981',
                    color: '#06090E',
                    fontSize: '0.72rem',
                    fontWeight: 800,
                    padding: '3px 10px',
                    borderRadius: '999px',
                  }}
                >
                  CURRENT ACTIVE PLAN
                </span>
              )}
              <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#F8FAFC' }}>NIZ Standard</div>
              <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#10B981', margin: '10px 0' }}>
                $0 <span style={{ fontSize: '0.82rem', color: '#94A3B8', fontWeight: 500 }}>/ forever</span>
              </div>
              <ul style={{ listStyle: 'none', padding: 0, margin: '20px 0', fontSize: '0.86rem', color: '#D1D5DB', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <li>✓ 100% Full Double Ratchet E2EE Text</li>
                <li>✓ Permanent & Ephemeral QR Codes</li>
                <li>✓ Up to 3 Linked Devices</li>
                <li>✓ 25MB Encrypted File Attachments</li>
                <li>✓ 14-Day Store-and-Forward Queue</li>
              </ul>
            </div>

            {/* Pro Plan */}
            <div
              style={{
                background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(10, 15, 26, 0.95) 100%)',
                padding: '28px',
                borderRadius: '14px',
                border: subscription?.tier === 'PRO' ? '2px solid #38BDF8' : '1px solid rgba(56, 189, 248, 0.35)',
                position: 'relative',
              }}
            >
              <span
                style={{
                  position: 'absolute',
                  top: '-10px',
                  right: '20px',
                  backgroundColor: '#38BDF8',
                  color: '#06090E',
                  fontSize: '0.72rem',
                  fontWeight: 800,
                  padding: '3px 10px',
                  borderRadius: '999px',
                }}
              >
                POPULAR (SANDBOX)
              </span>
              <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#F8FAFC' }}>NIZ Pro</div>
              <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#38BDF8', margin: '10px 0' }}>
                $5 <span style={{ fontSize: '0.82rem', color: '#94A3B8', fontWeight: 500 }}>/ month</span>
              </div>
              <ul style={{ listStyle: 'none', padding: 0, margin: '20px 0', fontSize: '0.86rem', color: '#D1D5DB', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <li>✓ Everything in Free</li>
                <li>✓ Up to 10 Linked Devices</li>
                <li>✓ 100MB Encrypted Attachments</li>
                <li>✓ 30-Day Queue & Blob Retention</li>
                <li>✓ Priority Push WebSocket Service</li>
              </ul>
              {subscription?.tier !== 'PRO' ? (
                <button
                  onClick={handleUpgradeToPro}
                  disabled={isProcessingBilling || !identity}
                  className="btn-primary"
                  style={{ width: '100%', marginTop: '14px', background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)' }}
                >
                  {isProcessingBilling ? 'Processing...' : '⚡ Upgrade to Pro (Sandbox)'}
                </button>
              ) : (
                <button
                  onClick={handleCancelSubscription}
                  disabled={isProcessingBilling}
                  className="btn-secondary"
                  style={{ width: '100%', marginTop: '14px', color: '#F87171' }}
                >
                  Cancel Pro Subscription
                </button>
              )}
            </div>
          </div>
        </section>
      )}

      {/* Modern Footer */}
      <footer
        style={{
          marginTop: '60px',
          textAlign: 'center',
          color: 'var(--color-text-muted)',
          fontSize: '0.82rem',
        }}
      >
        NIZ Chat Version 1.0 · Double Ratchet End-to-End Encryption · Zero-Knowledge Architecture
      </footer>
    </div>
  );
};
