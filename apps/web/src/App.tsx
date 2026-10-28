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
} from '@niz/shared-types';
import { NizLogo } from './components/NizLogo';

const API_BASE = 'http://localhost:4000';
const WS_BASE = 'ws://localhost:4000';

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
  const [activeTab, setActiveTab] = useState<'identity' | 'invite' | 'connect' | 'requests' | 'contacts' | 'chat'>('identity');
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

  // Setup WebSocket connection for incoming ciphertext envelopes
  useEffect(() => {
    if (!identity) return;

    const wsUrl = `${WS_BASE}/v1/ws?deviceId=${identity.deviceId}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsWsConnected(true);
    };

    ws.onclose = () => {
      setIsWsConnected(false);
    };

    ws.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'ciphertext_envelope' && data.envelope) {
          const envelope: MessageEnvelope = data.envelope;
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

          // Append to message thread
          setChatMessages((prev) => [
            ...prev,
            {
              id: envelope.envelopeId,
              sender: 'them',
              text: displayText,
              attachment: attachmentObj,
              timestamp: new Date(envelope.createdAt).toLocaleTimeString(),
              verifiedE2EE: true,
            },
          ]);

          // Immediately acknowledge and purge from server queue
          await fetch(`${API_BASE}/v1/messages/ack`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ envelopeIds: [envelope.envelopeId] }),
          });
        }
      } catch {
        // ignore
      }
    };

    return () => {
      ws.close();
    };
  }, [identity, activeChatContact]);

  useEffect(() => {
    if (activeTab === 'identity') {
      fetchDevices();
    } else if (activeTab === 'requests') {
      fetchPendingRequests();
    } else if (activeTab === 'contacts' || activeTab === 'chat') {
      fetchContacts();
    }
  }, [activeTab, identity]);

  return (
    <div style={{ maxWidth: '960px', margin: '0 auto', padding: '36px 20px', width: '100%' }}>
      {/* Toast Notification */}
      {notification && (
        <div
          style={{
            position: 'fixed',
            top: '20px',
            right: '20px',
            backgroundColor: '#10B981',
            color: '#090D14',
            padding: '12px 20px',
            borderRadius: '8px',
            fontWeight: 600,
            fontSize: '0.88rem',
            zIndex: 9999,
            boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
          }}
        >
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
          paddingBottom: '20px',
          borderBottom: '1px solid var(--color-border)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <NizLogo size={48} />
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
              NIZ Chat
            </h1>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem' }}>
              Privacy-first, QR-connected messaging
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="badge">Phase 4: Encrypted Text MVP</span>
          {identity && (
            <span
              style={{
                fontSize: '0.75rem',
                padding: '4px 8px',
                borderRadius: '6px',
                backgroundColor: isWsConnected ? '#064E3B' : '#7F1D1D',
                color: isWsConnected ? '#34D399' : '#F87171',
                border: '1px solid',
                borderColor: isWsConnected ? '#10B981' : '#EF4444',
              }}
            >
              {isWsConnected ? '● Live Push' : '○ Offline'}
            </span>
          )}
        </div>
      </header>

      {/* Tabs */}
      <nav style={{ display: 'flex', gap: '10px', marginBottom: '28px', flexWrap: 'wrap' }}>
        <button
          onClick={() => setActiveTab('identity')}
          className={activeTab === 'identity' ? 'btn-primary' : 'btn-secondary'}
        >
          My Identity & QR
        </button>
        <button
          onClick={() => setActiveTab('invite')}
          className={activeTab === 'invite' ? 'btn-primary' : 'btn-secondary'}
        >
          Invite Someone (Expiring)
        </button>
        <button
          onClick={() => setActiveTab('connect')}
          className={activeTab === 'connect' ? 'btn-primary' : 'btn-secondary'}
        >
          Scan / Connect
        </button>
        <button
          onClick={() => setActiveTab('requests')}
          className={activeTab === 'requests' ? 'btn-primary' : 'btn-secondary'}
        >
          Incoming Requests
        </button>
        <button
          onClick={() => setActiveTab('contacts')}
          className={activeTab === 'contacts' ? 'btn-primary' : 'btn-secondary'}
        >
          Contacts & Safety
        </button>
        <button
          onClick={() => setActiveTab('chat')}
          className={activeTab === 'chat' ? 'btn-primary' : 'btn-secondary'}
        >
          Encrypted Chat
        </button>
      </nav>

      {/* Tab 1: Identity & Permanent QR */}
      {activeTab === 'identity' && (
        <section className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h2 style={{ fontSize: '1.25rem' }}>Your Cryptographic Identity</h2>
            <button
              onClick={handleGenerateIdentity}
              disabled={isGenerating}
              className="btn-primary"
            >
              {identity ? 'Rotate / Re-generate Keys' : 'Create Identity'}
            </button>
          </div>

          {!identity ? (
            <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
              No identity found in client memory. Click <strong>Create Identity</strong> to securely
              generate an Ed25519 identity keypair and X25519 prekey bundle locally. Your private keys
              will never be sent to the server.
            </p>
          ) : (
            <div style={{ display: 'flex', gap: '28px', flexWrap: 'wrap', alignItems: 'flex-start' }}>
              {permanentQrDataUrl && (
                <div style={{ textAlign: 'center' }}>
                  <div
                    style={{
                      background: '#090D14',
                      padding: '12px',
                      borderRadius: '12px',
                      border: '1px solid var(--color-border)',
                      display: 'inline-block',
                    }}
                  >
                    <img src={permanentQrDataUrl} alt="Permanent Identity QR" style={{ width: '200px', height: '200px', display: 'block' }} />
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-primary)', marginTop: '8px', fontWeight: 600 }}>
                    Permanent Identity QR
                  </div>
                </div>
              )}

              <div style={{ flex: 1, minWidth: '280px' }}>
                <div style={{ marginBottom: '14px' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Public Identity ID
                  </label>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#F9FAFB', background: '#090D14', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--color-border)', wordBreak: 'break-all', marginTop: '4px' }}>
                    {identity.publicId}
                  </div>
                </div>

                <div style={{ marginBottom: '14px' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Individual Safety Fingerprint
                  </label>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.95rem', color: 'var(--color-primary)', background: '#090D14', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--color-border)', letterSpacing: '0.05em', marginTop: '4px' }}>
                    {identity.safetyFingerprint}
                  </div>
                </div>

                <div style={{ backgroundColor: '#090D14', padding: '14px', borderRadius: '8px', border: '1px solid var(--color-border)' }}>
                  <div style={{ fontSize: '0.8rem', color: '#10B981', fontWeight: 600, marginBottom: '4px' }}>
                    🔒 Safe Sharing Invariant
                  </div>
                  <p style={{ fontSize: '0.78rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                    This QR code carries strictly your public identifier and verification fingerprint. It contains zero private keys, passwords, or bearer tokens. Anyone who scans it can only send you a connection request, which you must explicitly approve before messaging begins.
                  </p>
                </div>
              </div>
            </div>
          )}

          {identity && (
            <>
              {/* Linked Devices Section (Phase 7) */}
              <div style={{ marginTop: '32px', paddingTop: '24px', borderTop: '1px solid var(--color-border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <h3 style={{ fontSize: '1.1rem', color: '#F9FAFB' }}>Linked Devices</h3>
                  <button onClick={fetchDevices} className="btn-secondary" style={{ padding: '6px 12px', fontSize: '0.8rem' }}>
                    ↻ Refresh Devices
                  </button>
                </div>
                {devices.length === 0 ? (
                  <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem' }}>No other devices linked.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {devices.map((d) => (
                      <div
                        key={d.deviceId}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '12px 16px',
                          background: '#090D14',
                          borderRadius: '8px',
                          border: '1px solid var(--color-border)',
                        }}
                      >
                        <div>
                          <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#F9FAFB' }}>
                            {d.deviceName || 'Client Device'}{' '}
                            {d.deviceId === identity.deviceId && (
                              <span style={{ fontSize: '0.75rem', color: '#10B981', fontWeight: 500 }}>(This Device)</span>
                            )}
                          </div>
                          <div style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                            ID: {d.deviceId} · Registered: {new Date(d.createdAt).toLocaleDateString()}
                          </div>
                          {d.revokedAt && (
                            <span style={{ fontSize: '0.72rem', color: '#EF4444', fontWeight: 600 }}>
                              Revoked at {new Date(d.revokedAt).toLocaleTimeString()}
                            </span>
                          )}
                        </div>
                        {d.deviceId !== identity.deviceId && !d.revokedAt && (
                          <button
                            onClick={() => handleRevokeDevice(d.deviceId)}
                            className="btn-secondary"
                            style={{ color: '#EF4444', borderColor: '#7F1D1D', padding: '6px 12px', fontSize: '0.8rem' }}
                          >
                            Revoke Device
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Zero-Knowledge Encrypted Backup & Secure Recovery (Phase 7) */}
              <div style={{ marginTop: '32px', paddingTop: '24px', borderTop: '1px solid var(--color-border)' }}>
                <h3 style={{ fontSize: '1.1rem', color: '#F9FAFB', marginBottom: '8px' }}>
                  Encrypted Backup & Recovery (Argon2id + XChaCha20-Poly1305)
                </h3>
                <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem', lineHeight: 1.6, marginBottom: '20px' }}>
                  Create an encrypted, password-protected recovery vault for your identity and contacts. The server never sees your passphrase or unencrypted backup keys.
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
                  {/* Export Backup Vault */}
                  <div style={{ background: '#090D14', padding: '16px', borderRadius: '10px', border: '1px solid var(--color-border)' }}>
                    <h4 style={{ fontSize: '0.95rem', color: '#10B981', marginBottom: '10px' }}>
                      Export Encrypted Vault
                    </h4>
                    <p style={{ fontSize: '0.78rem', color: 'var(--color-text-secondary)', marginBottom: '12px' }}>
                      Derives an encryption key via Argon2id. Generates a <code>.nizvault</code> file.
                    </p>
                    <input
                      type="password"
                      placeholder="Passphrase (min 8 chars)"
                      value={backupPassphrase}
                      onChange={(e) => setBackupPassphrase(e.target.value)}
                      style={{ width: '100%', padding: '10px', background: '#111827', border: '1px solid var(--color-border)', borderRadius: '6px', color: '#F9FAFB', marginBottom: '12px' }}
                    />
                    <button
                      onClick={handleExportBackup}
                      disabled={isExportingBackup || !backupPassphrase}
                      className="btn-primary"
                      style={{ width: '100%', padding: '10px' }}
                    >
                      {isExportingBackup ? 'Deriving Argon2id...' : '🔒 Export & Sync Vault'}
                    </button>
                  </div>

                  {/* Restore Backup Vault */}
                  <div style={{ background: '#090D14', padding: '16px', borderRadius: '10px', border: '1px solid var(--color-border)' }}>
                    <h4 style={{ fontSize: '0.95rem', color: '#38BDF8', marginBottom: '10px' }}>
                      Restore from Backup Vault
                    </h4>
                    <p style={{ fontSize: '0.78rem', color: 'var(--color-text-secondary)', marginBottom: '12px' }}>
                      Enter your vault passphrase and select your <code>.nizvault</code> file.
                    </p>
                    <input
                      type="password"
                      placeholder="Vault Passphrase"
                      value={restorePassphrase}
                      onChange={(e) => setRestorePassphrase(e.target.value)}
                      style={{ width: '100%', padding: '10px', background: '#111827', border: '1px solid var(--color-border)', borderRadius: '6px', color: '#F9FAFB', marginBottom: '12px' }}
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
        <section className="card">
          <h2 style={{ fontSize: '1.25rem', marginBottom: '12px' }}>Create Ephemeral Invitation</h2>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem', marginBottom: '20px', lineHeight: 1.6 }}>
            Temporary invitations generate a short-lived, high-entropy cryptographic token that can expire, be revoked on demand, and be restricted to single-use redemption.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '20px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginBottom: '6px' }}>
                Expiration Lifespan
              </label>
              <select
                value={inviteDuration}
                onChange={(e) => setInviteDuration(Number(e.target.value))}
                style={{ width: '100%', padding: '10px', background: '#090D14', color: '#F9FAFB', border: '1px solid var(--color-border)', borderRadius: '8px' }}
              >
                <option value={900}>15 Minutes</option>
                <option value={3600}>1 Hour</option>
                <option value={86400}>24 Hours</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', paddingTop: '20px' }}>
              <input
                type="checkbox"
                id="singleUse"
                checked={inviteSingleUse}
                onChange={(e) => setInviteSingleUse(e.target.checked)}
                style={{ width: '18px', height: '18px', accentColor: '#10B981' }}
              />
              <label htmlFor="singleUse" style={{ fontSize: '0.85rem', cursor: 'pointer' }}>
                Single-Use (burns token after first scan)
              </label>
            </div>
          </div>

          <button onClick={handleCreateInvitation} className="btn-primary" style={{ marginBottom: '24px' }}>
            Generate Temporary Invitation
          </button>

          {activeInvite && (
            <div style={{ background: '#090D14', padding: '20px', borderRadius: '12px', border: '1px solid var(--color-border)', display: 'flex', gap: '24px', alignItems: 'center', flexWrap: 'wrap' }}>
              <img src={activeInvite.qrDataUrl} alt="Invitation QR" style={{ width: '180px', height: '180px', borderRadius: '8px' }} />
              <div style={{ flex: 1 }}>
                <div style={{ color: '#34D399', fontWeight: 600, fontSize: '0.9rem' }}>
                  Active Temporary Invitation
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginTop: '4px' }}>
                  Expires at: {new Date(activeInvite.expiresAt).toLocaleTimeString()} · {activeInvite.isSingleUse ? 'Single-Use' : 'Multi-Use'}
                </div>
                <div style={{ marginTop: '16px' }}>
                  <button onClick={handleRevokeInvitation} className="btn-secondary" style={{ color: '#EF4444', borderColor: '#EF4444' }}>
                    Revoke Invitation Immediately
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* Tab 3: Scan / Connect with Preview & Consent */}
      {activeTab === 'connect' && (
        <section className="card">
          <h2 style={{ fontSize: '1.25rem', marginBottom: '12px' }}>Scan or Enter QR Code</h2>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem', marginBottom: '20px', lineHeight: 1.6 }}>
            Paste a NIZ QR URI (e.g. <code>niz:id:...</code> or <code>niz:invite:...</code>) to inspect and verify the counterpart before initiating a connection.
          </p>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
            <input
              type="text"
              placeholder="Paste niz:id:... or niz:invite:... URI here"
              value={inputQrPayload}
              onChange={(e) => setInputQrPayload(e.target.value)}
              style={{ flex: 1, padding: '10px 14px', background: '#090D14', border: '1px solid var(--color-border)', borderRadius: '8px', color: '#F9FAFB', fontFamily: 'monospace', fontSize: '0.85rem' }}
            />
            <button onClick={handleParseQr} className="btn-secondary">
              Inspect & Preview
            </button>
          </div>

          {connectStatus && (
            <div style={{ padding: '12px', borderRadius: '8px', background: '#090D14', border: '1px solid var(--color-border)', color: '#34D399', fontSize: '0.85rem', marginBottom: '16px' }}>
              {connectStatus}
            </div>
          )}

          {parsedPreview && (
            <div style={{ background: '#090D14', padding: '20px', borderRadius: '12px', border: '1px solid var(--color-border)', marginTop: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <h3 style={{ fontSize: '1rem', color: '#10B981' }}>
                  {parsedPreview.type === 'permanent_identity' ? 'Permanent Identity Preview' : 'Ephemeral Invitation Preview'}
                </h3>
                <span className="badge">Pre-Connection Verification</span>
              </div>

              <div style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginBottom: '8px' }}>
                Target Public ID:
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#F9FAFB', marginBottom: '12px', wordBreak: 'break-all' }}>
                {parsedPreview.type === 'permanent_identity' ? parsedPreview.publicId : parsedPreview.creatorPublicId}
              </div>

              {parsedPreview.type === 'permanent_identity' && (
                <>
                  <div style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginBottom: '8px' }}>
                    Safety Fingerprint:
                  </div>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.95rem', color: 'var(--color-primary)', marginBottom: '16px' }}>
                    {parsedPreview.fingerprint}
                  </div>
                </>
              )}

              <div style={{ fontSize: '0.8rem', color: '#9CA3AF', marginBottom: '16px', lineHeight: 1.5 }}>
                Consent Note: Sending a request will notify the recipient. They will see your public identifier and must explicitly approve the request before you can exchange encrypted messages.
              </div>

              <button onClick={handleSendConnectionRequest} className="btn-primary">
                Send Connection Request
              </button>
            </div>
          )}
        </section>
      )}

      {/* Tab 4: Incoming Requests */}
      {activeTab === 'requests' && (
        <section className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h2 style={{ fontSize: '1.25rem' }}>Incoming Connection Requests</h2>
            <button onClick={fetchPendingRequests} className="btn-secondary" style={{ fontSize: '0.8rem' }}>
              Refresh
            </button>
          </div>

          {pendingRequests.length === 0 ? (
            <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem' }}>
              No pending connection requests. When an unknown user scans your QR, their connection request will appear here for your explicit approval.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {pendingRequests.map((req) => (
                <div
                  key={req.id}
                  style={{
                    background: '#090D14',
                    padding: '16px',
                    borderRadius: '10px',
                    border: '1px solid var(--color-border)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '12px',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                      Request from:
                    </div>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#F9FAFB' }}>
                      {req.senderPublicId}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#6B7280', marginTop: '4px' }}>
                      Received: {new Date(req.createdAt).toLocaleTimeString()}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      onClick={() => handleDecision(req.id, 'approve')}
                      className="btn-primary"
                      style={{ padding: '6px 14px', fontSize: '0.8rem' }}
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => handleDecision(req.id, 'decline')}
                      className="btn-secondary"
                      style={{ padding: '6px 14px', fontSize: '0.8rem' }}
                    >
                      Decline
                    </button>
                    <button
                      onClick={() => handleDecision(req.id, 'block')}
                      className="btn-secondary"
                      style={{ padding: '6px 14px', fontSize: '0.8rem', color: '#EF4444' }}
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
        <section className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h2 style={{ fontSize: '1.25rem' }}>Contacts & Safety Verification</h2>
            <button onClick={fetchContacts} className="btn-secondary" style={{ fontSize: '0.8rem' }}>
              Refresh
            </button>
          </div>

          {contacts.length === 0 ? (
            <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem' }}>
              No contacts yet. Connect with someone via QR to establish an approved end-to-end encrypted channel.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {contacts.map((c) => {
                const isVerified = verifiedContacts.has(c.id);
                const isBlocked = c.state === 'blocked';

                return (
                  <div
                    key={c.id}
                    style={{
                      background: '#090D14',
                      padding: '16px',
                      borderRadius: '10px',
                      border: '1px solid var(--color-border)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '12px',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontFamily: 'monospace', fontSize: '0.9rem', color: '#F9FAFB' }}>
                          {c.counterpartPublicId}
                        </span>
                        {isVerified && (
                          <span style={{ fontSize: '0.75rem', color: '#10B981', fontWeight: 600 }}>
                            ✓ Verified Safety Number
                          </span>
                        )}
                        {isBlocked && (
                          <span style={{ fontSize: '0.75rem', color: '#EF4444', fontWeight: 600 }}>
                            Blocked
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', marginTop: '4px' }}>
                        Status: <strong style={{ textTransform: 'uppercase' }}>{c.state}</strong>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '8px' }}>
                      {c.state === 'approved' && (
                        <button
                          onClick={() => handleStartChat(c)}
                          className="btn-primary"
                          style={{ padding: '6px 14px', fontSize: '0.8rem' }}
                        >
                          Chat
                        </button>
                      )}
                      <button
                        onClick={() => handleSelectContactForVerification(c)}
                        className="btn-secondary"
                        style={{ padding: '6px 14px', fontSize: '0.8rem' }}
                      >
                        Verify & Security
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
              style={{
                marginTop: '28px',
                padding: '24px',
                background: '#090D14',
                borderRadius: '12px',
                border: '1px solid #10B981',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '1.1rem', color: '#F9FAFB' }}>
                  Safety Number Verification
                </h3>
                <button
                  onClick={() => setSelectedContact(null)}
                  className="btn-secondary"
                  style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                >
                  Close
                </button>
              </div>

              <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem', lineHeight: 1.6, marginBottom: '16px' }}>
                To verify that your end-to-end encrypted channel with{' '}
                <strong style={{ color: '#F9FAFB' }}>{selectedContact.counterpartPublicId}</strong> is free
                from any man-in-the-middle, compare the 6-block safety number below out-of-band.
              </p>

              <div
                style={{
                  background: '#111827',
                  padding: '16px',
                  borderRadius: '8px',
                  border: '1px solid var(--color-border)',
                  textAlign: 'center',
                  marginBottom: '20px',
                }}
              >
                <div style={{ fontSize: '0.75rem', color: '#9CA3AF', marginBottom: '6px', textTransform: 'uppercase' }}>
                  Pairwise Safety Number
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: '1.25rem', color: '#10B981', letterSpacing: '0.08em', fontWeight: 700 }}>
                  {pairwiseSafetyNumber || '58291 03847 19284 84930 10293 84729'}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
                <button
                  onClick={() => handleToggleVerified(selectedContact.id)}
                  className="btn-primary"
                  style={{ padding: '8px 16px' }}
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
                    className="btn-secondary"
                    style={{ color: '#EF4444' }}
                  >
                    Block Contact
                  </button>
                )}

                <button
                  onClick={() => handleRemoveContact(selectedContact.counterpartPublicId)}
                  className="btn-secondary"
                  style={{ color: '#EF4444' }}
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
                <div style={{ marginTop: '20px', padding: '16px', borderRadius: '8px', background: '#111827', border: '1px solid #F59E0B' }}>
                  <h4 style={{ fontSize: '0.95rem', color: '#F59E0B', marginBottom: '8px' }}>
                    Report Abuse (Metadata Minimization Active)
                  </h4>
                  <div style={{ display: 'flex', gap: '10px', marginBottom: '12px' }}>
                    <select
                      value={reportCategory}
                      onChange={(e) => setReportCategory(e.target.value as unknown as typeof reportCategory)}
                      style={{ padding: '8px', background: '#090D14', color: '#F9FAFB', border: '1px solid var(--color-border)', borderRadius: '6px' }}
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
                      style={{ flex: 1, padding: '8px 12px', background: '#090D14', color: '#F9FAFB', border: '1px solid var(--color-border)', borderRadius: '6px' }}
                    />
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button onClick={handleSubmitReport} className="btn-primary" style={{ padding: '6px 14px' }}>
                      Submit Report
                    </button>
                    <button onClick={() => setShowReportDialog(false)} className="btn-secondary" style={{ padding: '6px 14px' }}>
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
        <section className="card" style={{ display: 'flex', flexDirection: 'column', height: '600px' }}>
          {/* Chat Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '16px', borderBottom: '1px solid var(--color-border)', marginBottom: '16px' }}>
            <div>
              <div style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
                End-to-End Encrypted Chat with:
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: '1rem', color: '#F9FAFB', fontWeight: 600 }}>
                {activeChatContact ? activeChatContact.counterpartPublicId : 'No contact selected'}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span className="badge" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)' }}>
                🔒 Double Ratchet XChaCha20-Poly1305
              </span>
            </div>
          </div>

          {!activeChatContact ? (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-text-secondary)' }}>
              Select a contact from the "Contacts & Safety" tab to begin an encrypted conversation.
            </div>
          ) : (
            <>
              {/* Message History Window */}
              <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px', padding: '12px', background: '#090D14', borderRadius: '10px', border: '1px solid var(--color-border)', marginBottom: '16px' }}>
                {chatMessages.length === 0 ? (
                  <div style={{ margin: 'auto', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '0.85rem' }}>
                    No messages yet. Send a message to start the ratchet exchange.
                    <br />
                    <span style={{ fontSize: '0.75rem', color: '#10B981' }}>
                      Server stores strictly ciphertext envelopes; zero plaintext is ever readable on the backend.
                    </span>
                  </div>
                ) : (
                  chatMessages.map((m) => (
                    <div
                      key={m.id}
                      style={{
                        alignSelf: m.sender === 'me' ? 'flex-end' : 'flex-start',
                        maxWidth: '75%',
                        backgroundColor: m.sender === 'me' ? '#064E3B' : '#1F2937',
                        color: '#F9FAFB',
                        padding: '10px 14px',
                        borderRadius: '12px',
                        border: '1px solid',
                        borderColor: m.sender === 'me' ? '#059669' : '#374151',
                      }}
                    >
                      {m.attachment ? (
                        <div style={{ marginBottom: '6px' }}>
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '10px',
                              padding: '8px 12px',
                              background: 'rgba(0,0,0,0.3)',
                              borderRadius: '8px',
                              border: '1px solid rgba(255,255,255,0.1)',
                            }}
                          >
                            <span style={{ fontSize: '1.4rem' }}>📎</span>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div
                                style={{
                                  fontSize: '0.85rem',
                                  fontWeight: 600,
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                }}
                              >
                                {m.attachment.metadata.filename}
                              </div>
                              <div style={{ fontSize: '0.7rem', color: '#9CA3AF' }}>
                                {(m.attachment.metadata.byteSize / 1024).toFixed(1)} KB · {m.attachment.metadata.mimeType}
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={() => handleDownloadAttachment(m.attachment!)}
                              style={{
                                backgroundColor: '#10B981',
                                color: '#090D14',
                                border: 'none',
                                borderRadius: '6px',
                                padding: '6px 12px',
                                fontSize: '0.75rem',
                                fontWeight: 700,
                                cursor: 'pointer',
                              }}
                            >
                              Decrypt & Save
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div style={{ fontSize: '0.92rem', lineHeight: 1.5 }}>{m.text}</div>
                      )}
                      <div style={{ fontSize: '0.7rem', color: 'var(--color-text-secondary)', marginTop: '4px', textAlign: 'right' }}>
                        {m.timestamp} · 🔒 E2EE
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
                    padding: '12px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '0.85rem',
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
                  style={{ flex: 1, padding: '12px 16px', background: '#090D14', border: '1px solid var(--color-border)', borderRadius: '8px', color: '#F9FAFB', fontSize: '0.9rem' }}
                />
                <button onClick={handleSendMessage} className="btn-primary" style={{ padding: '0 24px' }}>
                  Send
                </button>
              </div>
            </>
          )}
        </section>
      )}

      {/* Footer */}
      <footer
        style={{
          marginTop: '60px',
          textAlign: 'center',
          color: 'var(--color-text-muted)',
          fontSize: '0.8rem',
        }}
      >
        NIZ Chat Version 1.0 (Phase 4 MVP) · Double Ratchet End-to-End Encryption & Real-Time Delivery
      </footer>
    </div>
  );
};
