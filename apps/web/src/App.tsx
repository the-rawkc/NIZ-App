import React, { useState, useEffect } from 'react';
import QRCode from 'qrcode';
import {
  createClientIdentity,
  generatePermanentIdentityQrPayload,
  generateEphemeralInvitationQrPayload,
  parseNizQrPayload,
  type ClientIdentityBundle,
  type NizParsedQr,
} from '@niz/crypto-core';
import { NizLogo } from './components/NizLogo';

const API_BASE = 'http://localhost:4000';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'identity' | 'invite' | 'connect' | 'requests'>('identity');
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
      }
    } catch {
      showNotification('Failed to process decision');
    }
  };

  useEffect(() => {
    if (activeTab === 'requests') {
      fetchPendingRequests();
    }
  }, [activeTab]);

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
          <span className="badge">Phase 2: Identity & QR</span>
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
                    Safety Fingerprint
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

      {/* Tab 4: Incoming Requests & Approval State Machine */}
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

      {/* Footer */}
      <footer
        style={{
          marginTop: '60px',
          textAlign: 'center',
          color: 'var(--color-text-muted)',
          fontSize: '0.8rem',
        }}
      >
        NIZ Chat Version 1.0 (Phase 2 Active) · Libsodium X25519/Ed25519 Client Key Generation
      </footer>
    </div>
  );
};
