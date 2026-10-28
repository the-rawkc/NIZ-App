import React, { useState } from 'react';
import { NizLogo } from './components/NizLogo';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'welcome' | 'identity' | 'security'>('welcome');

  return (
    <div style={{ maxWidth: '900px', margin: '0 auto', padding: '40px 20px', width: '100%' }}>
      {/* Header */}
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '40px',
          paddingBottom: '20px',
          borderBottom: '1px solid var(--color-border)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <NizLogo size={52} />
          <div>
            <h1 style={{ fontSize: '1.6rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
              NIZ Chat
            </h1>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem' }}>
              Privacy-first, QR-connected messaging
            </p>
          </div>
        </div>
        <div>
          <span className="badge">Phase 1 Foundation</span>
        </div>
      </header>

      {/* Navigation tabs */}
      <nav style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
        <button
          onClick={() => setActiveTab('welcome')}
          className={activeTab === 'welcome' ? 'btn-primary' : 'btn-secondary'}
        >
          Product Overview
        </button>
        <button
          onClick={() => setActiveTab('identity')}
          className={activeTab === 'identity' ? 'btn-primary' : 'btn-secondary'}
        >
          Identity Architecture
        </button>
        <button
          onClick={() => setActiveTab('security')}
          className={activeTab === 'security' ? 'btn-primary' : 'btn-secondary'}
        >
          Security Invariants
        </button>
      </nav>

      {/* Tab Panels */}
      {activeTab === 'welcome' && (
        <section className="card">
          <h2 style={{ fontSize: '1.3rem', marginBottom: '12px' }}>
            Zero-Knowledge, Quiet-by-Default Messaging
          </h2>
          <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
            NIZ Chat is built for true privacy without phone numbers, contact address-book harvesting,
            or surveillance algorithms. Connections are initiated via user-controlled QR codes and
            messages are encrypted end-to-end on the client device before touching the server.
          </p>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '16px',
            }}
          >
            <div
              style={{
                background: '#090d14',
                padding: '16px',
                borderRadius: '10px',
                border: '1px solid var(--color-border)',
              }}
            >
              <h3 style={{ color: 'var(--color-primary)', fontSize: '1rem', marginBottom: '6px' }}>
                No Phone Number Required
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
                Random cryptographic IDs replace SIM card identities and telco tracking.
              </p>
            </div>

            <div
              style={{
                background: '#090d14',
                padding: '16px',
                borderRadius: '10px',
                border: '1px solid var(--color-border)',
              }}
            >
              <h3 style={{ color: 'var(--color-primary)', fontSize: '1rem', marginBottom: '6px' }}>
                Content-Free Server
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
                The server stores ciphertext only. Private keys never leave your device.
              </p>
            </div>

            <div
              style={{
                background: '#090d14',
                padding: '16px',
                borderRadius: '10px',
                border: '1px solid var(--color-border)',
              }}
            >
              <h3 style={{ color: 'var(--color-primary)', fontSize: '1rem', marginBottom: '6px' }}>
                Recipient Approval Default
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
                Unknown accounts cannot send normal messages without mutual approval.
              </p>
            </div>
          </div>
        </section>
      )}

      {activeTab === 'identity' && (
        <section className="card">
          <h2 style={{ fontSize: '1.3rem', marginBottom: '12px' }}>
            Client-Side Identity Generation
          </h2>
          <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
            In Phase 2, identity keys and prekey bundles are generated securely in client memory.
            Permanent identity QRs encode only public identifiers—never bearer secrets or private keys.
          </p>
          <div
            style={{
              padding: '16px',
              borderRadius: '8px',
              backgroundColor: '#090d14',
              border: '1px solid var(--color-border)',
              fontFamily: 'monospace',
              fontSize: '0.85rem',
            }}
          >
            <div>Public ID: niz_id_7a2f91c0b39d48e1a5...</div>
            <div style={{ color: 'var(--color-primary)', marginTop: '6px' }}>
              Algorithm: Double Ratchet + X3DH / PQXDH Hybrid
            </div>
            <div style={{ color: 'var(--color-text-secondary)', marginTop: '4px' }}>
              Private Key Location: Secure Local Device Enclave Only
            </div>
          </div>
        </section>
      )}

      {activeTab === 'security' && (
        <section className="card">
          <h2 style={{ fontSize: '1.3rem', marginBottom: '12px' }}>
            Enforced Security Invariants
          </h2>
          <ul
            style={{
              listStyle: 'none',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
              color: 'var(--color-text-secondary)',
            }}
          >
            <li style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ color: 'var(--color-primary)' }}>✔</span>
              <span>Zero private keys accepted or stored on the server (negative tests pass).</span>
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ color: 'var(--color-primary)' }}>✔</span>
              <span>Ciphertext-only store and forward queue with finite retention and delivery purge.</span>
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ color: 'var(--color-primary)' }}>✔</span>
              <span>Server-enforced recipient approval: unauthorized messages return 403 Forbidden.</span>
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ color: 'var(--color-primary)' }}>✔</span>
              <span>Content-free structured logging redacts tokens, secrets, and bodies.</span>
            </li>
          </ul>
        </section>
      )}

      <footer
        style={{
          marginTop: '60px',
          textAlign: 'center',
          color: 'var(--color-text-muted)',
          fontSize: '0.8rem',
        }}
      >
        NIZ Chat Version 1.0 (Phase 1 Baseline) · Designed with privacy as a foundational constraint
      </footer>
    </div>
  );
};
