import React, { useState } from 'react';
import type { AdminRole } from '@niz/shared-types';

export const App: React.FC = () => {
  const [selectedRole, setSelectedRole] = useState<AdminRole>('OPERATIONS_ADMIN');

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '40px 20px', width: '100%' }}>
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '32px',
          paddingBottom: '20px',
          borderBottom: '1px solid #232D3F',
        }}
      >
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#F9FAFB' }}>
            NIZ Administration & Operations
          </h1>
          <p style={{ color: '#9CA3AF', fontSize: '0.85rem' }}>
            Isolated administrative plane · Content browsing prohibited by design
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '9999px',
              fontSize: '0.75rem',
              fontWeight: 600,
              backgroundColor: '#1E293B',
              color: '#34D399',
              border: '1px solid #334155',
            }}
          >
            MFA Enforced
          </span>
        </div>
      </header>

      {/* Role selector to preview RBAC invariants */}
      <div style={{ marginBottom: '24px' }}>
        <label
          style={{
            display: 'block',
            fontSize: '0.85rem',
            color: '#9CA3AF',
            marginBottom: '8px',
          }}
        >
          Select Active Role Scope:
        </label>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {(
            [
              'OPERATIONS_ADMIN',
              'SUPER_ADMIN',
              'BILLING_ADMIN',
              'PRODUCT_ADMIN',
              'SECURITY_AUDITOR',
              'ANALYTICS_VIEWER',
            ] as AdminRole[]
          ).map((role) => (
            <button
              key={role}
              onClick={() => setSelectedRole(role)}
              style={{
                backgroundColor: selectedRole === role ? '#10B981' : '#1F2937',
                color: selectedRole === role ? '#090D14' : '#F9FAFB',
                padding: '8px 14px',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontWeight: 600,
                border: '1px solid #232D3F',
              }}
            >
              {role}
            </button>
          ))}
        </div>
      </div>

      {/* Metric Cards (Zero Plaintext Content) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '16px',
          marginBottom: '32px',
        }}
      >
        <div
          style={{
            background: '#111827',
            padding: '20px',
            borderRadius: '12px',
            border: '1px solid #232D3F',
          }}
        >
          <div style={{ color: '#9CA3AF', fontSize: '0.8rem' }}>System Status</div>
          <div style={{ color: '#10B981', fontSize: '1.4rem', fontWeight: 700, marginTop: '4px' }}>
            OPERATIONAL
          </div>
          <div style={{ color: '#6B7280', fontSize: '0.75rem', marginTop: '4px' }}>
            All storage adapters healthy
          </div>
        </div>

        <div
          style={{
            background: '#111827',
            padding: '20px',
            borderRadius: '12px',
            border: '1px solid #232D3F',
          }}
        >
          <div style={{ color: '#9CA3AF', fontSize: '0.8rem' }}>Queued Ciphertexts</div>
          <div style={{ color: '#F9FAFB', fontSize: '1.4rem', fontWeight: 700, marginTop: '4px' }}>
            0 Envelopes
          </div>
          <div style={{ color: '#6B7280', fontSize: '0.75rem', marginTop: '4px' }}>
            Store & forward TTL active (14d)
          </div>
        </div>

        <div
          style={{
            background: '#111827',
            padding: '20px',
            borderRadius: '12px',
            border: '1px solid #232D3F',
          }}
        >
          <div style={{ color: '#9CA3AF', fontSize: '0.8rem' }}>Registered Devices</div>
          <div style={{ color: '#F9FAFB', fontSize: '1.4rem', fontWeight: 700, marginTop: '4px' }}>
            Active
          </div>
          <div style={{ color: '#6B7280', fontSize: '0.75rem', marginTop: '4px' }}>
            Zero private keys retained
          </div>
        </div>
      </div>

      {/* Administrative Invariants Alert */}
      <div
        style={{
          background: '#111827',
          padding: '24px',
          borderRadius: '12px',
          border: '1px solid #232D3F',
        }}
      >
        <h2 style={{ fontSize: '1.1rem', color: '#F9FAFB', marginBottom: '8px' }}>
          RBAC Privacy Boundary Enforcement ({selectedRole})
        </h2>
        <p style={{ color: '#9CA3AF', fontSize: '0.85rem', lineHeight: 1.6, marginBottom: '16px' }}>
          Under Section 7 of the NIZ SRS, the administrative plane has no capability to read message
          bodies, browse conversation trees, or extract user cryptographic keys. Feature flags cannot
          disable encryption or contact approval invariants.
        </p>

        <div
          style={{
            padding: '12px 16px',
            borderRadius: '8px',
            backgroundColor: '#090D14',
            border: '1px solid #232D3F',
            color: '#10B981',
            fontSize: '0.8rem',
            fontFamily: 'monospace',
          }}
        >
          ✓ Content Browser: NOT IMPLEMENTED (Prohibited by Architecture)
          <br />
          ✓ Contact Graph Explorer: NOT IMPLEMENTED (Prohibited by Architecture)
          <br />✓ Private Key Extraction API: IMPOSSIBLE (Zero Keys on Server)
        </div>
      </div>
    </div>
  );
};
