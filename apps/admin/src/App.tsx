import React, { useState, useEffect } from 'react';
import type { AdminRole, FeatureFlag, AdminAuditEvent } from '@niz/shared-types';

const ADMIN_API_BASE = 'http://localhost:4000';

export const App: React.FC = () => {
  const [token, setToken] = useState<string | null>(null);
  const [currentUsername, setCurrentUsername] = useState<string>('');
  const [currentRoles, setCurrentRoles] = useState<AdminRole[]>([]);
  const [activeTab, setActiveTab] = useState<'metrics' | 'flags' | 'audit'>('metrics');

  // Login form state
  const [loginUser, setLoginUser] = useState<string>('superadmin');
  const [loginPass, setLoginPass] = useState<string>('dev_admin_super_secret_123');
  const [loginMfa, setLoginMfa] = useState<string>('123456');
  const [loginError, setLoginError] = useState<string | null>(null);

  // Admin Data state
  const [metrics, setMetrics] = useState<{
    status: string;
    uptimeSeconds: number;
    queuedCiphertextsTotal: number;
    registeredAccountsEstimate: number;
    errorRateLastHour: number;
    retentionPolicy: string;
  } | null>(null);
  const [featureFlags, setFeatureFlags] = useState<FeatureFlag[]>([]);
  const [auditLogs, setAuditLogs] = useState<AdminAuditEvent[]>([]);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const showNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 4000);
  };

  // Perform Admin Login with mandatory MFA
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);

    try {
      const res = await fetch(`${ADMIN_API_BASE}/v1/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginUser,
          password: loginPass,
          mfaCode: loginMfa,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || data.error || 'Authentication failed');
      }

      setToken(data.token);
      setCurrentUsername(data.username);
      setCurrentRoles(data.roles);
      showNotice(`Logged in as ${data.username} (${data.roles.join(', ')})`);
    } catch (err: unknown) {
      setLoginError(err instanceof Error ? err.message : 'Login failed');
    }
  };

  const handleLogout = () => {
    setToken(null);
    setCurrentUsername('');
    setCurrentRoles([]);
    setMetrics(null);
    setFeatureFlags([]);
    setAuditLogs([]);
  };

  // Fetch Aggregate Metrics (Zero Message Content)
  const fetchMetrics = async () => {
    if (!token) return;
    try {
      const res = await fetch(`${ADMIN_API_BASE}/v1/admin/metrics`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch {
      // ignore
    }
  };

  // Fetch Feature Flags
  const fetchFeatureFlags = async () => {
    if (!token) return;
    try {
      const res = await fetch(`${ADMIN_API_BASE}/v1/admin/feature-flags`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setFeatureFlags(data.flags || []);
      }
    } catch {
      // ignore
    }
  };

  // Toggle Feature Flag with Invariant Protection
  const handleToggleFlag = async (flag: FeatureFlag) => {
    if (!token) return;

    if (flag.isSecurityInvariant && flag.enabled) {
      showNotice(`⚠️ SECURITY INVARIANT: "${flag.key}" cannot be disabled.`);
      return;
    }

    try {
      const res = await fetch(`${ADMIN_API_BASE}/v1/admin/feature-flags`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          key: flag.key,
          enabled: !flag.enabled,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Update failed');
      }

      showNotice(`Flag "${flag.key}" updated`);
      fetchFeatureFlags();
    } catch (err: unknown) {
      showNotice(err instanceof Error ? err.message : 'Update rejected');
    }
  };

  // Fetch Audit Logs
  const fetchAuditLogs = async () => {
    if (!token) return;
    try {
      const res = await fetch(`${ADMIN_API_BASE}/v1/admin/audit-logs`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data.auditLogs || []);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    if (token) {
      if (activeTab === 'metrics') fetchMetrics();
      else if (activeTab === 'flags') fetchFeatureFlags();
      else if (activeTab === 'audit') fetchAuditLogs();
    }
  }, [token, activeTab]);

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '40px 20px', width: '100%' }}>
      {/* Notice Banner */}
      {actionNotice && (
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
          {actionNotice}
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
          borderBottom: '1px solid #232D3F',
        }}
      >
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#F9FAFB' }}>
            NIZ Administration & Operations
          </h1>
          <p style={{ color: '#9CA3AF', fontSize: '0.85rem' }}>
            Isolated administrative plane · Content browsing prohibited by architecture
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
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
          {token && (
            <button
              onClick={handleLogout}
              style={{
                backgroundColor: '#1F2937',
                color: '#F9FAFB',
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '0.8rem',
                border: '1px solid #232D3F',
              }}
            >
              Sign Out ({currentUsername}{currentRoles.length > 0 ? ` · ${currentRoles.join(', ')}` : ''})
            </button>
          )}
        </div>
      </header>

      {!token ? (
        /* Login Screen with Mandatory MFA */
        <div
          style={{
            maxWidth: '440px',
            margin: '40px auto',
            background: '#111827',
            padding: '32px',
            borderRadius: '14px',
            border: '1px solid #232D3F',
          }}
        >
          <h2 style={{ fontSize: '1.2rem', marginBottom: '8px', color: '#F9FAFB' }}>
            Administrative MFA Authentication
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#9CA3AF', marginBottom: '24px', lineHeight: 1.5 }}>
            Access to administrative endpoints requires an isolated identity provider account and an out-of-band 6-digit MFA verification code.
          </p>

          {loginError && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                backgroundColor: '#7F1D1D',
                color: '#FCA5A5',
                fontSize: '0.82rem',
                marginBottom: '16px',
              }}
            >
              {loginError}
            </div>
          )}

          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: '#9CA3AF', marginBottom: '4px' }}>
                Admin Account
              </label>
              <select
                value={loginUser}
                onChange={(e) => {
                  const u = e.target.value;
                  setLoginUser(u);
                  setLoginPass(
                    u === 'superadmin'
                      ? 'dev_admin_super_secret_123'
                      : u === 'opsadmin'
                      ? 'dev_admin_ops_secret_123'
                      : u === 'productadmin'
                      ? 'dev_admin_product_secret_123'
                      : 'dev_admin_auditor_secret_123'
                  );
                }}
                style={{ width: '100%', padding: '10px', background: '#090D14', border: '1px solid #232D3F', borderRadius: '8px', color: '#F9FAFB' }}
              >
                <option value="superadmin">superadmin (Super Admin — All Privileges)</option>
                <option value="opsadmin">opsadmin (Operations Admin)</option>
                <option value="productadmin">productadmin (Product Admin)</option>
                <option value="auditor">auditor (Security Auditor)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: '#9CA3AF', marginBottom: '4px' }}>
                Password
              </label>
              <input
                type="password"
                value={loginPass}
                onChange={(e) => setLoginPass(e.target.value)}
                style={{ width: '100%', padding: '10px', background: '#090D14', border: '1px solid #232D3F', borderRadius: '8px', color: '#F9FAFB' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: '#9CA3AF', marginBottom: '4px' }}>
                6-Digit MFA Token (TOTP)
              </label>
              <input
                type="text"
                maxLength={6}
                value={loginMfa}
                onChange={(e) => setLoginMfa(e.target.value)}
                placeholder="123456"
                style={{ width: '100%', padding: '10px', background: '#090D14', border: '1px solid #232D3F', borderRadius: '8px', color: '#10B981', fontFamily: 'monospace', letterSpacing: '0.2em', fontSize: '1.1rem', textAlign: 'center' }}
              />
            </div>

            <button
              type="submit"
              style={{
                backgroundColor: '#10B981',
                color: '#090D14',
                padding: '12px',
                borderRadius: '8px',
                fontWeight: 600,
                marginTop: '8px',
              }}
            >
              Verify MFA & Authenticate
            </button>
          </form>
        </div>
      ) : (
        /* Authenticated Admin Dashboard */
        <div>
          {/* Admin Navigation */}
          <div style={{ display: 'flex', gap: '10px', marginBottom: '24px' }}>
            <button
              onClick={() => setActiveTab('metrics')}
              style={{
                backgroundColor: activeTab === 'metrics' ? '#10B981' : '#1F2937',
                color: activeTab === 'metrics' ? '#090D14' : '#F9FAFB',
                padding: '8px 16px',
                borderRadius: '8px',
                fontWeight: 600,
              }}
            >
              Operational Metrics
            </button>
            <button
              onClick={() => setActiveTab('flags')}
              style={{
                backgroundColor: activeTab === 'flags' ? '#10B981' : '#1F2937',
                color: activeTab === 'flags' ? '#090D14' : '#F9FAFB',
                padding: '8px 16px',
                borderRadius: '8px',
                fontWeight: 600,
              }}
            >
              Feature Flags & Invariants
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              style={{
                backgroundColor: activeTab === 'audit' ? '#10B981' : '#1F2937',
                color: activeTab === 'audit' ? '#090D14' : '#F9FAFB',
                padding: '8px 16px',
                borderRadius: '8px',
                fontWeight: 600,
              }}
            >
              Security Audit Logs
            </button>
          </div>

          {/* Tab 1: Operational Telemetry */}
          {activeTab === 'metrics' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '28px' }}>
              <div style={{ background: '#111827', padding: '20px', borderRadius: '12px', border: '1px solid #232D3F' }}>
                <div style={{ color: '#9CA3AF', fontSize: '0.8rem' }}>System Status</div>
                <div style={{ color: '#10B981', fontSize: '1.4rem', fontWeight: 700, marginTop: '4px' }}>
                  {metrics?.status.toUpperCase() || 'OPERATIONAL'}
                </div>
                <div style={{ color: '#6B7280', fontSize: '0.75rem', marginTop: '4px' }}>
                  Uptime: {metrics ? `${metrics.uptimeSeconds}s` : 'Healthy'}
                </div>
              </div>

              <div style={{ background: '#111827', padding: '20px', borderRadius: '12px', border: '1px solid #232D3F' }}>
                <div style={{ color: '#9CA3AF', fontSize: '0.8rem' }}>Queued Ciphertexts</div>
                <div style={{ color: '#F9FAFB', fontSize: '1.4rem', fontWeight: 700, marginTop: '4px' }}>
                  {metrics ? `${metrics.queuedCiphertextsTotal} Envelopes` : '0 Envelopes'}
                </div>
                <div style={{ color: '#6B7280', fontSize: '0.75rem', marginTop: '4px' }}>
                  Purged immediately upon delivery ACK
                </div>
              </div>

              <div style={{ background: '#111827', padding: '20px', borderRadius: '12px', border: '1px solid #232D3F' }}>
                <div style={{ color: '#9CA3AF', fontSize: '0.8rem' }}>Registered Accounts</div>
                <div style={{ color: '#F9FAFB', fontSize: '1.4rem', fontWeight: 700, marginTop: '4px' }}>
                  {metrics ? metrics.registeredAccountsEstimate : 10}
                </div>
                <div style={{ color: '#6B7280', fontSize: '0.75rem', marginTop: '4px' }}>
                  Zero private keys retained
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Feature Flags & Security Invariant Locking */}
          {activeTab === 'flags' && (
            <div style={{ background: '#111827', padding: '24px', borderRadius: '12px', border: '1px solid #232D3F', marginBottom: '28px' }}>
              <h3 style={{ fontSize: '1.1rem', color: '#F9FAFB', marginBottom: '8px' }}>
                Feature Flags & Security Invariants
              </h3>
              <p style={{ color: '#9CA3AF', fontSize: '0.85rem', marginBottom: '20px' }}>
                Flags marked with 🔒 are core security invariants and cannot be disabled under Section 7 of the NIZ SRS.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {featureFlags.map((flag) => (
                  <div
                    key={flag.key}
                    style={{
                      background: '#090D14',
                      padding: '16px',
                      borderRadius: '8px',
                      border: '1px solid #232D3F',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontFamily: 'monospace', fontWeight: 600, color: '#F9FAFB' }}>
                          {flag.key}
                        </span>
                        {flag.isSecurityInvariant ? (
                          <span style={{ fontSize: '0.75rem', color: '#10B981', fontWeight: 600, backgroundColor: 'rgba(16,185,129,0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                            🔒 Security Invariant (Locked)
                          </span>
                        ) : (
                          <span style={{ fontSize: '0.75rem', color: '#9CA3AF', backgroundColor: '#1F2937', padding: '2px 8px', borderRadius: '4px' }}>
                            Experimental Flag
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.8rem', color: '#9CA3AF', marginTop: '4px' }}>
                        {flag.description} · Rollout: {flag.rolloutPercentage}%
                      </div>
                    </div>

                    <button
                      onClick={() => handleToggleFlag(flag)}
                      disabled={flag.isSecurityInvariant}
                      style={{
                        backgroundColor: flag.enabled ? (flag.isSecurityInvariant ? '#064E3B' : '#10B981') : '#374151',
                        color: flag.enabled ? (flag.isSecurityInvariant ? '#34D399' : '#090D14') : '#9CA3AF',
                        padding: '6px 14px',
                        borderRadius: '6px',
                        fontWeight: 600,
                        fontSize: '0.8rem',
                        cursor: flag.isSecurityInvariant ? 'not-allowed' : 'pointer',
                      }}
                    >
                      {flag.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 3: Tamper-Evident Audit Logs */}
          {activeTab === 'audit' && (
            <div style={{ background: '#111827', padding: '24px', borderRadius: '12px', border: '1px solid #232D3F', marginBottom: '28px' }}>
              <h3 style={{ fontSize: '1.1rem', color: '#F9FAFB', marginBottom: '8px' }}>
                Immutable Administrative Audit Trail
              </h3>
              <p style={{ color: '#9CA3AF', fontSize: '0.85rem', marginBottom: '16px' }}>
                All administrative actions are permanently recorded with timestamps, actor IDs, and role grants.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {auditLogs.length === 0 ? (
                  <div style={{ color: '#6B7280', fontSize: '0.85rem' }}>No audit events recorded in this session.</div>
                ) : (
                  auditLogs.map((log) => (
                    <div
                      key={log.eventId}
                      style={{
                        background: '#090D14',
                        padding: '12px 16px',
                        borderRadius: '6px',
                        border: '1px solid #232D3F',
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                        display: 'flex',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div>
                        <span style={{ color: '#10B981' }}>[{log.action}]</span>{' '}
                        <span style={{ color: '#F9FAFB' }}>{log.adminId}</span> ({log.role}) →{' '}
                        <span style={{ color: '#9CA3AF' }}>{log.targetResource}</span>
                      </div>
                      <div style={{ color: '#6B7280' }}>
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
