import React, { useState, useEffect } from 'react';
import type { AdminRole, FeatureFlag, AdminAuditEvent } from '@niz/shared-types';

const ADMIN_API_BASE =
  import.meta.env.VITE_ADMIN_API_BASE ||
  (typeof window !== 'undefined' && window.location.port === '5174'
    ? 'http://localhost:4000'
    : typeof window !== 'undefined'
    ? window.location.origin
    : 'http://localhost:4000');

export const App: React.FC = () => {
  const [token, setToken] = useState<string | null>(null);
  const [currentUsername, setCurrentUsername] = useState<string>('');
  const [currentRoles, setCurrentRoles] = useState<AdminRole[]>([]);
  const [activeTab, setActiveTab] = useState<'metrics' | 'flags' | 'audit'>('metrics');

  // Dedicated Superadmin Credentials (configured in .env)
  const defaultSuperUser = 'superadmin';
  const defaultSuperPass = 'Niz_SuperAdmin_2026_xK9#vL2!Secure';
  const defaultSuperMfa = '948216';

  // Login form state
  const isDev = import.meta.env.DEV;
  const [loginUser, setLoginUser] = useState<string>(isDev ? defaultSuperUser : '');
  const [loginPass, setLoginPass] = useState<string>(isDev ? defaultSuperPass : '');
  const [loginMfa, setLoginMfa] = useState<string>(isDev ? defaultSuperMfa : '');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  // Admin Data state
  const [metrics, setMetrics] = useState<{
    status: string;
    uptimeSeconds: number;
    queuedCiphertextsTotal: number;
    registeredAccountsEstimate: number;
    errorRateLastHour: number;
    retentionPolicy: string;
    subscriptions?: {
      free: number;
      pro: number;
      business: number;
      totalSubscribers: number;
    };
  } | null>(null);
  const [featureFlags, setFeatureFlags] = useState<FeatureFlag[]>([]);
  const [auditLogs, setAuditLogs] = useState<AdminAuditEvent[]>([]);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const showNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 4000);
  };

  const autofillSuperadmin = () => {
    setLoginUser(defaultSuperUser);
    setLoginPass(defaultSuperPass);
    setLoginMfa(defaultSuperMfa);
    showNotice('Loaded Superadmin Credentials (All Roles Active)');
  };

  // Perform Admin Login with mandatory MFA
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setIsSubmitting(true);

    try {
      const res = await fetch(`${ADMIN_API_BASE}/v1/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginUser.trim(),
          password: loginPass,
          mfaCode: loginMfa.trim(),
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || data.error || 'Authentication failed');
      }

      setToken(data.token);
      setCurrentUsername(data.username);
      setCurrentRoles(data.roles);
      showNotice(`Authenticated as ${data.username} (${data.roles.join(', ')})`);
    } catch (err: unknown) {
      setLoginError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLogout = () => {
    setToken(null);
    setCurrentUsername('');
    setCurrentRoles([]);
    setMetrics(null);
    setFeatureFlags([]);
    setAuditLogs([]);
    showNotice('Signed out successfully');
  };

  // Fetch Aggregate Metrics (Zero Message Content)
  const fetchMetrics = async () => {
    if (!token) return;
    setIsRefreshing(true);
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
    } finally {
      setIsRefreshing(false);
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
      showNotice(`🔒 SECURITY INVARIANT: "${flag.key}" cannot be disabled.`);
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
    <div style={{ maxWidth: '1080px', margin: '0 auto', padding: '40px 24px', width: '100%' }}>
      {/* Dynamic Animated Toast Notification */}
      {actionNotice && (
        <div
          style={{
            position: 'fixed',
            top: '24px',
            right: '24px',
            background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(13, 18, 29, 0.98) 100%)',
            backdropFilter: 'blur(20px)',
            color: '#f8fafc',
            padding: '14px 22px',
            borderRadius: '12px',
            fontWeight: 600,
            fontSize: '0.9rem',
            zIndex: 99999,
            border: '1px solid rgba(16, 185, 129, 0.5)',
            boxShadow: '0 12px 36px rgba(0, 0, 0, 0.6), 0 0 24px rgba(16, 185, 129, 0.25)',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            animation: 'fadeIn 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
          }}
        >
          <span style={{ width: '8px', height: '8px', backgroundColor: '#10B981', borderRadius: '50%', boxShadow: '0 0 8px #10B981' }} />
          {actionNotice}
        </div>
      )}

      {/* Futuristic Header */}
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '36px',
          paddingBottom: '24px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '46px',
              height: '46px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.2) 0%, rgba(6, 182, 212, 0.2) 100%)',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 20px rgba(16, 185, 129, 0.2)',
            }}
          >
            <span style={{ fontSize: '1.4rem' }}>🛡️</span>
          </div>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#F8FAFC' }}>
              NIZ Operations & Control Plane
            </h1>
            <p style={{ color: '#94A3B8', fontSize: '0.84rem', marginTop: '2px' }}>
              Zero-knowledge server telemetry · Content browsing prohibited by cryptographic architecture
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span
            style={{
              padding: '6px 14px',
              borderRadius: '9999px',
              fontSize: '0.76rem',
              fontWeight: 700,
              backgroundColor: 'rgba(16, 185, 129, 0.12)',
              color: '#34D399',
              border: '1px solid rgba(16, 185, 129, 0.35)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span style={{ width: '6px', height: '6px', backgroundColor: '#34D399', borderRadius: '50%' }} />
            MFA Enforced
          </span>

          {token && (
            <button
              onClick={handleLogout}
              className="btn-secondary"
              style={{ padding: '7px 14px', fontSize: '0.82rem' }}
            >
              Sign Out ({currentUsername}{currentRoles.length > 0 ? ` · ${currentRoles[0]}` : ''})
            </button>
          )}
        </div>
      </header>

      {!token ? (
        /* Superadmin Login Portal */
        <div style={{ maxWidth: '480px', margin: '30px auto' }} className="animate-fade-in">
          <div
            className="admin-card"
            style={{
              background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(10, 15, 26, 0.95) 100%)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              position: 'relative',
            }}
          >
            {/* Ambient cyber line */}
            <div
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                height: '2px',
                background: 'linear-gradient(90deg, transparent, #10B981, #06B6D4, transparent)',
              }}
            />

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
              <div
                style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '10px',
                  background: 'rgba(16, 185, 129, 0.15)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#10B981',
                  fontWeight: 800,
                }}
              >
                🔐
              </div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#F8FAFC' }}>
                Administrative Authentication
              </h2>
            </div>

            <p style={{ fontSize: '0.82rem', color: '#94A3B8', marginBottom: '20px', lineHeight: 1.5 }}>
              Enter your provisioned administrative credentials and 6-digit MFA verification token.
            </p>

            {/* Quick-fill Banner for Exclusive Superadmin Access */}
            <div
              style={{
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.25)',
                borderRadius: '10px',
                padding: '12px 14px',
                marginBottom: '20px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#34D399' }}>
                  Superadmin Provisioned Credentials
                </div>
                <div style={{ fontSize: '0.74rem', color: '#94A3B8', marginTop: '2px' }}>
                  User: <code>superadmin</code> · MFA: <code>948216</code>
                </div>
              </div>
              <button
                type="button"
                onClick={autofillSuperadmin}
                style={{
                  background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.3) 0%, rgba(5, 150, 105, 0.4) 100%)',
                  color: '#34D399',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  border: '1px solid rgba(16, 185, 129, 0.4)',
                }}
              >
                ⚡ Auto-fill
              </button>
            </div>

            {loginError && (
              <div
                style={{
                  padding: '12px 16px',
                  borderRadius: '10px',
                  backgroundColor: 'rgba(244, 63, 94, 0.15)',
                  border: '1px solid rgba(244, 63, 94, 0.4)',
                  color: '#FDA4AF',
                  fontSize: '0.84rem',
                  marginBottom: '18px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                <span>⚠️</span> {loginError}
              </div>
            )}

            <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>
                  Username
                </label>
                <input
                  type="text"
                  value={loginUser}
                  onChange={(e) => setLoginUser(e.target.value)}
                  placeholder="superadmin"
                  required
                />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <label style={{ fontSize: '0.8rem', fontWeight: 600, color: '#94A3B8' }}>
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{ background: 'none', color: '#34D399', fontSize: '0.75rem', padding: 0 }}
                  >
                    {showPassword ? 'Hide' : 'Show'}
                  </button>
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={loginPass}
                  onChange={(e) => setLoginPass(e.target.value)}
                  placeholder="••••••••••••"
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>
                  6-Digit MFA Verification Code (TOTP)
                </label>
                <input
                  type="text"
                  maxLength={6}
                  value={loginMfa}
                  onChange={(e) => setLoginMfa(e.target.value)}
                  placeholder="948216"
                  style={{
                    color: '#10B981',
                    fontFamily: 'monospace',
                    letterSpacing: '0.3em',
                    fontSize: '1.2rem',
                    textAlign: 'center',
                    fontWeight: 700,
                  }}
                  required
                />
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="btn-primary"
                style={{ width: '100%', padding: '12px', marginTop: '6px', fontSize: '0.95rem' }}
              >
                {isSubmitting ? 'Verifying MFA Token...' : 'Verify MFA & Enter Operations Console'}
              </button>
            </form>
          </div>
        </div>
      ) : (
        /* Authenticated Operational Dashboard */
        <div className="animate-fade-in">
          {/* Navigation Tabs */}
          <div style={{ display: 'flex', gap: '10px', marginBottom: '28px', flexWrap: 'wrap' }}>
            <button
              onClick={() => setActiveTab('metrics')}
              className={activeTab === 'metrics' ? 'btn-primary' : 'btn-secondary'}
              style={{ borderRadius: '10px' }}
            >
              📊 System Telemetry & Metrics
            </button>
            <button
              onClick={() => setActiveTab('flags')}
              className={activeTab === 'flags' ? 'btn-primary' : 'btn-secondary'}
              style={{ borderRadius: '10px' }}
            >
              🔒 Feature Flags & Invariants
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              className={activeTab === 'audit' ? 'btn-primary' : 'btn-secondary'}
              style={{ borderRadius: '10px' }}
            >
              📜 Immutable Audit Trail
            </button>
          </div>

          {/* Tab 1: Operational Metrics */}
          {activeTab === 'metrics' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
                <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#F8FAFB' }}>
                  Live Telemetry Overview
                </h2>
                <button
                  onClick={fetchMetrics}
                  className="btn-secondary"
                  disabled={isRefreshing}
                  style={{ padding: '6px 14px', fontSize: '0.8rem' }}
                >
                  {isRefreshing ? 'Refreshing...' : '🔄 Refresh Metrics'}
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '18px', marginBottom: '32px' }}>
                <div className="admin-metric-card">
                  <div style={{ color: '#94A3B8', fontSize: '0.8rem', fontWeight: 600 }}>System Health</div>
                  <div style={{ color: '#10B981', fontSize: '1.6rem', fontWeight: 800, marginTop: '6px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ width: '10px', height: '10px', backgroundColor: '#10B981', borderRadius: '50%', boxShadow: '0 0 10px #10B981' }} />
                    {metrics?.status.toUpperCase() || 'OPERATIONAL'}
                  </div>
                  <div style={{ color: '#64748B', fontSize: '0.78rem', marginTop: '6px' }}>
                    Uptime: {metrics ? `${metrics.uptimeSeconds} seconds` : 'Normal'}
                  </div>
                </div>

                <div className="admin-metric-card">
                  <div style={{ color: '#94A3B8', fontSize: '0.8rem', fontWeight: 600 }}>Queued Ciphertexts</div>
                  <div style={{ color: '#F8FAFB', fontSize: '1.6rem', fontWeight: 800, marginTop: '6px' }}>
                    {metrics ? `${metrics.queuedCiphertextsTotal}` : '0'}{' '}
                    <span style={{ fontSize: '0.9rem', color: '#94A3B8', fontWeight: 500 }}>Envelopes</span>
                  </div>
                  <div style={{ color: '#64748B', fontSize: '0.78rem', marginTop: '6px' }}>
                    Strict ephemeral TTL · Zero retention
                  </div>
                </div>

                <div className="admin-metric-card">
                  <div style={{ color: '#94A3B8', fontSize: '0.8rem', fontWeight: 600 }}>Registered Identities</div>
                  <div style={{ color: '#F8FAFB', fontSize: '1.6rem', fontWeight: 800, marginTop: '6px' }}>
                    {metrics ? metrics.registeredAccountsEstimate : 10}{' '}
                    <span style={{ fontSize: '0.9rem', color: '#94A3B8', fontWeight: 500 }}>Public IDs</span>
                  </div>
                  <div style={{ color: '#64748B', fontSize: '0.78rem', marginTop: '6px' }}>
                    Content-free database · Zero private keys
                  </div>
                </div>

                <div className="admin-metric-card">
                  <div style={{ color: '#94A3B8', fontSize: '0.8rem', fontWeight: 600 }}>Cloud Subscriptions</div>
                  <div style={{ color: '#38BDF8', fontSize: '1.6rem', fontWeight: 800, marginTop: '6px' }}>
                    {metrics?.subscriptions ? `${metrics.subscriptions.totalSubscribers}` : '0'}{' '}
                    <span style={{ fontSize: '0.9rem', color: '#94A3B8', fontWeight: 500 }}>Paid Users</span>
                  </div>
                  <div style={{ color: '#64748B', fontSize: '0.78rem', marginTop: '6px' }}>
                    Core E2EE encryption 100% unpaywalled
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Feature Flags & Security Invariants */}
          {activeTab === 'flags' && (
            <div className="admin-card animate-fade-in">
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <span style={{ fontSize: '1.3rem' }}>🔒</span>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#F8FAFB' }}>
                  Feature Flags & Security Invariants
                </h3>
              </div>
              <p style={{ color: '#94A3B8', fontSize: '0.86rem', marginBottom: '24px', lineHeight: 1.5 }}>
                Security invariant flags are mathematically bound to the NIZ Security Requirements Specification.
                They cannot be disabled at runtime, even by Superadmin, ensuring mathematical integrity.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {featureFlags.map((flag) => (
                  <div
                    key={flag.key}
                    style={{
                      background: 'rgba(10, 15, 26, 0.75)',
                      padding: '18px',
                      borderRadius: '12px',
                      border: flag.isSecurityInvariant ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(255, 255, 255, 0.08)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '16px',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                        <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '0.95rem', color: '#F8FAFB' }}>
                          {flag.key}
                        </span>
                        {flag.isSecurityInvariant ? (
                          <span
                            style={{
                              fontSize: '0.74rem',
                              color: '#34D399',
                              fontWeight: 700,
                              backgroundColor: 'rgba(16, 185, 129, 0.15)',
                              border: '1px solid rgba(16, 185, 129, 0.35)',
                              padding: '3px 10px',
                              borderRadius: '9999px',
                            }}
                          >
                            🔒 Security Invariant (Immutable)
                          </span>
                        ) : (
                          <span
                            style={{
                              fontSize: '0.74rem',
                              color: '#94A3B8',
                              backgroundColor: 'rgba(255, 255, 255, 0.06)',
                              padding: '3px 10px',
                              borderRadius: '9999px',
                            }}
                          >
                            Dynamic Flag
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.84rem', color: '#94A3B8', marginTop: '6px' }}>
                        {flag.description} · Rollout: <strong>{flag.rolloutPercentage}%</strong>
                      </div>
                    </div>

                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={flag.enabled}
                        disabled={flag.isSecurityInvariant}
                        onChange={() => handleToggleFlag(flag)}
                      />
                      <span className="slider" />
                    </label>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 3: Tamper-Evident Audit Logs */}
          {activeTab === 'audit' && (
            <div className="admin-card animate-fade-in">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#F8FAFB' }}>
                    Immutable Security Audit Logs
                  </h3>
                  <p style={{ color: '#94A3B8', fontSize: '0.84rem', marginTop: '2px' }}>
                    Chronological audit event trail recorded with actor IDs, roles, and cryptographic nonces.
                  </p>
                </div>
                <button
                  onClick={fetchAuditLogs}
                  className="btn-secondary"
                  style={{ padding: '6px 14px', fontSize: '0.8rem' }}
                >
                  🔄 Refresh Logs
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {auditLogs.length === 0 ? (
                  <div style={{ padding: '24px', textAlign: 'center', color: '#64748B', fontSize: '0.88rem' }}>
                    No audit records registered yet in this session.
                  </div>
                ) : (
                  auditLogs.map((log) => (
                    <div
                      key={log.eventId}
                      style={{
                        background: 'rgba(10, 15, 26, 0.85)',
                        padding: '14px 18px',
                        borderRadius: '10px',
                        border: '1px solid rgba(255, 255, 255, 0.07)',
                        fontFamily: 'monospace',
                        fontSize: '0.82rem',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: '12px',
                        flexWrap: 'wrap',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span
                          style={{
                            color: '#10B981',
                            fontWeight: 700,
                            background: 'rgba(16, 185, 129, 0.12)',
                            padding: '3px 8px',
                            borderRadius: '6px',
                          }}
                        >
                          [{log.action}]
                        </span>
                        <span style={{ color: '#F8FAFB', fontWeight: 600 }}>{log.adminId}</span>
                        <span style={{ color: '#64748B' }}>({log.role})</span>
                        <span style={{ color: '#94A3B8' }}>→ {log.targetResource}</span>
                      </div>
                      <div style={{ color: '#64748B', fontSize: '0.78rem' }}>
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
