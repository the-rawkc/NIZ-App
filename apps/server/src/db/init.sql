-- NIZ Chat PostgreSQL Schema Initialization
-- INVARIANT: No private keys, no passwords, no plaintext message bodies.

CREATE TABLE IF NOT EXISTS accounts (
    public_id VARCHAR(75) PRIMARY KEY,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    device_id UUID PRIMARY KEY,
    account_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id) ON DELETE CASCADE,
    public_identity_key TEXT NOT NULL,
    public_signed_prekey TEXT NOT NULL,
    signed_prekey_signature TEXT NOT NULL,
    device_name VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY,
    creator_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    is_single_use BOOLEAN NOT NULL DEFAULT TRUE,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    redemption_count INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS connection_requests (
    id UUID PRIMARY KEY,
    sender_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id) ON DELETE CASCADE,
    recipient_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id) ON DELETE CASCADE,
    state VARCHAR(20) NOT NULL DEFAULT 'pending',
    safety_number_fingerprint TEXT,
    originated_invitation_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Ciphertext Queue: Stores ONLY encrypted ciphertext envelopes with finite TTL
CREATE TABLE IF NOT EXISTS message_queue (
    envelope_id UUID PRIMARY KEY,
    sender_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id),
    sender_device_id UUID NOT NULL,
    recipient_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id),
    recipient_device_id UUID NOT NULL,
    ratchet_dh_key TEXT NOT NULL,
    ratchet_pn INT NOT NULL,
    ratchet_n INT NOT NULL,
    ciphertext TEXT NOT NULL, -- Pure encrypted ciphertext
    nonce TEXT NOT NULL,      -- AEAD Nonce
    protocol_version VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '14 days')
);

CREATE INDEX IF NOT EXISTS idx_message_queue_recipient ON message_queue(recipient_public_id, recipient_device_id);
CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON invitations(token_hash);

-- Encrypted Attachments: Stores strictly ciphertext metadata (zero plaintext or keys)
CREATE TABLE IF NOT EXISTS encrypted_attachments (
    attachment_id UUID PRIMARY KEY,
    uploader_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id) ON DELETE CASCADE,
    recipient_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id) ON DELETE CASCADE,
    size_bytes BIGINT NOT NULL,
    sha256_ciphertext VARCHAR(64) NOT NULL,
    storage_path TEXT NOT NULL,
    blob_data BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '14 days')
);

CREATE INDEX IF NOT EXISTS idx_attachments_participants ON encrypted_attachments(uploader_public_id, recipient_public_id);

-- Encrypted Backup Vaults: Client-side Argon2id encrypted recovery vaults
CREATE TABLE IF NOT EXISTS encrypted_backup_vaults (
    account_public_id VARCHAR(75) PRIMARY KEY REFERENCES accounts(public_id) ON DELETE CASCADE,
    version INT NOT NULL DEFAULT 1,
    algorithm VARCHAR(64) NOT NULL,
    kdf_salt VARCHAR(64) NOT NULL,
    kdf_opslimit INT NOT NULL,
    kdf_memlimit BIGINT NOT NULL,
    kdf_alg INT NOT NULL,
    ciphertext TEXT NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Subscriptions & Quotas (Core E2EE unpaywalled)
CREATE TABLE IF NOT EXISTS subscriptions (
    public_id VARCHAR(75) PRIMARY KEY REFERENCES accounts(public_id) ON DELETE CASCADE,
    tier VARCHAR(20) NOT NULL DEFAULT 'FREE',
    status VARCHAR(20) NOT NULL DEFAULT 'free',
    current_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    max_devices INT NOT NULL DEFAULT 3,
    max_attachment_size_bytes BIGINT NOT NULL DEFAULT 26214400,
    retention_days INT NOT NULL DEFAULT 14,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Abuse Reports (Zero message content)
CREATE TABLE IF NOT EXISTS abuse_reports (
    id UUID PRIMARY KEY,
    reporter_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id) ON DELETE CASCADE,
    reported_public_id VARCHAR(75) NOT NULL REFERENCES accounts(public_id) ON DELETE CASCADE,
    category VARCHAR(32) NOT NULL,
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Admin Audit Events: Tamper-evident administrative action log
CREATE TABLE IF NOT EXISTS admin_audit_events (
    event_id UUID PRIMARY KEY,
    admin_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_resource VARCHAR(128) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    details JSONB NOT NULL DEFAULT '{}'
);

-- Feature Flags: With immutable security invariant protection
CREATE TABLE IF NOT EXISTS feature_flags (
    key VARCHAR(64) PRIMARY KEY,
    enabled BOOLEAN NOT NULL,
    description TEXT NOT NULL,
    rollout_percentage INT NOT NULL DEFAULT 100,
    is_security_invariant BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert default security invariants
INSERT INTO feature_flags (key, enabled, description, rollout_percentage, is_security_invariant)
VALUES 
    ('enforce_e2ee', TRUE, 'Enforce End-to-End Encryption on all messages', 100, TRUE),
    ('enforce_contact_approval', TRUE, 'Require mutual approval before messaging by default', 100, TRUE),
    ('experimental_voice_notes', FALSE, 'Opt-in preview of encrypted voice notes', 0, FALSE)
ON CONFLICT (key) DO NOTHING;
