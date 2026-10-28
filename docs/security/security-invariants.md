# NIZ Chat: Core Security Invariants

These invariants are non-negotiable. No pull request, feature flag, administrative bypass, or architectural change may violate these rules.

## Invariant 1: Zero Private Keys on Server
- Under no circumstance shall any private key (identity private key, ephemeral ratchet private key, signed prekey private key, one-time prekey private key, backup encryption key, or recovery mnemonic) be sent to, accepted by, processed by, or stored on the server.
- The server validation pipeline must reject any JSON payload containing private key identifiers.

## Invariant 2: Content-Free Server Persistence
- The server backend, database, cache, message broker, and object store shall never receive, store, or log plaintext message bodies or decrypted attachments.
- All message payloads are encrypted client-side prior to network transmission and decrypted client-side on authorized recipient devices.

## Invariant 3: Recipient Approval Default
- An unknown account cannot deliver messages into another user's normal chat conversation without an explicit contact approval state (`APPROVED`).
- Inbound messages from unapproved contacts are dropped or rejected server-side.

## Invariant 4: No Bearer Secrets in Permanent Identity QR Codes
- A user's permanent identity QR code encodes strictly the user's public identity ID and protocol verification fingerprint.
- It must NEVER contain API bearer tokens, session cookies, private keys, or recovery secrets.
- Possessing or copying a permanent QR code only permits the bearer to initiate a connection request; it grants zero conversation access.

## Invariant 5: Fail-Closed Security
- If cryptographic verification (signature check, AEAD authentication tag, or ratchet step) fails, the client and server must immediately reject the payload and abort the session step.
- The system must never silently downgrade to plaintext or unauthenticated delivery.

## Invariant 6: Feature Flags Cannot Bypass Security Invariants
- Dynamic configuration and feature flags may enable/disable product experiments (e.g. UI layouts, sandbox billing features, experimental codecs).
- Feature flags are cryptographically and structurally decoupled from:
  1. Encryption enforcement
  2. Contact approval requirements
  3. Identity verification warnings
  4. Server-side authorization checks
  5. Device revocation enforcement

## Invariant 7: Admin Plane Privacy Isolation
- The administrative console is hosted on an isolated origin with a separate API boundary and authentication mechanism (mandatory MFA).
- No administrative role (including Super Admin) possesses the capability to view message text, browse user conversation histories, or extract cryptographic keys.
- Admin APIs only serve aggregate counters, health telemetry, and audited configuration.
