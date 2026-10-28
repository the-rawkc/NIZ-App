# NIZ Chat v1.0.0-rc1 Release Notes

> **Privacy-First, QR-Connected Messaging Application for Web, Mobile, and Desktop**  
> **Release Candidate 1.0 (28 October 2026)**  
> **Built strictly according to NIZ Chat SRS v1.0 & Master Build Specification**

---

## 🌟 Executive Overview
NIZ Chat is an end-to-end encrypted (E2EE), privacy-first messaging platform engineered so that the backend server and system operators **have zero knowledge of message contents or user private cryptographic keys**. All identities are cryptographically generated on user devices (`niz_id_<hex>`), all connections require mutual recipient consent or single-use expiring invitations, all message payloads and file attachments are encrypted client-side using Libsodium (`XChaCha20-Poly1305` and the Double Ratchet Algorithm), and local vaults are secured using Argon2id (`crypto_pwhash`).

---

## 🔒 Verification of Non-Negotiable Security Invariants
- [x] **Invariant 1: Zero Private Keys on Server**: Backend validation deeply scans all JSON payloads with `assertNoSecretsInPayload`, rejecting any private keys, passphrases, seed phrases, or mnemonics with immediate 400 Bad Request.
- [x] **Invariant 2: Content-Free Server Persistence**: The server database and queues hold strictly AEAD-authenticated ciphertext envelopes. Plaintext message bodies and decrypted media never touch server memory, disk, or logs.
- [x] **Invariant 3: Recipient Approval Default**: Unapproved accounts cannot message a recipient; inbound messages are blocked server-side with 403 Forbidden.
- [x] **Invariant 4: Bearer-Free Permanent QR**: Permanent identity QRs contain only public IDs and safety fingerprints—zero bearer tokens or session secrets.
- [x] **Invariant 5: Fail-Closed Cryptography**: All signature verification, MAC checks, and prekey authentications fail closed with immediate session termination on tampering.
- [x] **Invariant 6: Invariant Locks on Feature Flags**: Feature flags cannot disable core security invariants (`enforce_e2ee`, `enforce_contact_approval`).
- [x] **Invariant 7: Isolated Admin Operations Plane**: Isolated origin/port with mandatory MFA, role-based access control (RBAC), and zero ability to inspect user messages or extract keys.
- [x] **Invariant 8: Strict Attachment Authorization**: Encrypted attachments are gated strictly to authorized conversation participants.
- [x] **Invariant 9: Account Closure Cryptographic Purging**: User account closure permanently purges all identities, devices, invitations, queue envelopes, backup vaults, and attachment blobs (FR-020).

---

## 📦 Monorepo Packages & Applications

| Workspace | Description | Tech Stack |
| :--- | :--- | :--- |
| `packages/shared-types` | Canonical protocol interfaces, DTOs, and envelopes | TypeScript |
| `packages/validation` | Zod validation schemas & deep negative secret checks | Zod, TypeScript |
| `packages/crypto-core` | Double Ratchet, Ed25519/X25519, Argon2id, QR generators | Libsodium (`libsodium-wrappers-sumo`), QRCode |
| `packages/ui` | Design tokens (Charcoal `#0B0F17`, Emerald `#10B981`) | CSS, TypeScript |
| `apps/server` | Modular backend, WebSocket push, PostgreSQL & Memory adapters | Fastify, pg, ws, Helmet, Rate Limit |
| `apps/web` | Privacy-first Web Client with QR preview & encrypted chat | React, TypeScript, Vite, Libsodium |
| `apps/admin` | Isolated Operations Console with MFA and tamper-evident audit logs | React, TypeScript, Vite |

---

## 🚀 Completed Delivery Roadmap (Phases 0–13)
- **Phase 0: Product & Security Decisions** — ADR-001, ADR-002, ADR-003, Threat Model, Invariant Matrix.
- **Phase 1: Foundation & Monorepo** — Multi-package workspaces, Fastify modular server scaffold, Docker Postgres.
- **Phase 2: Identity & QR Lifecycle** — Client key generation, 6-block safety numbers, permanent QR, ephemeral invitations.
- **Phase 3: Connection Requests & Verification** — Request/approval state machine, contact management, safety numbers, abuse reporting.
- **Phase 4: Encrypted 1:1 Text MVP** — Double Ratchet (DH + symmetric ratchets), out-of-order skipping, WebSocket ciphertext push, ACK purges.
- **Phase 5: Hardening MVP & Operations Plane** — Mandatory admin MFA, RBAC privilege separation, locked feature flags, FR-020 account closure.
- **Phase 6: Encrypted Attachments** — Client-side `XChaCha20-Poly1305` attachment encryption, opaque UUID blobs, 25MB cap, participant download gate.
- **Phase 7: Multi-Device & Secure Recovery** — Multi-device linking/revocation, Argon2id-derived `.nizvault` encrypted backup sync.
- **Phase 8: Billing & Sandbox Subscriptions** — Free-tier unpaywalled E2EE messaging, simulated sandbox checkout, webhook lifecycle.
- **Phase 9: Production Read-Model & PostgreSQL** — `pg.Pool` connection pooling, parameterized SQL queries, transactional BYTEA blob attachments.
- **Phase 10: Performance & Ingestion Benchmarks** — Batch message ingestion (`/v1/messages/batch`), queue pagination, WebSocket heartbeat ping-pong, auto-reconnect.
- **Phase 11: Production Hardening & Containerization** — Multi-stage production Dockerfiles, Nginx SPA routing, Fastify Helmet CSP/HSTS, `docker-compose.prod.yml`.
- **Phase 12: Production Readiness & Disaster Recovery** — Automated invariant regression audits, crash resilience, readiness certification.
- **Phase 13: Final Polish & Release Candidate** — Full cross-workspace typechecking (0 errors), all 33 automated tests passing, release documentation.

---

## 🧪 Test Suite Summary
```
> niz-chat@0.1.0 test
> npm run test --workspace=@niz/crypto-core && npm run test --workspace=@niz/server

ℹ @niz/crypto-core: 9 tests, 9 passed, 0 failed
ℹ @niz/server:      24 tests, 24 passed, 0 failed
Total Tests:        33 passing, 0 failing (100% PASS)
```
