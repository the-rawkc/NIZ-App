# NIZ Chat (Version 1.0)

> **Privacy-first, QR-connected messaging application for web, mobile, and desktop.**

NIZ Chat is built around user-controlled identities, QR-based connections, zero-knowledge end-to-end encryption, distraction-free UX, and an operational model where backend services and administrators **cannot read message contents or access private cryptographic keys**.

---

## 🔒 Non-Negotiable Security Invariants
1. **Zero Private Keys on Server**: The server never generates, receives, or stores private identity keys, device keys, ratchet keys, or recovery secrets.
2. **Content-Free Persistence**: Server queues and databases store strictly authenticated ciphertext envelopes (`XChaCha20-Poly1305` / `AES-256-GCM`). No plaintext bodies or decrypted attachments exist in server memory or disk.
3. **Recipient Approval Default**: Unknown accounts cannot deliver normal messages without an explicit `APPROVED` contact relationship.
4. **No Secrets in Permanent QR**: Permanent identity QRs encode only public identifiers and key fingerprints; they carry zero bearer tokens or session secrets.
5. **Fail Closed**: Any cryptographic failure or unauthenticated message attempt aborts immediately without silent unencrypted fallback.
6. **Isolated Admin Plane**: The admin console runs on an isolated origin/API with mandatory MFA and zero capability to inspect message content or extract keys.

---

## 📁 Repository Structure
```
├── docs/
│   ├── adr/                      # Architectural Decision Records (ADR-001, 002, 003)
│   ├── threat-model/             # Comprehensive Threat Model & Attacker Personas
│   ├── security/                 # Security Invariants & Data Inventory / Retention Policy
│   ├── architecture/             # System Architecture & Flow Diagrams
│   └── operations/               # Free-Tier Strategy & Cloud Migration Runbook
├── packages/
│   ├── shared-types/             # Canonical DTOs, Envelopes & Protocol Contracts
│   ├── validation/               # Zod validation schemas & Negative Security Validators
│   └── ui/                       # Design tokens (charcoal/dark navy, emerald accent)
├── apps/
│   ├── server/                   # Fastify modular monolith (Identity, Invites, Queue, Storage)
│   ├── web/                      # React + TypeScript + Vite web client
│   └── admin/                    # React + TypeScript + Vite isolated operations console
├── docker-compose.yml            # Local PostgreSQL 16 container setup
├── .env.example                  # Environment template (zero real secrets)
└── package.json                  # Root monorepo workspace definition
```

---

## 🚀 Quickstart & Local Development

### 1. Prerequisites
- **Node.js**: v20 or v22+
- **Docker** (optional): for local PostgreSQL; in-memory storage adapter runs with zero external dependencies.

### 2. Install Dependencies
```bash
npm install
```

### 3. Build & Typecheck
```bash
npm run build
npm run typecheck
```

### 4. Run Automated Test Suite
```bash
npm test
```
The test suite executes comprehensive unit and integration tests, including:
- Healthcheck and server lifecycle
- Public identity and device key registration
- **Negative Security Invariant Test**: Confirms immediate rejection (400) if a payload contains any private key or secret
- Ephemeral invitation lifecycle: expiry, redemption, and single-use enforcement
- **Negative Authorization Invariant Test**: Confirms 403 Forbidden when an unapproved sender attempts to message a recipient
- End-to-end ciphertext queueing, delivery, and post-delivery ACK purging

### 5. Running the Services
- **Backend Server**:
  ```bash
  npm run dev --workspace=@niz/server
  ```
  Runs on `http://localhost:4000`. Health endpoint: `http://localhost:4000/health`.
- **Web Client**:
  ```bash
  npm run dev --workspace=@niz/web
  ```
  Runs on `http://localhost:5173`.
- **Admin Console**:
  ```bash
  npm run dev --workspace=@niz/admin
  ```
  Runs on `http://localhost:5174`.

### 6. Local PostgreSQL via Docker (Optional)
```bash
docker compose up -d
```
Loads PostgreSQL 16 with schema initialized at `apps/server/src/db/init.sql`.

---

## 🗺️ Roadmap & Phase Progress
- [x] **Phase 0: Product & Security Decisions** — ADRs, Threat Model, Invariants, Protocol Review, Data Inventory.
- [x] **Phase 1: Foundation & Monorepo** — Workspaces, shared types, validation schemas, design tokens, modular server, web & admin scaffolds, automated security tests, CI pipeline.
- [ ] **Phase 2: Identity & QR Lifecycle** — Client-side cryptographic identity generation, permanent identity QR, and temporary expiring invitations.
- [ ] **Phase 3: Connection Requests & Verification** — Request/approval state machine and safety number verification.
- [ ] **Phase 4: Encrypted One-to-One Text MVP** — Double Ratchet session establishment and ciphertext store-and-forward.
- [ ] **Phase 5: Hardening MVP** — Abuse quotas, rate limits, structured non-content audit logging.
