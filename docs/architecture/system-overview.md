# NIZ Chat: Architecture & System Overview (Phase 0)

## 1. High-Level Architecture

NIZ Chat follows a clean modular monolith approach for the backend service, paired with standalone client applications and a physically and logically isolated administrative plane.

```
                    +---------------------------+
                    |    NIZ Chat Client App    |
                    | (Web / Mobile / Desktop)  |
                    |                           |
                    |  - Client Crypto Engine   |
                    |  - Local Plaintext DB     |
                    |  - Double Ratchet State   |
                    +-------------+-------------+
                                  |
                           TLS 1.3 (WSS / HTTPS)
                           Encrypted Envelopes Only
                                  |
                    +-------------v-------------+
                    |      NIZ Server API       |
                    |    (Modular Monolith)     |
                    |                           |
                    |  - Identity Module        |
                    |  - Invitation Module      |
                    |  - Connection Module      |
                    |  - Ciphertext Queue       |
                    +-------------+-------------+
                                  |
                    +-------------+-------------+
                    |                           |
            +-------v-------+           +-------v-------+
            |  PostgreSQL   |           | S3 / Storage  |
            |   Database    |           | (Ciphertext)  |
            | (Zero Keys)   |           |  (Zero Keys)  |
            +---------------+           +---------------+
```

---

## 2. Component Directory

| Component | Location | Role & Boundaries |
| :--- | :--- | :--- |
| **Server Monolith** | `apps/server` | Handles REST API & WebSocket routing, rate limiting, connection state, and ciphertext queue delivery. Zero decryption capability. |
| **Web Client** | `apps/web` | React + TypeScript + Vite app. Performs client-side key generation, Double Ratchet encryption/decryption, and UI rendering. |
| **Admin Console** | `apps/admin` | React + TypeScript console on separate origin. MFA enforced. RBAC with zero access to message content or private keys. |
| **Shared Types** | `packages/shared-types` | Strict TypeScript DTOs, message envelopes, and protocol contracts. |
| **Validation** | `packages/validation` | Runtime Zod schemas ensuring complete input sanitization and negative validation (rejecting secret payloads). |
| **UI Design System** | `packages/ui` | Accessible components adhering to NIZ dark charcoal/navy styling, emerald accents, and WCAG AA contrast. |

---

## 3. Data Flow: Sending an Encrypted Message

1. **Sender** constructs plaintext message locally.
2. **Sender Crypto Engine** checks active Double Ratchet session for recipient device.
   - If no session exists, fetches recipient's public prekey bundle from server and performs 3DH/PQXDH handshake.
   - Ratchets symmetric send chain, deriving a single-use message key.
   - Encrypts plaintext message with XChaCha20-Poly1305 / AES-256-GCM AEAD authenticated encryption.
3. **Sender Client** encapsulates ciphertext in a versioned `MessageEnvelope` DTO and posts via HTTPS / WSS to `/v1/messages`.
4. **Server Monolith**:
   - Validates authorization and recipient connection status (`APPROVED`).
   - Stores ciphertext envelope in `message_queue` table with 14-day TTL.
   - If recipient has an active WebSocket connection, pushes ciphertext envelope immediately.
5. **Recipient Client**:
   - Receives ciphertext envelope.
   - Decrypts envelope using Double Ratchet state.
   - Stores decrypted message in local SQLite / IndexedDB client database.
   - Sends delivery ACK back to server.
6. **Server** permanently purges ciphertext from `message_queue`.
