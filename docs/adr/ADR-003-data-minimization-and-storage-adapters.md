# ADR-003: Storage Adapters and Data Minimization Strategy

## Status
Accepted (Phase 0 Evaluation)

## Context
NIZ Chat follows a "privacy by default" model and a "free-first migration policy."
Local development must run without paid cloud subscriptions. Furthermore, storage engines must sit behind clean interface abstractions so that the product can migrate seamlessly from local Docker/in-memory adapters to managed PostgreSQL, Redis, and S3-compatible cloud storage without breaking application code or exposing user content.

## Decision

1. **Storage Adapter Pattern**:
   - Provide clean storage interfaces (`IdentityRepository`, `InvitationRepository`, `ConnectionRepository`, `MessageQueueRepository`, `AuditRepository`).
   - Implement:
     - `MemoryStorageAdapter`: Zero-dependency, thread-safe in-memory storage for unit tests, rapid CI runs, and developer setups where Docker is not available.
     - `PostgresStorageAdapter`: Production-grade SQL adapter using parameterized queries, transactional guarantees, and SQL migrations.
     - `LocalDiskStorageAdapter` & `S3StorageAdapter`: For encrypted attachment blobs (opaque ciphertext only).

2. **Data Minimization Invariants**:
   - The database stores NO user phone numbers, NO address books, and NO real names.
   - All identities are random cryptographic IDs (e.g. `niz_id_<hex>`).
   - The database stores NO private keys (`identity_private_key`, `ratchet_key`, `session_key`, `recovery_seed`). Attempts to write a private key will fail closed at the validation layer and repository boundary.
   - Server queues hold ciphertext envelopes with finite TTL (e.g. 14 days default for offline delivery). Once acknowledged as delivered, ciphertext is marked for purge.
   - Admin queries can only query aggregate counts and metrics; no query exists to dump contact graphs or message contents.

## Consequences
- Guaranteed zero lock-in to cloud vendors.
- Developers can immediately run the entire system locally with `npm test` and `npm run dev` even without Docker running, while Docker Compose provides a production-identical PostgreSQL setup.
