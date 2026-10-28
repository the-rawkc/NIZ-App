# NIZ Chat: Incident Response & Data Deletion Runbook (Phase 5)

## 1. Incident Response Procedures

### Severity Levels
- **P0 (Critical)**: Suspected client update chain compromise, cryptographic invariant violation, or denial-of-service affecting all message routing.
- **P1 (High)**: Server queue failure, elevated decryption failure reports indicating ratchet desynchronization, or abuse flood.
- **P2 (Medium)**: Transient database connection latency, webhook delivery failures, non-critical admin console degradation.

### P0 Incident Response Protocol
1. **Immediate Triage & Containment**:
   - If a malicious client update is suspected: halt deployment pipelines, freeze CDN caches, and trigger emergency client advisory.
   - If server database compromise is suspected: rotate all database credentials, inspect admin audit logs (`/v1/admin/audit-logs`), and verify that no private keys were ever present (guaranteed by Phase 0-4 architecture).
2. **Key Material Safety**:
   - Remember: **Servers hold NO private keys or plaintext messages**. A compromised backend exposes only ciphertext envelopes with finite TTL (14 days) and public routing identifiers.
3. **Post-Mortem & Disclosure**:
   - Document root cause, timeline, affected components, and public disclosure notice within 72 hours under responsible disclosure standards.

---

## 2. User Account Closure & Data Deletion Runbook

Under SRS Section 6 (FR-020), users possess the right to permanently close their accounts and purge their server-side records.

### Account Deletion Data Flow
1. User requests deletion via client (`DELETE /v1/identity/:publicId`).
2. Server verifies caller authorization (`x-sender-public-id`).
3. Storage Layer atomically executes:
   - Delete `accounts` record.
   - Delete all associated `devices` and public keys.
   - Invalidate and purge all active `invitations`.
   - Purge all pending `connection_requests`.
   - Purge all queued offline ciphertext envelopes in `message_queue`.
4. Note on Counterparts:
   - Account deletion purges all server-side records. Content already delivered to and stored locally on approved recipients' devices cannot be remotely deleted from their physical hardware.
