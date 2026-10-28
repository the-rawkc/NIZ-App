# NIZ Chat: Data Inventory & Retention Policy (Phase 0)

## Purpose & Scope
This document outlines every data field collected or stored by NIZ Chat, its legitimate operational purpose, access restrictions, retention lifespan, and deletion triggers.

---

## Data Inventory Table

| Data Element | Storage Location | Sensitivity | Operational Purpose | Access Control | Retention / Expiry | Deletion Trigger |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Account Public ID** (`public_id`) | Database (`accounts`) | Low (Pseudonymous) | Routing and user identification | Public to approved contacts | Retained while account active | Account deletion |
| **Public Identity Key** (`identity_key`) | Database (`devices`) | Public Key | E2EE session initiation and signature verification | Public to connection requesters | Retained while device active | Device revocation / account deletion |
| **Public Signed Prekey & One-time Prekeys** | Database (`prekeys`) | Public Key | Asynchronous X3DH / PQXDH session establishment | Public | Consumed once or rotated every 7-30 days | Replenished/deleted after consumption |
| **Invitation Tokens** (`token_hash`) | Database (`invitations`) | High (Cryptographic token) | Ephemeral connection onboarding | System server only (salted SHA-256 hash stored) | Configurable TTL (15 min to 24 hrs max) | Expired by timer or revoked by user |
| **Connection Requests** | Database (`connection_requests`) | Medium | Sender/recipient routing of contact requests | Sender and recipient only | 30 days pending TTL | Approval, decline, or timeout |
| **Ciphertext Message Envelopes** | Database / Queue (`message_queue`) | High (Ciphertext only) | Store-and-forward offline message delivery | Recipient device only | 14 days max for offline delivery | Immediately purged upon client delivery ack |
| **Admin Audit Trail** | Database (`admin_audit_logs`) | High (Security Log) | Compliance, accountability, tamper detection | Security Auditor / Super Admin | 365 days immutable retention | Retention expiration (no manual deletion) |
| **Aggregate Metrics** | Database (`metrics_daily`) | Low | Platform health, error rates, capacity planning | Operations / Product Admins | Aggregated daily; retained 90 days | Aggregated to monthly summaries |

---

## Prohibited Data Elements
The following data elements are strictly prohibited from being collected, processed, or persisted by any NIZ Chat server or third-party service:
1. Address book / phone contact lists.
2. User phone numbers or mobile network operator identifiers.
3. Plaintext message bodies or unencrypted media contents.
4. Private cryptographic keys of any kind (identity, ratchet, backup, or recovery seed).
5. GPS coordinates or location tracking logs.
6. Payment card numbers (all card processing is delegated exclusively to PCI-DSS certified payment processors).
