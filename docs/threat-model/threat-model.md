# NIZ Chat: Comprehensive Threat Model (Phase 0)

## Document Version
Version 1.0 — October 2026

## 1. System Overview & Boundaries
NIZ Chat is a privacy-first messaging system. Its fundamental architecture assumes that the network, hosting infrastructure, and even server operators may be curious or compromised.

### Trust Boundaries
1. **Endpoint Trust Boundary (Client Device)**:
   - Contains: User identity private keys, prekey bundles private keys, active Double Ratchet session states, plaintext message database in local client storage, decrypted attachments.
   - Assumed secure unless device is rooted/jailbroken, compromised by endpoint malware, or stolen while unlocked.
2. **Network Boundary (Client <-> Server TLS)**:
   - Transport Layer Security (TLS 1.3) protects against passive and active network eavesdropping, ISP inspection, and Wi-Fi sniffing.
   - End-to-end encryption (E2EE) protects message payloads against compromised TLS proxies or compromised backend servers.
3. **Server / Infrastructure Boundary (Backend Monolith & Database)**:
   - Contains: Public identity records, public prekey bundles, ephemeral invitation hashes, pending connection states, queued ciphertext envelopes, aggregate metrics, and administrative audit trails.
   - Strictly untrusted with respect to message content or private keys.

---

## 2. Attacker Personas & Threat Capabilities

| Persona | Motivation | Capabilities | Mitigation in NIZ Chat |
| :--- | :--- | :--- | :--- |
| **Curious or Compromised Server Operator** | Attempt to read messages, discover social graphs, or impersonate users. | Full access to server RAM, database tables, disk storage, application logs, and network routing. | Server only receives and stores ciphertext. Zero private keys exist on server. Prekey bundles are signed by user identity keys. Identity verification (Safety Numbers) detects MITM key substitution. |
| **Network Eavesdropper / ISP / State Actor** | Intercept traffic, inspect payloads, block communication. | Passive packet inspection, active DNS/BGP hijacking, TLS interception attempt. | TLS 1.3 + pinned certificates. Double Ratchet ciphertext is indistinguishable from random bytes. |
| **Malicious Contact / Spam Bot** | Flood users with unsolicited messages or harassment. | Automated account creation, scanning public identity IDs, spamming connection requests. | Default "Fail Closed": Unknown accounts cannot send messages until contact request is explicitly accepted. Temporary invitations expire, are revocable, rate-limited, and optionally single-use. |
| **Thief / Physical Device Compromise** | Access messages or extract keys from a lost/stolen device. | Physical access to device file system or RAM. | Client-side encryption of local storage with device biometric/passphrase. Remote device revocation from another linked device. |
| **Malicious Update / CI Supply Chain Attacker** | Push malicious JS or client binary to exfiltrate private keys from client memory. | Commit malicious dependency, compromise CI/CD token. | Treat web-delivered JS as part of TCB: strict dependency pinning, automated vulnerability and secret scanning in CI, subresource integrity (SRI), and code signing for mobile/desktop. |

---

## 3. Threat Analysis & Mitigations

### 3.1 Identity Enumeration & QR Guessing
- **Threat**: Attacker brute-forces identity IDs or invitation tokens to connect to arbitrary users.
- **Mitigation**:
  - Identity IDs are 256-bit cryptographically secure random values (hex/base58).
  - Invitation tokens use 128-bit high-entropy random secrets.
  - Server applies aggressive rate limits on invitation redemption and connection request attempts per IP and per account.

### 3.2 QR Screenshot Theft & Replay
- **Threat**: An invitation QR code is photographed, screenshotted, or shared in a public chat.
- **Mitigation**:
  - Invitation QRs have configurable short TTLs (default 15 minutes to 24 hours).
  - One-time-use flag: atomic database transition ensures token is burned on first redemption.
  - Permanent QR contains ONLY public identity identifier; scanning it triggers a connection request that the receiver must explicitly approve before any conversation can occur.

### 3.3 Server Compromise & Ciphertext Manipulation
- **Threat**: Attacker with database access modifies queued messages, replays old messages, or injects forged messages.
- **Mitigation**:
  - Authenticated Encryption with Associated Data (AEAD - XChaCha20-Poly1305 / AES-256-GCM) with ratcheted keys.
  - Every envelope includes counter, ephemeral ratchet public key, and MAC. Tampered ciphertext fails decryption and is discarded.
  - Replay cache on client rejects duplicate message counters.

### 3.4 Key Leakage to Logs or Crash Telemetry
- **Threat**: Developer error or logging middleware records request bodies containing key material.
- **Mitigation**:
  - Strict input schemas reject private key fields at the gateway.
  - Structured content-free logging redacts payloads and records only `requestId`, `senderId`, `recipientId`, `envelopeId`, `status`, and `timestamp`.
  - Automated security regression tests verify that logger output contains no cryptographic secrets or message content.

### 3.5 Metadata Leakage
- **Threat**: Observer infers communication networks from routing metadata.
- **Mitigation**:
  - Acknowledged messages are promptly purged from server queues.
  - Offline message envelopes contain only minimal routing headers (`recipientDeviceId`, `envelopeId`, `timestamp`, `ciphertext`).
  - No permanent server-side social graph: contact relationships are stored only as necessary for routing approval flags and can be revoked by either party.
