# ADR-001: Cryptographic Protocol and Implementation Strategy for NIZ Chat

## Status
Accepted (Phase 0 Evaluation)

## Context
NIZ Chat requires end-to-end encryption (E2EE) for one-to-one asynchronous messaging, with zero knowledge on the server (the server routes and temporarily queues ciphertext envelopes without access to private keys or plaintext payloads).

The requirements dictate:
1. **Never invent custom cryptography**: algorithms, key exchanges, ratchets, or authenticated encryption primitives must be established, maintained, and audited.
2. **Asynchronous forward secrecy (FS) and post-compromise security (PCS)**: if a session key is compromised, past messages remain secure (forward secrecy) and future messages heal automatically (healing ratchet).
3. **Multi-platform support**: must run reliably in Web environments (WASM / Web Crypto), Mobile (React Native / native secure enclaves), and Desktop (Tauri).
4. **Permissive/compatible licensing**: allowing clean adoption without licensing pitfalls.
5. **Post-Quantum Cryptography (PQC) readiness**: path towards hybrid KEMs (such as Kyber/ML-KEM with X25519, e.g. PQXDH).

## Candidate Evaluations

### Candidate A: Signal Protocol (`@signalapp/libsignal-client`)
- **Strengths**: Gold standard in asynchronous ratchet protocols (Double Ratchet, X3DH, PQXDH hybrid post-quantum key agreement). Rust core with TypeScript/Node/Web/C/Java bindings. Heavily audited.
- **Risks & Limitations**: AGPLv3 license. Strict compliance requirements. Rust WASM build toolchain for web can have packaging friction. Protocol server implementation requires tight coupling with prekey bundle management.

### Candidate B: Matrix Vodozemac (`vodozemac` - Olm/Megolm successor)
- **Strengths**: Apache-2.0 license. Rust implementation with maintained WASM and JavaScript bindings (`@matrix-org/vodozemac`). Implements Olm (Double Ratchet + 3DH) for 1:1 and Megolm for group messaging. Independent security audit by Least Authority (2022).
- **Risks & Limitations**: Group ratchets (Megolm) do not provide post-compromise security in the same manner as Double Ratchet. Active development is tied to the Matrix ecosystem.

### Candidate C: Standard Double Ratchet over Libsodium (`libsodium-wrappers` / `sodium-native`) + Hybrid KEM abstraction
- **Strengths**: ISC license (extremely permissive). Libsodium is one of the most widely scrutinized cryptographic libraries in history. Runs natively across Web (WASM), Node.js, iOS, Android, and Desktop without heavy native compilation hurdles. Robust primitives: X25519 key exchange, Ed25519 identity signatures, XChaCha20-Poly1305 authenticated encryption, and BLAKE2b / HKDF for key derivation.
- **Risks & Limitations**: Libsodium provides primitives (crypto_kx, crypto_box, crypto_secretstream, crypto_sign, crypto_auth), but the session ratchet state machine must follow the formal Signal Double Ratchet specification (RFC / Pond / Signal Double Ratchet Spec) rigorously without deviation.

## Decision: Dual-Layer Architecture

1. **Protocol Specification**:
   - Adopt the formal **Double Ratchet Algorithm** (Diffie-Hellman ratchet + symmetric KDF ratchets using HKDF-SHA256 / HKDF-BLAKE2b and AEAD XChaCha20-Poly1305) and **Prekey Tri-Diffie-Hellman (X3DH)** session initiation.
   - For post-quantum resistance, structure the Prekey Bundle interface to accept a hybrid KEM component (X25519 + ML-KEM-768/Kyber) as standardized in PQXDH.

2. **Core Implementation Engine**:
   - For web, backend test harness, and mobile clients, use **Libsodium** (`libsodium-wrappers-sumo` for universal WASM/Node compatibility) and vetted, audited Double Ratchet state machines with strict byte-level unit test vectors matching the Signal Double Ratchet test vectors.
   - All cryptographic operations are encapsulated in `@niz/crypto-core` (or `packages/crypto-core`) behind an immutable, verifiable interface.
   - No plaintext, private keys, or ratchet states are ever transmitted outside the client device.

## Consequences
- **Positive**: High performance, zero native compilation pain on web/desktop, permissive license, well-understood security boundaries, strict adherence to peer-reviewed specifications.
- **Verification Requirement**: Complete test suites verifying forward secrecy, out-of-order message handling, duplicate rejection, ciphertext tampering failure, and zero-key leakage to storage/logs.
