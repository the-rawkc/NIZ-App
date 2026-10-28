# ADR-002: Monorepo Structure and Modular Monolith Architecture

## Status
Accepted (Phase 0 Evaluation)

## Context
NIZ Chat requires a clean, maintainable architecture across multiple applications (Web, Admin, Server, and future Mobile/Desktop) while preserving strict security boundaries.
Premature microservices introduce network latency, distributed transaction complexity, unnecessary serialization overhead, and elevated operational cost. At the same time, tight coupling between transport (HTTP/WebSocket) and domain logic invites security regressions.

## Decision

1. **Monorepo Strategy**:
   - Use standard Node.js/npm workspaces for zero-dependency workspace management.
   - Applications:
     - `apps/web`: React + Vite + TypeScript web client.
     - `apps/admin`: React + Vite + TypeScript operations & business console (distinct origin/API to eliminate cross-session privilege leakage).
     - `apps/server`: Modular monolith backend with Fastify / Node.js HTTP + WebSocket server.
   - Packages:
     - `packages/shared-types`: Canonical DTOs, message envelopes, and protocol contracts.
     - `packages/validation`: Zod schemas for all request, response, and envelope inputs.
     - `packages/ui`: Accessible design system tokens (dark navy/charcoal `#0D1117`, `#161B22`, emerald green `#10B981` / `#059669`, high contrast neutrals).

2. **Modular Monolith Backend Architecture**:
   - Segregate domains into autonomous internal modules:
     - `modules/identity`: Public identity and device key registration (strictly public keys; never private).
     - `modules/invitations`: Ephemeral invitation token generation, rate limits, expiry, and single-use lifecycle.
     - `modules/connections`: Connection request state machine (`pending`, `approved`, `declined`, `blocked`).
     - `modules/messaging`: Ciphertext envelope routing, offline message queueing, delivery acks, deduplication.
     - `modules/admin`: Separate admin auth, RBAC, aggregate health metrics, feature flags, audit logging (no plaintext message viewing).
   - Domain modules communicate via typed interfaces and event emitters, not direct database joins across module boundaries.

## Consequences
- Fast local development with single-command build, typecheck, and test.
- Easy migration to separate microservices in later phases if required by horizontal scale, with zero domain refactoring needed.
