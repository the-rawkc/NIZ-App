# Multi-stage production Dockerfile for @niz/server
FROM node:20-alpine AS builder

WORKDIR /app

# Copy root workspace configurations
COPY package.json package-lock.json ./
COPY packages/shared-types/package.json ./packages/shared-types/
COPY packages/validation/package.json ./packages/validation/
COPY packages/crypto-core/package.json ./packages/crypto-core/
COPY packages/ui/package.json ./packages/ui/
COPY apps/server/package.json ./apps/server/

# Install all dependencies (including devDependencies needed for build)
RUN npm ci

# Copy source trees
COPY packages/ ./packages/
COPY apps/server/ ./apps/server/

# Build internal shared packages and server
RUN npm run build --workspace=@niz/shared-types
RUN npm run build --workspace=@niz/validation
RUN npm run build --workspace=@niz/crypto-core
RUN npm run build --workspace=@niz/ui
RUN npm run build --workspace=@niz/server

# Production runner stage
FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

# Install curl for optional container health inspection
RUN apk add --no-cache curl

# Copy root package.json and built outputs
COPY package.json package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/shared-types ./packages/shared-types
COPY --from=builder /app/packages/validation ./packages/validation
COPY --from=builder /app/packages/crypto-core ./packages/crypto-core
COPY --from=builder /app/packages/ui ./packages/ui
COPY --from=builder /app/apps/server/dist ./apps/server/dist
COPY --from=builder /app/apps/server/package.json ./apps/server/package.json
COPY --from=builder /app/apps/server/src/db ./apps/server/src/db

WORKDIR /app/apps/server

# Security: run as non-root unprivileged node user
USER node

EXPOSE 4000

# Healthcheck targeting Fastify content-free healthcheck endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:4000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "dist/index.js"]
