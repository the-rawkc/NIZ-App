# Multi-stage production Dockerfile for @niz/admin (Isolated Operations Console)
FROM node:20-alpine AS builder

WORKDIR /app

# Copy root workspace configurations
COPY package.json package-lock.json ./
COPY packages/shared-types/package.json ./packages/shared-types/
COPY packages/validation/package.json ./packages/validation/
COPY packages/crypto-core/package.json ./packages/crypto-core/
COPY packages/ui/package.json ./packages/ui/
COPY apps/admin/package.json ./apps/admin/

RUN npm ci

# Copy source trees
COPY packages/ ./packages/
COPY apps/admin/ ./apps/admin/

# Build internal shared packages and admin client
RUN npm run build --workspace=@niz/shared-types
RUN npm run build --workspace=@niz/validation
RUN npm run build --workspace=@niz/crypto-core
RUN npm run build --workspace=@niz/ui
RUN npm run build --workspace=@niz/admin

# Nginx Alpine server stage
FROM nginx:alpine AS runner

COPY --from=builder /app/apps/admin/dist /usr/share/nginx/html
COPY apps/admin/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
