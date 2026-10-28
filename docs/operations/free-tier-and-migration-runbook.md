# NIZ Chat: Free-Tier Strategy & Cloud Migration Runbook (Phase 0)

## 1. Principles
- **Zero Cost for Developers**: Local development must execute without credit cards, third-party API keys, or paid services.
- **Portability by Design**: Database (PostgreSQL), Object Storage (MinIO / S3), and queues use standard protocols.
- **No Insecure Shortcuts**: Free tiers must never be treated as an excuse to compromise cryptographic invariants, skip TLS, or omit secret scanning.

---

## 2. Environment Configurations

| Environment | Database | Storage | Queues & Cache | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Local Dev (Node)** | In-Memory / PostgreSQL via Docker | Local filesystem / MinIO | Node EventEmitter / Memory | Instant startup for any developer without setup friction. |
| **Local Dev (Docker)**| PostgreSQL 16 Alpine container | MinIO container | In-memory / Redis container | Full multi-container production emulation. |
| **Free Staging Tier**| Neon / Supabase Free Tier Postgres | Cloudflare R2 Free Tier / Local | PostgreSQL LISTEN/NOTIFY | For staging tests; strict quotas and spend alerts set. |
| **Production** | Managed Dedicated PostgreSQL (AWS RDS / GCP Cloud SQL) | AWS S3 / GCP GCS with Object Lock | Redis / PostgreSQL | Paid tier when validated; automated backups and multi-AZ failover. |

---

## 3. Migration Procedure (Free Tier to Production)

1. **Database Migration**:
   - Schema is managed via migration scripts (`apps/server/src/db/migrations`).
   - Run pg_dump on staging / free database:
     ```bash
     pg_dump -h <staging_host> -U <user> -d niz_chat --schema-only > schema.sql
     pg_dump -h <staging_host> -U <user> -d niz_chat --data-only --exclude-table=message_queue > data.sql
     ```
   - Restore onto production RDS/Cloud SQL:
     ```bash
     psql -h <prod_host> -U <prod_user> -d niz_chat -f schema.sql
     psql -h <prod_host> -U <prod_user> -d niz_chat -f data.sql
     ```
   - Verify: No ciphertext messages need to be decrypted during migration! Ciphertext envelopes in queue remain opaque and decryptable only by client devices.

2. **Attachment / Ciphertext Blob Migration**:
   - S3-compatible API ensures `aws s3 sync` or `rclone sync` moves encrypted files between buckets without re-encryption.
