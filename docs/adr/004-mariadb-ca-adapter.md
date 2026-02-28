# ADR-004: MariaDB CA Database Adapter

**Status**: Accepted

**Date**: 2026-02-27

### Context

The DigiCert Private CA stores all issued certificates in a MariaDB 10.11.16 database (`digicert_ca`). mtc-bridge needs to poll for new issuances and revocations without modifying the CA database.

### Decision

Implement a read-only MariaDB adapter using `go-sql-driver/mysql`. The adapter:
- Polls `certificate` table for new rows ordered by `(created_date, id)` cursor
- Polls `certificate.is_revoked` flag for revocation detection
- Extracts DER certificate blobs from `cert_blob` column
- Caches the CA hierarchy from the `ca` table at startup
- NEVER writes to the CA database

### Consequences

- **Positive**: Zero impact on the running CA — purely read-only.
- **Positive**: Cursor-based polling is simple, reliable, and doesn't require triggers or CDC.
- **Negative**: Polling latency (default 10s) means MTCs won't reflect certs issued in the last few seconds.
- **Negative**: No `AUTO_INCREMENT` column on `certificate` — must use `created_date` + `id` composite cursor, which is less efficient.

### Alternatives Considered

- **MariaDB binlog CDC**: Lower latency, but complex and fragile connector setup.
- **Webhook from CA**: Requires CA modification, violates "no CA changes" constraint.
- **Shared filesystem watching**: CA exports DER files; fragile and non-transactional.
