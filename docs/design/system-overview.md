# mtc-bridge System Overview

## Purpose

mtc-bridge is a standalone Go service that extends a DigiCert Private CA with experimental Merkle Tree Certificate (MTC) support. It watches the CA's certificate database, constructs an append-only issuance log as a Merkle tree, and serves it via the C2SP tlog-tiles HTTP protocol.

## Data Flow

```
1. Watcher polls CA MariaDB every ~10s for new certificates
2. For each new cert:
   a. Parse DER blob from cert_blob column
   b. Construct TBSCertificateLogEntry (MTC §5.3)
   c. Append entry to issuance log (PostgreSQL)
   d. Recompute affected tree hashes (bottom-up)
3. After batch append:
   a. Generate new checkpoint (signed note with Ed25519)
   b. Store checkpoint in PostgreSQL
   c. Emit SSE event to admin dashboard
4. Revocation polling:
   a. Check for is_revoked flag changes
   b. Map serial_number → log entry index
   c. Add to revoked_indices table
   d. Update compacted revocation ranges
5. HTTP serving (concurrent with watcher):
   a. /checkpoint → latest signed checkpoint
   b. /tile/<L>/<N> → Merkle tree hash tiles
   c. /tile/entries/<N> → entry bundle tiles
   d. /admin/ → dashboard pages
```

## Database Schemas

### PostgreSQL State Store (`mtcbridge`)

```sql
-- Append-only log of all certificate entries
CREATE TABLE log_entries (
    idx         BIGINT PRIMARY KEY,     -- 0-based entry index
    entry_type  SMALLINT NOT NULL,      -- 0=null_entry, 1=x509_entry, 2=precert_entry
    entry_data  BYTEA NOT NULL,         -- serialized MerkleTreeCertEntry
    cert_sha256 BYTEA,                  -- SHA-256 of original DER cert (NULL for null_entry)
    serial_hex  TEXT,                   -- hex serial number from cert
    ca_cert_id  TEXT,                   -- reference to source CA cert ID
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Precomputed tree node hashes for tile serving
CREATE TABLE tree_nodes (
    level   INTEGER NOT NULL,           -- 0 = leaf level
    index   BIGINT NOT NULL,            -- node index at this level
    hash    BYTEA NOT NULL,             -- 32-byte SHA-256 hash
    PRIMARY KEY (level, index)
);

-- Signed checkpoints (append-only)
CREATE TABLE checkpoints (
    id          BIGSERIAL PRIMARY KEY,
    tree_size   BIGINT NOT NULL,
    root_hash   BYTEA NOT NULL,         -- 32-byte root hash
    timestamp   TIMESTAMPTZ NOT NULL,
    signature   BYTEA NOT NULL,         -- Ed25519 signature
    body        TEXT NOT NULL,           -- full signed-note text
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Revocation tracking
CREATE TABLE revoked_indices (
    entry_idx   BIGINT PRIMARY KEY REFERENCES log_entries(idx),
    serial_hex  TEXT NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL,
    reason      SMALLINT NOT NULL DEFAULT 0
);

-- Watcher cursor for CA DB polling
CREATE TABLE watcher_cursors (
    id              TEXT PRIMARY KEY DEFAULT 'default',
    last_created_at TIMESTAMPTZ NOT NULL,
    last_cert_id    TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Admin event log
CREATE TABLE events (
    id          BIGSERIAL PRIMARY KEY,
    event_type  TEXT NOT NULL,           -- e.g., "entry_appended", "checkpoint_created", "revocation_detected"
    payload     JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### MariaDB CA Database (read-only access)

Key columns queried:

```sql
-- certificate table (primary source)
SELECT id, serial_number, cert_blob, created_date, valid_from, valid_to,
       is_revoked, revoked_date, revoked_reason, issuer_id,
       subject_key_id, thumbprint_sha256
FROM certificate
WHERE (created_date, id) > (?, ?)
ORDER BY created_date, id
LIMIT 100;

-- ca table (loaded once at startup)
SELECT id, name, cert_type, status, cert_blob
FROM ca
WHERE status = 'active';

-- revocation polling
SELECT id, serial_number, revoked_date, revoked_reason
FROM certificate
WHERE is_revoked = 1
  AND revoked_date > ?;
```

## Component Interaction

```
cmd/mtc-bridge
  ├── internal/config      ← loads YAML + env vars
  ├── internal/cadb        ← MariaDB read-only adapter
  ├── internal/store       ← PostgreSQL state store
  ├── internal/merkle      ← tree hash computation
  ├── internal/cosigner    ← Ed25519 signing
  ├── internal/issuancelog ← entry construction + log management
  ├── internal/revocation  ← revocation-by-index tracking
  ├── internal/watcher     ← background polling orchestrator
  ├── internal/tlogtiles   ← HTTP tile serving handlers
  └── internal/admin       ← dashboard handlers + templates
```
