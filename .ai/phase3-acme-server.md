# Phase 3 — ACME Server Integration

## Overview

Phase 3 added a **standalone ACME server** (RFC 8555) that runs on a separate port alongside the existing mtc-bridge HTTP server. It provides automated certificate issuance by accepting ACME orders, proxying finalize requests to the DigiCert Private CA, waiting for the assertion issuer to build inclusion proof bundles, and delivering certificates with their MTC proofs attached.

The ACME server implements JWS request verification (ES256 + RS256), nonce-based replay protection, account management, order lifecycle (pending → ready → processing → valid), http-01 challenge validation (with auto-approve mode for internal CAs), and certificate download with appended assertion bundles.

## What Was Built

### New Package

| Package | Files | Lines | Purpose |
|---|---|---|---|
| `internal/acme` | 6 | 1,173 | RFC 8555 ACME server with JWS verification, nonce management, account/order/authorization/challenge handlers, CA proxy, and certificate+assertion delivery |

### Package Files

| File | Lines | Responsibility |
|---|---|---|
| `server.go` | 74 | Config, Server struct, New() constructor, ServeHTTP(), route registration |
| `handlers.go` | 362 | Directory, nonce, account, order, authorization, challenge handlers |
| `finalize.go` | 330 | Order finalization, CA proxy, certificate download, assertion waiting |
| `jws.go` | 254 | JWS parsing/verification, JWK→public key, EC/RSA signature verification, JWK thumbprint (RFC 7638) |
| `helpers.go` | 103 | Error responses, URL builders, ID generation, rendering helpers, admin stats |
| `nonce.go` | 50 | Nonce creation, consumption, background cleanup |

### Modified Packages

| Package | Changes |
|---|---|
| `internal/store` | Added 4 ACME tables (`acme_accounts`, `acme_orders`, `acme_authorizations`, `acme_challenges`) with 6 indexes. Added 4 types (`ACMEAccount`, `ACMEOrder`, `ACMEAuthorization`, `ACMEChallenge`). Added ~16 CRUD methods. |
| `internal/config` | Added `ACMEConfig` type with 12 fields. Added `IsEnabled()` method. Added ACME defaults in `applyDefaults()`. |
| `cmd/mtc-bridge` | Wired ACME server creation and startup on separate HTTP listener. Included in graceful shutdown. |
| `cmd/mtc-conformance` | Added 5 ACME conformance tests (22 total) + JWS helper functions. Added `-acme-url` flag. |
| `Makefile` | Updated conformance target with `-acme-url` flag. |
| `config.yaml` | Added `acme:` configuration section with local dev values. |

## Major Design Decisions

### 1. Separate port, same binary

The ACME server runs on its own port (default `:8443`) rather than as a path prefix on the main HTTP server. Rationale:
- ACME clients expect the server at a known base URL, not behind a path prefix
- Separate ports allow independent TLS termination (ACME server could have its own cert)
- Clear operational boundary: the tlog-tiles API is read-only, ACME is write-oriented
- Either server can be disabled independently via config

### 2. Stdlib-only JWS implementation

JWS verification uses only Go standard library (`crypto/ecdsa`, `crypto/rsa`, `crypto/sha256`, `encoding/json`). No external JOSE libraries. Rationale:
- The ACME JWS profile is narrow: only ES256 and RS256 are needed
- Reduces dependency surface for a security-critical path
- Keeps the module dependency graph minimal (only pgx, mysql, yaml)
- Full control over the parsing pipeline for audit purposes

### 3. Auto-approve challenge mode for internal CAs

The `auto_approve_challenge` config flag (default: `true`) skips real HTTP-01 validation and immediately marks challenges as valid. Rationale:
- Internal/private CAs don't need domain control validation
- The DigiCert Private CA already enforces its own authorization policies
- Simplifies development and conformance testing
- Real HTTP-01 validation is implemented and available when auto-approve is disabled

### 4. CA proxy pattern for finalize

Rather than implementing certificate issuance directly, the ACME server **proxies** the CSR to the DigiCert Private CA REST API. The flow:
1. ACME client sends CSR via finalize
2. Server encodes CSR into DigiCert CA API format and POSTs to `/certificate-authority/api/v1/certificate`
3. Server extracts the serial number from the CA response
4. Background goroutine polls `store.FindEntryBySerial()` + `store.GetAssertionBundle()` waiting for the watcher to ingest the cert and the assertion issuer to build the proof
5. Once found, order status transitions to `valid` and the certificate URL becomes available

### 5. Assertion bundle attached to certificate download

The ACME certificate endpoint returns:
1. The X.509 certificate in PEM format (extracted from the log entry DER)
2. The assertion bundle appended as a second PEM block (custom `MTC ASSERTION` type)

This means ACME clients receive both the traditional certificate and its MTC proof in a single download, which is the key integration point between ACME and MTC.

### 6. In-memory nonce store with TTL cleanup

Nonces are stored in a `sync.Mutex`-protected map with 1-hour expiry, cleaned up by a background goroutine every 5 minutes. Rationale:
- Nonces are ephemeral and don't need persistence — they're only valid for minutes
- In-memory storage is faster than database round-trips for every request
- Single-instance deployment (no need for distributed nonce store)
- Background cleanup prevents unbounded memory growth

### 7. JWK thumbprint for account deduplication

Accounts are identified by their JWK thumbprint (RFC 7638: SHA-256 of canonical JSON). This means:
- Same key always maps to the same account, regardless of contact info
- No external account binding needed
- Matches the RFC 8555 account lookup model (POST-as-GET to newAccount with onlyReturnExisting)

## ACME Order Lifecycle

```
Client                     ACME Server                   DigiCert CA
  │                            │                              │
  │ POST /new-account (JWK)    │                              │
  │───────────────────────────>│ Create/lookup by thumbprint   │
  │<───────────────────────────│ 201 + Location: /account/xxx  │
  │                            │                              │
  │ POST /new-order (KID)      │                              │
  │───────────────────────────>│ Create order + authz + chall  │
  │<───────────────────────────│ 201 + pending + authz URLs    │
  │                            │                              │
  │ POST /authz/{id}           │                              │
  │───────────────────────────>│ Return authz + challenges     │
  │<───────────────────────────│ 200 + http-01 challenge       │
  │                            │                              │
  │ POST /challenge/{id}       │                              │
  │───────────────────────────>│ Auto-approve (or HTTP-01)     │
  │<───────────────────────────│ 200 + processing/valid        │
  │                            │ ┌──────────────────┐         │
  │                            │ │ Check all authzs │         │
  │                            │ │ valid → order    │         │
  │                            │ │ status = "ready" │         │
  │                            │ └──────────────────┘         │
  │ POST /order/{id}/finalize  │                              │
  │   (CSR payload)            │                              │
  │───────────────────────────>│ Validate CSR identifiers      │
  │<───────────────────────────│ 200 + processing              │
  │                            │                              │
  │                            │ POST /certificate (CSR)       │
  │                            │─────────────────────────────>│
  │                            │<─────────────────────────────│
  │                            │ Serial number returned        │
  │                            │                              │
  │                            │ ┌──────────────────────────┐ │
  │                            │ │ Poll store for:          │ │
  │                            │ │ 1. FindEntryBySerial     │ │
  │                            │ │ 2. GetAssertionBundle    │ │
  │                            │ │ (timeout: 5 min)         │ │
  │                            │ └──────────────────────────┘ │
  │                            │                              │
  │ POST /certificate/{id}     │                              │
  │───────────────────────────>│ Return PEM cert + assertion   │
  │<───────────────────────────│ bundle (application/pem-...   │
```

## Database Schema

### `acme_accounts` Table

```sql
CREATE TABLE IF NOT EXISTS acme_accounts (
    id             TEXT PRIMARY KEY,
    thumbprint     TEXT NOT NULL UNIQUE,
    public_key     JSONB NOT NULL,
    contact        JSONB,
    status         TEXT NOT NULL DEFAULT 'valid',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
```

### `acme_orders` Table

```sql
CREATE TABLE IF NOT EXISTS acme_orders (
    id             TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL REFERENCES acme_accounts(id),
    status         TEXT NOT NULL DEFAULT 'pending',
    identifiers    JSONB NOT NULL,
    not_before     TIMESTAMPTZ,
    not_after      TIMESTAMPTZ,
    expires        TIMESTAMPTZ NOT NULL,
    finalize_url   TEXT,
    certificate_id TEXT,
    serial_hex     TEXT,
    error          JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
```

### `acme_authorizations` Table

```sql
CREATE TABLE IF NOT EXISTS acme_authorizations (
    id             TEXT PRIMARY KEY,
    order_id       TEXT NOT NULL REFERENCES acme_orders(id),
    identifier     JSONB NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    expires        TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
```

### `acme_challenges` Table

```sql
CREATE TABLE IF NOT EXISTS acme_challenges (
    id             TEXT PRIMARY KEY,
    authz_id       TEXT NOT NULL REFERENCES acme_authorizations(id),
    type           TEXT NOT NULL,
    token          TEXT NOT NULL UNIQUE,
    status         TEXT NOT NULL DEFAULT 'pending',
    validated_at   TIMESTAMPTZ,
    error          JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
```

### Indexes

| Index | Columns | Purpose |
|---|---|---|
| `idx_acme_orders_account` | `account_id` | List orders by account |
| `idx_acme_orders_serial` | `serial_hex` | Lookup order by certificate serial |
| `idx_acme_authz_order` | `order_id` | List authorizations by order |
| `idx_acme_challenges_authz` | `authz_id` | List challenges by authorization |
| `idx_acme_challenges_token` | `token` | Lookup challenge by token (for HTTP-01 validation) |
| `idx_acme_accounts_thumbprint` | `thumbprint` (UNIQUE in column def) | Account dedup by JWK thumbprint |

### Key Store Methods

| Method | SQL Pattern | Purpose |
|---|---|---|
| `CreateACMEAccount` | INSERT | Create new account |
| `GetACMEAccount` | SELECT by id | Fetch account by ID |
| `GetACMEAccountByThumbprint` | SELECT by thumbprint | Account dedup lookup |
| `CreateACMEOrder` | BEGIN/INSERT×3/COMMIT | Transactional order+authz+challenge creation |
| `GetACMEOrder` | SELECT by id | Fetch order |
| `UpdateACMEOrderStatus` | Dynamic UPDATE | Update status, serial, certificate_id, error |
| `ListACMEOrdersByAccount` | SELECT by account_id | List orders for account |
| `FindACMEOrderBySerial` | SELECT by serial_hex | Find order after CA issues cert |
| `GetACMEAuthorization` | SELECT by id | Fetch authorization |
| `ListACMEAuthorizationsByOrder` | SELECT by order_id | Get all authzs for an order |
| `UpdateACMEAuthorizationStatus` | UPDATE status | Transition authz state |
| `GetACMEChallenge` | SELECT by id | Fetch challenge |
| `ListACMEChallengesByAuthz` | SELECT by authz_id | Get challenges for authz |
| `UpdateACMEChallengeStatus` | UPDATE status+validated_at | Mark challenge valid/invalid |
| `GetACMEChallengeByToken` | SELECT by token | HTTP-01 validation lookup |

## ACME API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/acme/directory` | ACME directory (RFC 8555 §7.1.1) |
| HEAD/GET | `/acme/new-nonce` | Fresh anti-replay nonce (Replay-Nonce header) |
| POST | `/acme/new-account` | Create or lookup account (JWS with embedded JWK) |
| POST | `/acme/new-order` | Create certificate order (JWS with KID) |
| POST | `/acme/order/{id}` | Get order status (POST-as-GET) |
| POST | `/acme/authz/{id}` | Get authorization with challenges |
| POST | `/acme/challenge/{id}` | Trigger challenge validation |
| POST | `/acme/order/{id}/finalize` | Submit CSR to finalize order |
| POST | `/acme/certificate/{id}` | Download certificate + assertion PEM |

## Configuration

```yaml
acme:
  enabled: true
  addr: ":8443"
  external_url: "http://localhost:8443"
  ca_proxy_url: "http://localhost:80"
  ca_api_key: "<digicert-ca-api-key>"
  ca_id: "default"
  template_id: "default"
  mtc_bridge_url: "http://localhost:8080"
  auto_approve_challenge: true
  # order_expiry: "24h"           # default
  # assertion_timeout: "5m"       # default
  # assertion_poll_interval: "5s" # default
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable/disable the ACME server |
| `addr` | `:8443` | Listen address for the ACME HTTP server |
| `external_url` | — | Base URL used in ACME responses (directory, Location headers) |
| `ca_proxy_url` | — | DigiCert Private CA base URL for finalize proxy |
| `ca_api_key` | — | API key for the DigiCert CA REST API |
| `ca_id` | — | CA identifier for certificate issuance |
| `template_id` | — | Certificate template ID |
| `mtc_bridge_url` | — | mtc-bridge URL (used for assertion bundle polling) |
| `auto_approve_challenge` | `true` | Skip real HTTP-01 validation for internal CAs |
| `order_expiry` | `24h` | How long before pending orders expire |
| `assertion_timeout` | `5m` | Max wait time for assertion bundle during finalize |
| `assertion_poll_interval` | `5s` | How often to check for assertion bundle |

## Test Coverage

| Type | Count | Description |
|---|---|---|
| Conformance tests | 5 new (22 total) | `acme_directory`, `acme_nonce`, `acme_new_account`, `acme_new_order`, `acme_order_flow` |
| Unit tests | All passing | `go test ./internal/...` — no regressions |

### Conformance Test Details

| Test | What It Validates |
|---|---|
| `acme_directory` | Directory JSON has all required fields (newAccount, newNonce, newOrder, meta) |
| `acme_nonce` | HEAD to /acme/new-nonce returns unique Replay-Nonce headers |
| `acme_new_account` | JWS-signed account creation with ECDSA P-256, returns 201 + Location |
| `acme_new_order` | Order creation with DNS identifier, returns pending status + authz URLs |
| `acme_order_flow` | Full lifecycle: account → order → authz → challenge → poll until ready |

### JWS Test Helpers

The conformance client includes ACME JWS helpers for test requests:
- `acmeKey()` — generates ephemeral ECDSA P-256 key
- `acmeJWK()` — encodes public key as JWK JSON
- `acmeNonce()` — fetches a nonce from `/acme/new-nonce`
- `acmePost()` — signs payload as flattened JWS and POSTs with proper headers

## Demo Commands

```bash
# ACME directory
curl -s http://localhost:8443/acme/directory | python3 -m json.tool

# Get a nonce
curl -sI http://localhost:8443/acme/new-nonce | grep -i replay-nonce

# Run ACME conformance tests
./bin/mtc-conformance -url http://localhost:8080 -acme-url http://localhost:8443 -verbose

# Run all 22 conformance tests
make conformance
```

## Files Added/Modified

```
Added:
  internal/acme/server.go       Config, Server struct, New() constructor, ServeHTTP(),
                                route registration, nonce cleanup goroutine
  internal/acme/handlers.go     handleDirectory, handleNewNonce, handleNewAccount,
                                handleNewOrder, handleOrder, handleAuthorization,
                                handleChallenge, validateChallenge, performHTTP01
  internal/acme/finalize.go     handleFinalize, handleCertificate, processFinalize,
                                proxyToCA, waitForAssertion
  internal/acme/jws.go          verifyJWS, parseJWK, parseECJWK, parseRSAJWK,
                                verifySignature, jwkThumbprint (RFC 7638)
  internal/acme/helpers.go      acmeError, URL builders, newID, renderOrder,
                                renderChallenge, getAuthzURLs, admin stats helpers
  internal/acme/nonce.go        newNonce, consumeNonce, cleanupNonces

Modified:
  internal/store/store.go       4 ACME tables + 6 indexes in migrations,
                                4 types, ~16 CRUD methods
  internal/config/config.go     ACMEConfig type (12 fields), IsEnabled(),
                                defaults in applyDefaults()
  cmd/mtc-bridge/main.go        ACME server creation, config mapping,
                                separate HTTP listener, graceful shutdown
  cmd/mtc-conformance/main.go   5 ACME tests, JWS helpers, -acme-url flag
  Makefile                      -acme-url in conformance target
  config.yaml                   acme: configuration section
  README.md                     Phase 3 features, ACME endpoints, architecture
```

## What's Next (Phase 4)

Phase 4 focuses on **production hardening and observability**:
1. Structured logging (slog) with request IDs
2. Prometheus metrics for both HTTP and ACME servers
3. Rate limiting on ACME endpoints
4. TLS support for the ACME server
5. Docker Compose integration with ACME server
6. Load testing and performance benchmarks
