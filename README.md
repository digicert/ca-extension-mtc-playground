# mtc-bridge

A standalone Go service that extends a DigiCert Private CA with experimental
[Merkle Tree Certificate (MTC)](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-01.html) support.
It watches the CA's MariaDB database for certificate issuances and revocations,
constructs an append-only issuance log as a Merkle tree, and serves it via the
[C2SP tlog-tiles](https://c2sp.org/tlog-tiles) HTTP protocol.

---

## What This Does (and Doesn't Do) vs the MTC Standard

The MTC specification (`draft-ietf-plants-merkle-tree-certs-01`) is a large
standard covering transparent issuance logs, cosigner coordination, TLS 1.3
handshake integration, signatureless certificate construction, ACME extensions,
and browser relying-party logic. This project implements a **simplified subset**
focused on transparency and auditability.

### Implemented

| Feature | Spec Reference | Notes |
|---|---|---|
| Append-only issuance log | MTC §5.3 | Full X.509 DER certificates as log entries |
| Merkle tree construction | RFC 9162 §2 | `SHA-256(0x00 ∥ data)` for leaves, `SHA-256(0x01 ∥ left ∥ right)` for interior nodes |
| C2SP tlog-tiles HTTP API | [tlog-tiles](https://c2sp.org/tlog-tiles) | `/checkpoint`, `/tile/<L>/<N>`, `/tile/entries/<N>` |
| Signed checkpoints | [C2SP signed-note](https://c2sp.org/signed-note) | Ed25519 signatures in signed-note format |
| Inclusion proofs | RFC 9162 §2.1.3 | `GET /proof/inclusion?serial=<hex>` endpoint |
| Revocation tracking | MTC §5.7 | Revocation-by-index bitfield, polled from CA database |
| Single local cosigner | MTC §5.5 | Ed25519 key pair, signs checkpoints on each tree update |
| Null entry at index 0 | MTC §5.3 | Sentinel entry per spec |

### Not Implemented

| Feature | Spec Reference | Why |
|---|---|---|
| External cosigner protocol | MTC §5.5 | Requires distributed coordination infrastructure |
| Multi-cosigner coordination | MTC §5.5 | Only single local cosigner supported |
| TLS 1.3 integration | MTC §6 | Requires TLS library modifications |
| Signatureless certificates | MTC §4 | Needs TLS handshake integration to be useful |
| ACME MTC extensions | MTC §7 | Out of scope for this demonstration |
| Browser relying-party logic | MTC §8 | Requires browser/client-side implementation |
| Consistency proofs | RFC 9162 §2.1.4 | Not yet implemented (inclusion proofs only) |

---

## Architecture

```
┌─────────────────┐         ┌──────────────────┐
│  DigiCert CA    │  read   │   mtc-bridge     │
│  MariaDB 10.11  │◄────────│   (Go service)   │
│  :3306          │         │                  │
│  digicert_ca DB │         │  ┌─ watcher ──┐  │
└─────────────────┘         │  │ poll every  │  │
                            │  │ 10s for new │  │
                            │  │ certs/revs  │  │
                            │  └─────┬───────┘  │
                            │        │          │
                            │  ┌─────▼───────┐  │
                            │  │ issuancelog  │  │
                            │  │ append entry │  │
                            │  │ update tree  │  │──► PostgreSQL State DB
                            │  │ checkpoint   │  │    (mtcbridge, :5432)
                            │  └─────┬───────┘  │
                            │        │          │
                            │  ┌─────▼───────┐  │
                            │  │ tlogtiles   │  │──► HTTP :8080
                            │  │ admin UI    │  │    /checkpoint, /tile/...
                            │  │ proofs      │  │    /proof/inclusion
                            │  └─────────────┘  │
                            └──────────────────┘
```

**Data flow:** The watcher polls the DigiCert CA's MariaDB for new certificates
and revocations. Each new certificate is appended to the Merkle tree in
PostgreSQL. Checkpoints are signed with Ed25519 and served over HTTP alongside
tile data and inclusion proofs.

---

## Prerequisites

- **Go 1.21+**
- **DigiCert Private CA** running with MariaDB (container `ca-db` on port 3306)
- **PostgreSQL 16** for the state store (container `mtc-state-db` on port 5433)
- **DigiCert CA API key** (provisioned during CA setup)
- `curl`, `openssl`, `jq` for the walkthrough commands

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/briantrzupek/ca-extension-merkle.git
cd ca-extension-merkle

# 2. Build
make build

# 3. Generate a cosigner key (first time only)
make generate-key

# 4. Start PostgreSQL state store (if not already running)
docker run -d --name mtc-state-db \
  -e POSTGRES_DB=mtcbridge \
  -e POSTGRES_USER=mtcbridge \
  -e POSTGRES_PASSWORD=mtcbridge \
  -p 5433:5432 \
  postgres:16-alpine

# 5. Run mtc-bridge
make run
# Or: ./bin/mtc-bridge -config config.yaml
```

The service starts on `http://localhost:8080`. It will immediately begin
ingesting certificates from the CA database and building the Merkle tree.

---

## Hands-On Walkthrough

This section provides step-by-step commands you can run to issue a certificate
through the DigiCert Private CA, watch mtc-bridge detect it, verify its
inclusion in the Merkle tree, revoke it, and confirm the revocation is tracked.

> **Note:** All commands below assume the DigiCert CA is running on
> `localhost:80` and mtc-bridge is running on `localhost:8080`. Adjust the
> `CA_API_KEY`, `CA_ID`, and `TEMPLATE_ID` values for your environment.

### Step 0 — Set Variables

```bash
# DigiCert CA API credentials (from your CA provisioning)
export CA_API_KEY="your-api-key-here"
export CA_ID="A76AC522CBABC804919211EB5706CFAD"
export TEMPLATE_ID="0196198F96545084143B237D9E39FC90"
export CA_URL="http://localhost"
export MTC_URL="http://localhost:8080"
```

### Step 1 — Check Current Tree State

```bash
# View the current checkpoint (tree size + root hash)
curl -s $MTC_URL/checkpoint
```

Example output:

```
localhost/mtc-bridge
7968
yDioudA/efgM/lkppZ5GO87ABRF03/BrdTNk530dq+g=

— mtc-bridge-dev o+eJTz2yzeOM...
```

The second line (`7968`) is the number of entries in the tree.

### Step 2 — Issue a Certificate Through the CA

```bash
# Generate a key pair and CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /tmp/mtc-demo.key \
  -subj "/CN=mtc-demo.example.com/O=MTC Demo Corp/C=US" \
  -addext "subjectAltName=DNS:mtc-demo.example.com" \
  -out /tmp/mtc-demo.csr 2>/dev/null

# Read the CSR and escape newlines for JSON
CSR=$(awk '{printf "%s\\n", $0}' /tmp/mtc-demo.csr)

# Issue the certificate via the DigiCert CA REST API
CERT_RESPONSE=$(curl -s -X POST \
  -H "x-api-key: $CA_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d "{
    \"issuer\": {\"id\": \"$CA_ID\"},
    \"template_id\": \"$TEMPLATE_ID\",
    \"cert_type\": \"private_ssl\",
    \"csr\": \"$CSR\",
    \"subject\": {
      \"common_name\": \"mtc-demo.example.com\",
      \"organization_name\": \"MTC Demo Corp\",
      \"country\": \"US\"
    },
    \"validity\": {
      \"valid_from\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"valid_to\": \"$(date -u -v+365d +%Y-%m-%dT%H:%M:%SZ)\"
    },
    \"extensions\": {
      \"san\": {\"dns_names\": [\"mtc-demo.example.com\"]}
    }
  }" \
  "$CA_URL/certificate-authority/api/v1/certificate")

# Extract the certificate ID and serial number
CERT_ID=$(echo "$CERT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
SERIAL=$(echo "$CERT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['serial_number'])")
echo "Certificate ID: $CERT_ID"
echo "Serial Number:  $SERIAL"
```

### Step 3 — Wait for mtc-bridge to Detect the Certificate

mtc-bridge polls the CA database every 10 seconds and creates a new checkpoint
every 60 seconds. Wait about 15-60 seconds, then check:

```bash
# Watch the tree size grow
curl -s $MTC_URL/checkpoint

# Or check the admin dashboard
open http://localhost:8080/admin/
```

The tree size should have increased by 1.

### Step 4 — Verify the Certificate is in the Merkle Tree

```bash
# Request an inclusion proof by serial number
curl -s "$MTC_URL/proof/inclusion?serial=$SERIAL" | python3 -m json.tool
```

Example output:

```json
{
  "leaf_index": 7968,
  "tree_size": 7969,
  "leaf_hash": "5b9a1e9e9f15e4ab4d8ddd5faefae9cf...",
  "proof": [
    "305170f5b9beb10f43d491d0dea2a56d...",
    "08f1f04d5d8c81a18d273b8f4f9acaab..."
  ],
  "root_hash": "c838a8b9d03f79f80cfe5929a59e463b...",
  "checkpoint": "localhost/mtc-bridge\n7969\n..."
}
```

The response contains:
- **`leaf_index`** — position of the certificate in the tree
- **`proof`** — the Merkle inclusion proof (list of sibling hashes)
- **`root_hash`** — the tree root that can be independently verified
- **`checkpoint`** — the signed checkpoint anchoring the proof

### Step 5 — Browse the Raw Tree Data

```bash
# Fetch a Merkle hash tile (level 0, tile 0 = first 256 leaves)
curl -s $MTC_URL/tile/0/000 | xxd | head -5

# Fetch an entry bundle tile (first 256 entries)
curl -s $MTC_URL/tile/entries/000 | wc -c

# Fetch the latest checkpoint
curl -s $MTC_URL/checkpoint
```

### Step 6 — Revoke the Certificate

```bash
# Revoke via the DigiCert CA REST API
curl -s -X PUT \
  -H "x-api-key: $CA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"revocation_reason": "key_compromise"}' \
  "$CA_URL/certificate-authority/api/v1/certificate/$CERT_ID/revocation"

# Response: HTTP 204 No Content (success)
echo "Certificate $CERT_ID revoked."
```

### Step 7 — Verify Revocation in the MTC

Wait ~30 seconds for the revocation poller to detect the change, then:

```bash
# Check the revocation bitfield
# This returns a binary bitfield where each bit represents a tree index.
# A set bit means that index has been revoked.
curl -s $MTC_URL/revocation | wc -c

# Confirm via the admin dashboard
open http://localhost:8080/admin/
```

The admin dashboard will show the updated revocation count.

### Step 8 — Run the Full Conformance Suite

```bash
make conformance
```

Expected output:

```
=== MTC tlog-tiles Conformance Test Suite ===
Target: http://localhost:8080

  checkpoint_exists              [PASS]
  checkpoint_format              [PASS]
  checkpoint_parseable           [PASS]
  tile_level0_exists             [PASS]
  tile_hash_size                 [PASS]
  entry_tile_exists              [PASS]
  entry_tile_parseable           [PASS]
  inclusion_proof                [PASS]
  proof_api_inclusion            [PASS]
  tile_caching                   [PASS]
  revocation_endpoint            [PASS]

Results: 11 passed, 0 failed, 0 skipped
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/checkpoint` | Latest signed checkpoint (C2SP signed-note format) |
| GET | `/tile/<L>/<N>` | Merkle hash tile at level L, index N |
| GET | `/tile/entries/<N>` | Entry bundle tile at index N |
| GET | `/proof/inclusion?serial=<hex>[&index=<n>]` | Inclusion proof for a certificate by serial number |
| GET | `/revocation` | Revocation bitfield (binary) |
| GET | `/admin/` | HTMX admin dashboard |
| GET | `/healthz` | Health check |

### Checkpoint Format

```
<origin>
<tree_size>
<base64 root hash>

— <key_id> <base64 Ed25519 signature>
```

### Inclusion Proof Response

```json
{
  "leaf_index": 42,
  "tree_size": 7968,
  "leaf_hash": "<hex SHA-256>",
  "proof": ["<hex hash>", "..."],
  "root_hash": "<hex SHA-256>",
  "checkpoint": "<full signed checkpoint text>"
}
```

---

## Project Structure

```
cmd/
  mtc-bridge/          Main service binary
  mtc-conformance/     Conformance test client (11 tests)
internal/
  admin/               HTMX dashboard (templates + handlers)
  cadb/                Read-only MariaDB adapter for DigiCert CA
  config/              YAML config with env-var substitution
  cosigner/            Ed25519 key management + checkpoint signing
  issuancelog/         Entry construction + Merkle tree maintenance
  merkle/              RFC 9162 Merkle tree operations + inclusion proofs
  revocation/          Revocation bitfield construction
  store/               PostgreSQL state store (6 tables)
  tlogtiles/           C2SP tlog-tiles HTTP handler + proof API
  watcher/             CA database poller (certs + revocations)
docs/
  adr/                 Architecture Decision Records (ADR-000 through ADR-008)
  design/              System overview documentation
keys/                  Ed25519 cosigner key (generated, not committed)
config.yaml            Local development configuration
docker-compose.yml     Docker Compose for mtc-bridge + PostgreSQL
Dockerfile             Multi-stage Docker build
Makefile               Build, test, run, conformance targets
```

---

## Configuration

See [config.yaml](config.yaml) for the full configuration reference. Key
sections:

- **`state_db`** — PostgreSQL connection for the Merkle tree state
- **`ca_db`** — MariaDB connection for the DigiCert CA database (read-only)
- **`watcher`** — Polling intervals for certificates and revocations
- **`cosigner`** — Ed25519 key file path and key ID
- **`http`** — Listen address, timeouts, cache TTLs

Environment variables can override config values (see `docker-compose.yml` for
the full list).

---

## Running Tests

```bash
# Unit tests (38 tests across merkle, config, cosigner, tlogtiles packages)
make test

# Conformance tests (requires a running mtc-bridge instance)
make conformance

# Go vet
make vet
```

---

## DigiCert CA API Quick Reference

These are the DigiCert Private CA REST API calls used in the walkthrough above.
The API base URL is `http://localhost/certificate-authority/api/v1`.

### Issue a Certificate

```
POST /certificate-authority/api/v1/certificate
Headers:
  x-api-key: <api-key>
  Content-Type: application/json

Body:
{
  "issuer": {"id": "<CA_ID>"},
  "template_id": "<TEMPLATE_ID>",
  "cert_type": "private_ssl",
  "csr": "<PEM CSR>",
  "subject": {
    "common_name": "example.com",
    "organization_name": "Org",
    "country": "US"
  },
  "validity": {
    "valid_from": "2026-01-01T00:00:00Z",
    "valid_to": "2027-01-01T00:00:00Z"
  },
  "extensions": {
    "san": {"dns_names": ["example.com"]}
  }
}
```

### Revoke a Certificate

```
PUT /certificate-authority/api/v1/certificate/<CERT_ID>/revocation
Headers:
  x-api-key: <api-key>
  Content-Type: application/json

Body:
{
  "revocation_reason": "key_compromise"
}

Response: 204 No Content
```

### List Certificates

```
GET /certificate-authority/api/v1/certificate?limit=10
Headers:
  x-api-key: <api-key>
```

---

## License

Internal / experimental. Not for production use.
