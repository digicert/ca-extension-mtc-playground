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
| Assertion bundles | Phase 1 | Self-contained proof artifacts (JSON + PEM) with cert metadata |
| X.509 metadata extraction | Phase 1 | Parses DER certificates for display in bundles and UI |
| Certificate browser | Phase 1 | Admin UI for searching/browsing certs with status badges |
| Visualization explorer | Phase 4 | Sunburst, treemap, and proof explorer with 4 color modes |
| `mtc-assertion` CLI | Phase 1 | Standalone tool to fetch, verify, and inspect assertion bundles |
| Proactive assertion generation | Phase 2 | Background pipeline pre-computes bundles after each checkpoint |
| Proof freshness management | Phase 2 | Detects and regenerates stale proofs as the tree grows |
| Assertion polling endpoint | Phase 2 | `GET /assertions/pending` for downstream consumers |
| Webhook notifications | Phase 2 | Push notifications with HMAC-SHA256 signing when assertions are ready |
| Assertion statistics | Phase 2 | `GET /assertions/stats` + admin dashboard metrics |
| ACME server (RFC 8555) | Phase 3 / MTC §7 | Standalone ACME endpoint on separate port with full order lifecycle |
| JWS request verification | Phase 3 / RFC 7515 | ES256 + RS256 with JWK and KID authentication |
| Account management | Phase 3 / RFC 8555 §7.3 | Create/lookup accounts by JWK thumbprint |
| Order lifecycle | Phase 3 / RFC 8555 §7.4 | pending → ready → processing → valid with authorization + challenge flow |
| http-01 challenge validation | Phase 3 / RFC 8555 §8.3 | Auto-approve mode for internal CAs, real HTTP validation path |
| CA proxy (finalize) | Phase 3 | Proxies CSR to DigiCert CA REST API, polls for assertion bundle |
| Certificate + assertion download | Phase 3 | PEM certificate with appended assertion bundle proof |

### Not Implemented

| Feature | Spec Reference | Why |
|---|---|---|
| External cosigner protocol | MTC §5.5 | Requires distributed coordination infrastructure |
| Multi-cosigner coordination | MTC §5.5 | Only single local cosigner supported |
| TLS 1.3 integration | MTC §6 | Requires TLS library modifications |
| Signatureless certificates | MTC §4 | Needs TLS handshake integration to be useful |
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
                            │        │          │
                            │  ┌─────▼───────┐  │
                            │  │ assertion   │  │
                            │  │ issuer      │  │  On each checkpoint:
                            │  │ (Phase 2)   │  │  batch-build bundles,
                            │  └─────┬───────┘  │  refresh stale proofs
                            │        │          │
                            │  ┌─────▼───────┐  │
                            │  │ tlogtiles   │  │──► HTTP :8080
                            │  │ admin UI    │  │    /checkpoint, /tile/...
                            │  │ proofs      │  │    /proof/inclusion
                            │  │ assertions  │  │    /assertion/{query}
                            │  │ polling     │  │    /assertions/pending
                            │  └──────┬──────┘  │
                            │         │         │
                            │    ┌────▼────┐    │
                            │    │webhooks │    │──► POST to configured URLs
                            │    │(optional│    │   HMAC-SHA256 signed
                            │    └────┬────┘    │
                            │         │         │
                            │  ┌──────▼──────┐  │
                            │  │ ACME server │  │──► HTTP :8443
                            │  │ (Phase 3)   │  │    /acme/directory
                            │  │ RFC 8555    │  │    /acme/new-account
                            │  │ JWS verify  │──│──► DigiCert CA REST API
                            │  │ CA proxy    │  │    (finalize → issue cert)
                            │  └─────────────┘  │
                            └──────────────────┘
```

**Data flow:** The watcher polls the DigiCert CA's MariaDB for new certificates
and revocations. Each new certificate is appended to the Merkle tree in
PostgreSQL. Checkpoints are signed with Ed25519 and served over HTTP alongside
tile data and inclusion proofs. The ACME server (Phase 3) runs on a separate
port and provides RFC 8555 certificate issuance — it proxies finalize requests
to the DigiCert CA, then waits for the assertion issuer to build the inclusion
proof bundle before delivering the certificate with its MTC proof.

---

## Prerequisites

- **Go 1.21+**
- **DigiCert Private CA** running with MariaDB (container `ca-db` on port 3306)
- **PostgreSQL 16** for the state store (via Docker Compose on port 5432)
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

# 4. Configure environment (copy and edit .env with your CA credentials)
cp .env.example .env
# Edit .env with your DigiCert CA API key, CA ID, and template ID

# 5. Generate self-signed TLS certs for the ACME server
./gen-demo-cert.sh

# 6. Start all services via Docker Compose
docker compose up -d

# Or run locally (requires PostgreSQL on localhost:5432):
make run
# Or: ./bin/mtc-bridge -config config.yaml
```

The service starts on `http://localhost:8080`. It will immediately begin
ingesting certificates from the CA database and building the Merkle tree.
The ACME server starts on `https://localhost:8443` (TLS with self-signed cert).

---

## Demonstrating ACME Functionality (Phase 3)

### Architectural & Design Decisions

- **Standalone ACME server** (RFC 8555) runs on a separate port (`:8443`) alongside the main service.
- **JWS verification** uses only Go stdlib (ES256/RS256), no external JOSE libraries.
- **Account management** via JWK thumbprint (RFC 7638).
- **Order lifecycle**: pending → ready → processing → valid, with http-01 challenge validation (auto-approve for internal CAs).
- **CA proxy**: Finalize requests are proxied to DigiCert CA REST API; assertion bundles are polled and attached to certificate downloads.
- **In-memory nonce store** with TTL cleanup.
- **Database**: 4 new ACME tables, 6 indexes, ~16 CRUD methods.
- **Config**: `ACMEConfig` with 12 fields, sensible defaults.
- **Conformance**: 6 ACME tests (23 total), all passing — including full MTC flow with real CA.

### How to Demonstrate

1. **Start the Service**
   ```bash
   make build
   ./bin/mtc-bridge -config config.yaml
   ```
   - Main API: `http://localhost:8080`
   - ACME API: `https://localhost:8443`

   Or use Docker Compose for reproducible setup:
   ```bash
   cp .env.example .env   # edit with your CA credentials
   ./gen-demo-cert.sh     # generate self-signed TLS certs
   docker compose up -d
   docker compose logs -f acme-server
   ```
   - Main API: `http://localhost:8080`
   - ACME API: `https://localhost:8443`

2. **Check ACME Directory**
   ```bash
   curl -sk https://localhost:8443/acme/directory | python3 -m json.tool
   ```

3. **Get a Replay-Nonce**
   ```bash
   curl -skI https://localhost:8443/acme/new-nonce | grep -i replay-nonce
   ```

4. **Run ACME Conformance Tests**
   ```bash
   ./bin/mtc-conformance -url http://localhost:8080 -acme-url https://localhost:8443 -verbose
   ```
   - All 23 tests should pass, including 6 ACME tests.

   Or run all tests with:
   ```bash
   make conformance
   ```

5. **Full ACME Order Flow**
   - Create account (JWS POST to `/acme/new-account`)
   - Create order (JWS POST to `/acme/new-order`)
   - Get authorization and challenge
   - Trigger challenge validation (auto-approved in dev mode)
   - Finalize order (proxy CSR to DigiCert CA)
   - Download certificate + assertion bundle (PEM)
   - See `.ai/phase3-acme-server.md` for full technical details and API examples.

   For a quick demo, use the provided script:
   ```bash
   ./demo-acme.sh
   ```
   This automates key/CSR generation, ACME directory/nonce fetch, and guides you to run conformance tests for full flow.

---

## Visualization Explorer

The admin dashboard includes an interactive visualization module at
`http://localhost:8080/admin/viz` with three viewing modes:

### Sunburst & Treemap Views

Both views render the certificate hierarchy (CA > Batch Window > Key Algorithm)
using HTML5 Canvas. Click segments to drill down, use breadcrumbs to navigate
back up.

**Color modes** control how segments are colored:
- **Trust Status** — green (valid) vs red (revoked)
- **Key Algorithm** — purple (post-quantum) vs blue (classical)
- **Certificate Age** — gradient from green (fresh) to red (expiring)
- **Assertion Coverage** — green (>80% fresh proofs), amber (>30% stale),
  red (>50% missing), blue (mixed)

**Highlight Revoked** toggle dims non-revoked segments and amplifies revoked
overlays with stronger colors and borders for quick identification.

### Proof Explorer

The Proof Explorer tab renders the Merkle inclusion proof for any certificate
as an interactive binary tree visualization. Enter a leaf index to see:
- The path from leaf to root highlighted in green
- Proof sibling hashes shown in blue at each tree level
- Hover any node to see its full SHA-256 hash
- Side panel with complete proof details (leaf hash, root hash, all proof
  hashes with left/right indicators)

### Data Pipeline

The visualization uses a `cert_metadata` cache table that is incrementally
populated by parsing DER certificates on first access. This avoids re-parsing
DER blobs on every request. The table is automatically populated when the
visualization page is loaded.

```bash
# Open the visualization
open http://localhost:8080/admin/viz
```

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

### Step 8 — Fetch an Assertion Bundle

Assertion bundles are self-contained proof artifacts that package a
certificate with its Merkle inclusion proof, signed checkpoint, and
parsed X.509 metadata.

```bash
# Fetch the assertion bundle by serial number (JSON)
curl -s "$MTC_URL/assertion/$SERIAL" | python3 -m json.tool
```

Example output:

```json
{
  "leaf_index": 7968,
  "serial_hex": "5BF2A7443A479D5600C6220D369208E325F31C62",
  "cert_meta": {
    "common_name": "mtc-demo.example.com",
    "organization": ["MTC Demo Corp"],
    "sans": ["mtc-demo.example.com"],
    "key_algorithm": "RSA",
    "is_ca": false
  },
  "leaf_hash": "5b9a1e9e9f15e4ab...",
  "proof": ["305170f5b9beb10f...", "08f1f04d5d8c81a1..."],
  "tree_size": 7969,
  "root_hash": "c838a8b9d03f79f8...",
  "checkpoint": "localhost/mtc-bridge\n7969\n...",
  "revoked": false,
  "log_origin": "localhost/mtc-bridge"
}
```

The bundle includes everything needed to independently verify the
certificate's presence in the log — the leaf hash, inclusion proof,
tree size, root hash, and signed checkpoint.

```bash
# Also available in PEM-like text format
curl -s "$MTC_URL/assertion/$SERIAL/pem"
```

### Step 9 — Use the mtc-assertion CLI

The `mtc-assertion` CLI tool provides fetch, verify, and inspect
subcommands for working with assertion bundles offline.

```bash
# Fetch a bundle by serial number and save to file
./bin/mtc-assertion fetch -serial $SERIAL -output /tmp/bundle.json

# Verify the inclusion proof cryptographically
./bin/mtc-assertion verify -input /tmp/bundle.json
# Output: "Inclusion proof is VALID"

# Pretty-print all bundle details
./bin/mtc-assertion inspect -input /tmp/bundle.json
```

`verify` walks the Merkle inclusion proof from the leaf hash up to the
root, using RFC 9162 hash combining (`SHA-256(0x01 ∥ left ∥ right)`).
If the computed root matches the checkpoint's root hash, the proof is
valid.

```bash
# You can also fetch by tree index
./bin/mtc-assertion fetch -index 1 -output /tmp/bundle1.json
./bin/mtc-assertion inspect -input /tmp/bundle1.json

# Or fetch in PEM format
./bin/mtc-assertion fetch -serial $SERIAL -format pem
```

### Step 10 — Browse Certificates in the Admin UI

The admin dashboard includes a certificate browser with search:

```bash
open http://localhost:8080/admin/certs
```

Features:
- **Search** by serial number or cert ID
- **Status badges** showing Active (green) or Revoked (red)
- **Detail pages** with parsed X.509 metadata, inclusion proof, and
  download links for JSON/PEM assertion bundles

### Step 11 — View Assertion Issuer Statistics

The assertion issuer (Phase 2) automatically pre-computes assertion
bundles in the background after each checkpoint. Check its progress:

```bash
# View aggregate assertion statistics
curl -s $MTC_URL/assertions/stats | python3 -m json.tool
```

Example output:

```json
{
  "total_bundles": 500,
  "fresh_bundles": 500,
  "stale_bundles": 0,
  "pending_entries": 7468,
  "last_generated": "2026-02-28T13:09:28Z"
}
```

- **`total_bundles`** — assertion bundles generated so far
- **`fresh_bundles`** — bundles with up-to-date inclusion proofs
- **`stale_bundles`** — bundles needing proof refresh (tree has grown)
- **`pending_entries`** — log entries without a bundle yet
- **`last_generated`** — timestamp of the last generation cycle

The issuer processes `batch_size` entries (default: 100) per checkpoint
cycle (~60 seconds). Over time it converges to full coverage of the log.

### Step 12 — Poll for Recently Generated Assertions

Downstream consumers (e.g., an ACME server) can poll for newly generated
assertion bundles:

```bash
# Get bundles generated since checkpoint 0 (all)
curl -s "$MTC_URL/assertions/pending?since=0&limit=5" | python3 -m json.tool
```

Example output:

```json
{
  "since": 0,
  "count": 5,
  "entries": [
    {
      "entry_idx": 1,
      "serial_hex": "5BF2A7443A479D5600C6220D369208E325F31C62",
      "checkpoint_id": 42,
      "assertion_url": "/assertion/1",
      "created_at": "2026-02-28T13:09:28Z"
    }
  ]
}
```

Each entry includes a direct `assertion_url` to fetch the full bundle.
Use the `since` parameter as a cursor — track the latest `checkpoint_id`
you've seen and pass it as `since` on the next poll.

### Step 13 — View Assertion Issuer in the Admin Dashboard

The admin dashboard includes an Assertion Issuer metrics section:

```bash
open http://localhost:8080/admin/
```

The dashboard shows two stats grids:
- **Log Statistics** — tree size, checkpoints, entries, revocations
- **Assertion Issuer** — total bundles, fresh/stale/pending counts,
  last generation time, and cycle duration

These update automatically via HTMX polling.

### Step 14 — Run the Full Conformance Suite

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
  assertion_bundle_json          [PASS]
  assertion_bundle_pem           [PASS]
  assertion_verify_proof         [PASS]
  assertion_auto_generation      [PASS]
  assertion_polling              [PASS]
  assertion_stats                [PASS]
  acme_directory                 [PASS]
  acme_nonce                     [PASS]
  acme_new_account               [PASS]
  acme_new_order                 [PASS]
  acme_order_flow                [PASS]
  acme_full_mtc_flow             [PASS]

Results: 23 passed, 0 failed, 0 skipped
```

### Step 15 — ACME Server: Directory & Nonce

The ACME server runs on a separate port (default 8443) and implements
RFC 8555 for automated certificate issuance.

```bash
export ACME_URL="https://localhost:8443"

# Fetch the ACME directory (-k for self-signed TLS cert)
curl -sk $ACME_URL/acme/directory | python3 -m json.tool
```

Example output:

```json
{
  "newAccount": "https://localhost:8443/acme/new-account",
  "newNonce": "https://localhost:8443/acme/new-nonce",
  "newOrder": "https://localhost:8443/acme/new-order",
  "meta": {
    "externalAccountRequired": false,
    "website": "https://localhost:8443"
  }
}
```

```bash
# Get a replay-protection nonce
curl -skI $ACME_URL/acme/new-nonce | grep -i replay-nonce
```

### Step 16 — ACME Order Lifecycle (via conformance test)

The ACME conformance tests exercise the full order lifecycle:

1. **Create account** — JWS-signed POST with ephemeral ECDSA P-256 key
2. **Create order** — Request certificate for DNS identifiers
3. **Get authorization** — Retrieve http-01 challenge for each identifier
4. **Trigger validation** — POST to challenge URL (auto-approved in dev mode)
5. **Poll order** — Wait for status to transition from `pending` → `ready`
6. **Finalize** — Submit CSR; ACME server proxies to DigiCert CA
7. **Download certificate** — Get PEM certificate with appended assertion bundle

Run just the ACME tests:

```bash
./bin/mtc-conformance -url http://localhost:8080 -acme-url https://localhost:8443 -verbose 2>&1 | grep acme
```

```
  acme_directory                 [PASS]
  acme_nonce                     [PASS]
  acme_new_account               [PASS]
  acme_new_order                 [PASS]
  acme_order_flow                [PASS]
  acme_full_mtc_flow             [PASS]
```

The `acme_full_mtc_flow` test exercises the **complete MTC pipeline**: ACME account
creation → order → challenge → CSR finalize (proxied to DigiCert CA) → poll until
the watcher ingests the cert into the Merkle tree → assertion issuer builds the
inclusion proof → certificate download with MTC assertion bundle attached.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/checkpoint` | Latest signed checkpoint (C2SP signed-note format) |
| GET | `/tile/<L>/<N>` | Merkle hash tile at level L, index N |
| GET | `/tile/entries/<N>` | Entry bundle tile at index N |
| GET | `/proof/inclusion?serial=<hex>[&index=<n>]` | Inclusion proof for a certificate by serial number |
| GET | `/assertion/{query}` | Assertion bundle as JSON (query by index or serial hex) |
| GET | `/assertion/{query}/pem` | Assertion bundle in PEM-like text format |
| GET | `/assertions/pending?since=<id>&limit=N` | Pre-computed bundles since a checkpoint (polling) |
| GET | `/assertions/stats` | Assertion statistics: total, fresh, stale, pending counts |
| GET | `/revocation` | Revocation bitfield (binary) |
| GET | `/admin/` | HTMX admin dashboard |
| GET | `/admin/certs` | Certificate browser with search |
| GET | `/admin/certs/{index}` | Certificate detail page with assertion bundle |
| GET | `/admin/viz` | Visualization explorer (Sunburst, Treemap, Proof Explorer) |
| GET | `/admin/viz/summary` | Aggregated certificate hierarchy JSON for visualization |
| GET | `/admin/viz/certificates` | Paginated leaf-level certificates JSON |
| GET | `/admin/viz/revocations` | Revoked entry indices JSON |
| GET | `/admin/viz/stats` | Aggregate visualization statistics JSON |
| GET | `/admin/viz/proof/{index}` | Merkle inclusion proof tree data for a leaf index |
| GET | `/healthz` | Health check |

### ACME Server Endpoints (port 8443)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/acme/directory` | ACME directory (RFC 8555 §7.1.1) |
| HEAD/GET | `/acme/new-nonce` | Get a fresh anti-replay nonce |
| POST | `/acme/new-account` | Create or lookup an account (JWS with JWK) |
| POST | `/acme/new-order` | Create a new certificate order |
| POST | `/acme/order/{id}` | Get order status |
| POST | `/acme/authz/{id}` | Get authorization with challenges |
| POST | `/acme/challenge/{id}` | Trigger challenge validation |
| POST | `/acme/order/{id}/finalize` | Submit CSR to finalize order |
| POST | `/acme/certificate/{id}` | Download certificate + assertion bundle PEM |

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

### Assertion Bundle Response (`/assertion/{query}`)

```json
{
  "leaf_index": 42,
  "serial_hex": "5BF2A7443A479D5600C6220D369208E325F31C62",
  "cert_der": "<base64 DER>",
  "cert_meta": {
    "common_name": "example.com",
    "organization": ["My Org"],
    "sans": ["example.com"],
    "serial_number": "5BF2A7...",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z",
    "key_algorithm": "RSA",
    "signature_algorithm": "SHA256-RSA",
    "is_ca": false
  },
  "leaf_hash": "<hex SHA-256>",
  "proof": ["<hex hash>", "..."],
  "tree_size": 7968,
  "root_hash": "<hex SHA-256>",
  "checkpoint": "<signed checkpoint>",
  "revoked": false,
  "log_origin": "localhost/mtc-bridge"
}
```

The `cert_meta` field provides parsed X.509 metadata including subject,
issuer, SANs, key usage, validity period, and more — extracted from the
raw DER certificate without requiring any external parsing tools.

### Assertion Polling Response (`/assertions/pending`)

```json
{
  "since": 42,
  "count": 3,
  "entries": [
    {
      "entry_idx": 100,
      "serial_hex": "5BF2A7443A479D5600C6220D369208E325F31C62",
      "checkpoint_id": 43,
      "assertion_url": "/assertion/100",
      "created_at": "2026-02-28T13:09:28Z"
    }
  ]
}
```

Use `since` as a cursor — pass the latest `checkpoint_id` you've processed
to get only new bundles. The `assertion_url` field provides a direct link
to fetch the full bundle.

### Assertion Stats Response (`/assertions/stats`)

```json
{
  "total_bundles": 500,
  "fresh_bundles": 500,
  "stale_bundles": 0,
  "pending_entries": 7468,
  "last_generated": "2026-02-28T13:09:28Z"
}
```

---

## Project Structure

```
cmd/
  mtc-bridge/          Main service binary
  mtc-conformance/     Conformance test client (23 tests)
  mtc-assertion/       CLI tool: fetch, verify, inspect assertion bundles
internal/
  acme/                RFC 8555 ACME server (JWS, nonce, accounts, orders, challenges, CA proxy)
  admin/               HTMX dashboard + certificate browser + visualization explorer
  assertion/           Assertion bundle builder + JSON/PEM formatter
  assertionissuer/     Background assertion generation pipeline + webhooks
  cadb/                Read-only MariaDB adapter for DigiCert CA
  certutil/            X.509 DER parser for certificate metadata extraction
  config/              YAML config with env-var substitution
  cosigner/            Ed25519 key management + checkpoint signing
  issuancelog/         Entry construction + Merkle tree maintenance
  merkle/              RFC 9162 Merkle tree operations + inclusion proofs
  revocation/          Revocation bitfield construction
  store/               PostgreSQL state store (11 tables, search/detail/assertion/ACME queries)
  tlogtiles/           C2SP tlog-tiles HTTP handler + proof + assertion API
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
- **`assertion_issuer`** — Assertion generation pipeline (batch size, concurrency, webhooks)
- **`acme`** — ACME server settings (port, CA proxy URL, API key, CA/template IDs, auto-approve)
- **`http`** — Listen address, timeouts, cache TTLs

Environment variables can override config values (see `docker-compose.yml` for
the full list).

---

## Running Tests

```bash
# Unit tests (44+ tests across merkle, config, cosigner, certutil, tlogtiles packages)
make test

# Conformance tests (23 tests, requires a running mtc-bridge instance)
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

## Fully Automated End-to-End Demo

This project provides a scriptable, reproducible demo of the complete ACME-to-MTC pipeline:
ACME certificate request → DigiCert CA issuance → Merkle tree ingestion → assertion proof
generation → certificate download with MTC assertion bundle attached.

### Prerequisites
- Fill in your secrets and config values in `.env` (copy from `.env.example`)
- Ensure Docker and Docker Compose are installed
- DigiCert Private CA and MariaDB available on the Docker network (see docker-compose.yml)

### Environment Variables (`.env`)

```bash
# Required — DigiCert Private CA credentials
CA_API_KEY=your-api-key-here
CA_ID=your-ca-id-here
CA_TEMPLATE_ID=your-template-id-here
CA_URL=http://digicert-ca:8080     # Docker service name

# Database credentials (defaults usually work)
MTC_POSTGRES_PASSWORD=mtcbridge
MTC_CADB_HOST=ca-db
MTC_CADB_PORT=3306
MTC_CADB_USERNAME=caadmin
MTC_CADB_PASSWORD=capassword
MTC_CADB_DATABASE=digicert_ca
```

### Steps
1. Generate demo TLS certs for the ACME server:
   ```bash
   ./gen-demo-cert.sh
   ```
2. Start all services:
   ```bash
   docker compose up -d
   ```
3. Verify everything is healthy:
   ```bash
   docker compose ps          # all containers should be "Up"
   curl -s http://localhost:8080/healthz  # {"status":"ok"}
   curl -sk https://localhost:8443/acme/directory | python3 -m json.tool
   ```
4. Run the conformance suite (includes full MTC flow):
   ```bash
   make build
   ./bin/mtc-conformance -url http://localhost:8080 -acme-url https://localhost:8443 -verbose
   ```
   All 23 tests pass, including `acme_full_mtc_flow` which exercises the complete pipeline.
5. Or run the end-to-end demo script:
   ```bash
   ./demo-e2e.sh
   ```

### Docker Deployment Notes

The Docker Compose setup runs three containers:
- **postgres** — PostgreSQL 16 state store for the Merkle tree
- **mtc-bridge** — main service (watcher, tree builder, assertion issuer, HTTP API on :8080)
- **acme-server** — ACME server (RFC 8555 on :8443 with TLS)

Configuration uses environment variable substitution (`${VAR:-default}` in config.yaml),
so the same config file works for both local development and Docker deployment. Docker
services communicate via Docker DNS names (e.g., `postgres`, `digicert-ca`, `ca-db`).

### What the Full MTC Flow Demonstrates

1. **ACME Account Creation** — ES256 JWS-signed request, account stored by JWK thumbprint
2. **Order + Authorization** — DNS identifier order with http-01 challenge (auto-approved for internal CA)
3. **CSR Finalize** — RSA-2048 CSR proxied to DigiCert Private CA REST API
4. **Certificate Issuance** — DigiCert CA issues the certificate, returns serial number
5. **Merkle Tree Ingestion** — Watcher detects the new cert in MariaDB, appends to Merkle tree
6. **Assertion Proof Generation** — Assertion issuer builds inclusion proof bundle at next checkpoint
7. **Certificate Download** — ACME certificate endpoint returns X.509 PEM + MTC assertion bundle

The assertion bundle contains the Merkle inclusion proof, leaf index, log origin, and
signed checkpoint — everything needed to independently verify the certificate's presence
in the transparency log.

See the script output and admin UI (`http://localhost:8080/admin/`) for verification.
