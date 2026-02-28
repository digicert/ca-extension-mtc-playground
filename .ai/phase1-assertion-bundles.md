# Phase 1 — Assertion Bundle API & Certificate Browser

## Overview

Phase 1 added **assertion bundles** — self-contained proof artifacts that package a certificate together with its Merkle inclusion proof, signed checkpoint, and parsed X.509 metadata. These bundles allow any third party to independently verify that a specific certificate exists in the MTC issuance log without needing to understand the tlog-tiles protocol or reconstruct proofs from raw tiles.

Phase 1 also added a **certificate browser** to the admin dashboard, an **`mtc-assertion` CLI tool**, and **X.509 metadata extraction** from DER-encoded certificates.

## What Was Built

### New Packages

| Package | Purpose |
|---|---|
| `internal/certutil` | X.509 DER parser — extracts human-readable metadata (CN, SANs, key usage, validity, issuer, etc.) from raw certificate bytes. Stdlib only, no internal dependencies. |
| `internal/assertion` | Assertion bundle builder + formatter. Constructs bundles from store data, formats as JSON or PEM, verifies inclusion proofs. |

### New Binary

| Binary | Purpose |
|---|---|
| `cmd/mtc-assertion` | Standalone CLI for fetching, verifying, and inspecting assertion bundles. Three subcommands: `fetch`, `verify`, `inspect`. Shares zero code with the server (stdlib + crypto/sha256 only). |

### Modified Packages

| Package | Changes |
|---|---|
| `internal/store` | Added `SearchEntries()`, `GetEntryDetail()`, `RecentEntries()` with LEFT JOIN on revoked_indices for status. Added index on `log_entries(ca_cert_id)`. |
| `internal/tlogtiles` | Added `GET /assertion/{query}` (JSON) and `GET /assertion/{query}/pem` routes. Handler now accepts `logOrigin` parameter. |
| `internal/admin` | Added certificate browser (`/admin/certs`), HTMX search (`/admin/certs/search`), detail pages (`/admin/certs/{index}`). Fixed stats panel layout for responsive display. |
| `cmd/mtc-bridge` | Plumbed `logOrigin` to tlogtiles and admin handlers. Added `/assertion/` route to main mux. |
| `cmd/mtc-conformance` | Added 3 new tests: `assertion_bundle_json`, `assertion_bundle_pem`, `assertion_verify_proof`. Now 14 total. |

## New API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/assertion/{query}` | Assertion bundle as JSON. Query by leaf index (numeric) or serial hex. |
| GET | `/assertion/{query}/pem` | Assertion bundle in PEM-like text format with human-readable headers. |
| GET | `/admin/certs` | Certificate browser page with HTMX search. |
| GET | `/admin/certs/search?q=` | HTMX fragment endpoint — returns table rows matching the query. |
| GET | `/admin/certs/{index}` | Certificate detail page with parsed metadata, inclusion proof, and download links. |

## Assertion Bundle Structure (JSON)

```json
{
  "leaf_index": 42,
  "serial_hex": "5BF2A7443A479D5600C6220D369208E325F31C62",
  "cert_der": "<base64 DER-encoded certificate>",
  "cert_meta": {
    "common_name": "example.com",
    "organization": ["My Org"],
    "sans": ["example.com", "www.example.com"],
    "serial_number": "5BF2A7...",
    "issuer_cn": "My Root CA",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z",
    "key_algorithm": "RSA",
    "signature_algorithm": "SHA256-RSA",
    "key_usage": "Digital Signature",
    "ext_key_usage": ["Server Authentication"],
    "is_ca": false
  },
  "leaf_hash": "<hex SHA-256>",
  "proof": ["<hex sibling hash>", "..."],
  "tree_size": 7968,
  "root_hash": "<hex SHA-256>",
  "checkpoint": "<full signed checkpoint text>",
  "revoked": false,
  "log_origin": "localhost/mtc-bridge",
  "created_at": "2026-02-27T18:07:06Z"
}
```

## Assertion Bundle Structure (PEM)

```
-----BEGIN MTC ASSERTION BUNDLE-----
Log-Origin: localhost/mtc-bridge
Leaf-Index: 1
Tree-Size: 7968
Root-Hash: c838a8b9d03f79f80cfe5929a59e463b...
Leaf-Hash: db444b3cf985dbc1a5483cd763057ed8...
Serial: 5BF2A7443A479D5600C6220D369208E325F31C62
Revoked: false

<signed checkpoint>

<base64 proof hashes, one per line>

<base64 DER certificate, 76-char lines>
-----END MTC ASSERTION BUNDLE-----
```

## How Verification Works

The `mtc-assertion verify` command (and `assertion.Verify()` function) performs RFC 9162 inclusion proof verification:

1. Start with the **leaf hash** from the bundle
2. For each sibling hash in the **proof** array, combine using the interior hash function:
   - If current index is even: `SHA-256(0x01 || current || sibling)`
   - If current index is odd: `SHA-256(0x01 || sibling || current)`
   - Divide index by 2 and continue
3. Compare the computed root against the **root hash** in the bundle
4. The root hash is anchored by the **signed checkpoint** (Ed25519 signature)

This allows offline, independent verification without contacting the server.

## Store Query Design

The new store methods use LEFT JOIN against `revoked_indices` to annotate each entry with its revocation status in a single query:

```sql
SELECT le.idx, le.serial_hex, le.ca_cert_id, le.entry_data, le.created_at,
       ri.idx IS NOT NULL AS revoked, ri.revoked_at
FROM log_entries le
LEFT JOIN revoked_indices ri ON le.idx = ri.idx
WHERE le.serial_hex ILIKE $1 OR le.ca_cert_id = $2
ORDER BY le.idx DESC
LIMIT $3
```

A new index `idx_log_entries_ca_cert_id` on `log_entries(ca_cert_id)` supports efficient cert ID lookups.

## certutil Package

`internal/certutil` is a leaf package with zero internal dependencies. It parses DER-encoded X.509 certificates using only `crypto/x509` and extracts:

- Subject: CN, Organization, OU, Country, Province, Locality
- Issuer: CN, Organization
- SANs: DNS names, IP addresses, email addresses, URIs
- Validity: NotBefore, NotAfter
- Key info: algorithm, signature algorithm
- Usage: KeyUsage (bitmask → human-readable), ExtKeyUsage
- CA status: IsCA flag
- Distribution: CRL endpoints, OCSP servers, issuing cert URLs

`ParseLogEntry()` also handles the MTC log entry wire format: `[uint16 LE type][uint32 LE length][DER blob]`.

## mtc-assertion CLI

```
mtc-assertion <command> [options]

Commands:
  fetch      Fetch an assertion bundle from a running mtc-bridge server
  verify     Verify an assertion bundle's inclusion proof
  inspect    Display human-readable details of an assertion bundle

Fetch options:
  -url       Base URL of mtc-bridge server (default: http://localhost:8080)
  -serial    Certificate serial number (hex)
  -index     Log entry index
  -format    Output format: json or pem (default: json)
  -output    Output file (default: stdout)

Verify options:
  -input     Path to assertion bundle JSON file

Inspect options:
  -input     Path to assertion bundle JSON file
```

The CLI shares zero code with the server — it uses only stdlib and `crypto/sha256`. This is intentional: a verifier should not need to trust any of the server's code.

## Admin Certificate Browser

The certificate browser at `/admin/certs` provides:

- **Real-time search** via HTMX — type a serial number and results update with 300ms debounce
- **Status badges** — green "Active" or red "Revoked" for each entry
- **Detail pages** at `/admin/certs/{index}` showing:
  - Parsed X.509 metadata (subject, issuer, SANs, key usage, validity)
  - Inclusion proof details (leaf hash, tree size, root hash, proof hashes)
  - Revocation status and timestamp if applicable
  - Download links for JSON and PEM assertion bundles
  - Raw certificate in PEM format

## Test Coverage

| Type | Count | Description |
|---|---|---|
| Unit tests (certutil) | 6 | ParseDER, ParseLogEntry, null/short entries, formatKeyUsage, formatSerial |
| Conformance tests | 3 new (14 total) | assertion_bundle_json, assertion_bundle_pem, assertion_verify_proof |

## Demo Commands

```bash
# Fetch assertion bundle by index
curl -s http://localhost:8080/assertion/1 | python3 -m json.tool

# Fetch by serial number
curl -s http://localhost:8080/assertion/5BF2A7443A479D5600C6220D369208E325F31C62

# PEM format
curl -s http://localhost:8080/assertion/1/pem

# CLI workflow
./bin/mtc-assertion fetch -index 1 -output /tmp/bundle.json
./bin/mtc-assertion verify -input /tmp/bundle.json
./bin/mtc-assertion inspect -input /tmp/bundle.json

# Browse certificates
open http://localhost:8080/admin/certs

# Run conformance (14/14)
make conformance
```

## Files Added/Modified

```
Added:
  internal/certutil/parse.go          X.509 metadata extraction
  internal/certutil/parse_test.go     Unit tests for certutil
  internal/assertion/bundle.go        Bundle builder (BuildBySerial, BuildByIndex, Resolve)
  internal/assertion/format.go        JSON/PEM formatters + Verify function
  cmd/mtc-assertion/main.go           CLI tool (fetch, verify, inspect)

Modified:
  internal/store/store.go             SearchEntries, GetEntryDetail, RecentEntries, new index
  internal/tlogtiles/handler.go       /assertion/{query} and /assertion/{query}/pem routes
  internal/admin/handler.go           Certificate browser handlers, stats panel layout fix
  internal/admin/templates.go         certBrowserHTML, certDetailStartHTML/EndHTML, responsive grid
  cmd/mtc-bridge/main.go              logOrigin plumbing, /assertion/ route
  cmd/mtc-conformance/main.go         3 new assertion conformance tests
  Makefile                            bin/mtc-assertion build target
  README.md                           Assertion docs, updated API table, demo walkthrough
```
