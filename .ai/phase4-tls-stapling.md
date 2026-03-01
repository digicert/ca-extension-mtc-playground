# Phase 4 — TLS Assertion Stapling Demo

## Overview

Phase 4 adds two standalone CLI binaries — `cmd/mtc-tls-server` and `cmd/mtc-tls-verify` — that demonstrate MTC assertion stapling in TLS handshakes. The server fetches an assertion bundle from the running mtc-bridge instance and staples it to every TLS connection via the `SignedCertificateTimestamps` extension field. The client connects, extracts the assertion, and verifies the Merkle inclusion proof against the bridge's checkpoint.

Neither binary accesses the database directly. They are pure HTTP clients of the mtc-bridge API, importing only `internal/assertion` (for the `Bundle` type and `Verify()` function).

## What Was Built

### New Binaries

| Binary | Purpose |
|---|---|
| `cmd/mtc-tls-server` | HTTPS server that staples MTC assertions via the SCT TLS extension |
| `cmd/mtc-tls-verify` | CLI client that extracts and verifies the stapled assertion |

### Modified Files

| File | Changes |
|---|---|
| `Makefile` | Added `mtc-tls-server` and `mtc-tls-verify` to build target, added `demo-tls` target |
| `Dockerfile` | Added build + copy steps for both binaries, exposed port 4443 |
| `README.md` | Added Phase 4 TLS section, updated project structure and feature tables |
| `.ai/build-plan.md` | Updated Phase 4 from "DEFERRED" to "COMPLETE" |

### New Files

| File | Purpose |
|---|---|
| `demo-tls.sh` | Automated end-to-end demo: issues cert, waits for assertion, runs server + verifier |

## Architecture

### TLS Delivery Mechanism

The MTC spec (§6) defines a custom TLS extension for carrying assertion data. Go's `crypto/tls` does not support custom server-side TLS extensions (golang/go#51497). Instead, we use `tls.Certificate.SignedCertificateTimestamps` — a `[][]byte` field that Go's TLS implementation sends to clients during the handshake.

```
┌──────────────────────┐        ┌──────────────────────┐
│  mtc-tls-server      │        │  mtc-tls-verify      │
│                      │  TLS   │                      │
│  1. Load cert+key    │ ─────► │  1. TLS handshake    │
│  2. Fetch assertion  │        │  2. Extract SCT data │
│     from bridge API  │        │  3. Parse as Bundle   │
│  3. Staple as SCT    │        │  4. Verify proof     │
│  4. Serve HTTPS      │        │  5. Check checkpoint │
│                      │        │  6. Print report     │
└───────┬──────────────┘        └───────┬──────────────┘
        │                               │
        │ GET /assertion/{serial}       │ GET /checkpoint
        ▼                               ▼
┌──────────────────────────────────────────────┐
│              mtc-bridge (:8080)               │
│   Assertion API + Checkpoint endpoint        │
└──────────────────────────────────────────────┘
```

### SCT Payload Format

To minimize TLS handshake size, the stapled payload is a lightweight JSON structure that omits `cert_der` and `cert_meta` (the client already has the certificate from the handshake):

```json
{
  "leaf_index": 42,
  "serial_hex": "AB12CD34...",
  "leaf_hash": "5b9a1e9e...",
  "proof": ["305170f5...", "08f1f04d..."],
  "tree_size": 8192,
  "root_hash": "c838a8b9...",
  "checkpoint": "localhost/mtc-bridge\n8192\n...",
  "revoked": false,
  "log_origin": "localhost/mtc-bridge"
}
```

Typical payload size: ~500-800 bytes (depends on proof depth / tree size).

### Background Refresh

The TLS server periodically re-fetches the assertion (default: every 60s) to pick up fresh proofs as the Merkle tree grows. This uses a `sync.RWMutex` — TLS handshakes take the read lock, the refresh goroutine takes the write lock.

### Verification Checks

The verifier performs 5 checks:

| # | Check | Implementation |
|---|-------|---------------|
| 1 | Assertion present in TLS handshake | `len(ConnectionState.SignedCertificateTimestamps) > 0` |
| 2 | Certificate serial matches assertion | Compare formatted `PeerCertificates[0].SerialNumber` against `bundle.SerialHex` |
| 3 | Merkle inclusion proof valid | `assertion.Verify(bundle)` — calls `merkle.VerifyInclusion` internally |
| 4 | Root hash matches checkpoint | Fetch `/checkpoint`, parse tree size + root hash, compare |
| 5 | Certificate not revoked | Check `bundle.Revoked` field |

For check 4, if the tree has grown since the proof was generated, the root hashes won't match exactly. The verifier handles this by checking `bundle.TreeSize <= checkpoint.TreeSize` — the proof is still valid against its own tree size (verified in check 3).

## Major Design Decisions

### 1. SCT field for assertion transport

The `SignedCertificateTimestamps` field is the most natural fit — it's designed for carrying transparency proofs, works with standard Go, and clients can read it from `ConnectionState()`. This repurposes CT's SCT mechanism for MTC, which is acceptable for a demo. In production, a custom TLS extension would be more appropriate.

### 2. Lightweight staple payload

The full assertion bundle can be several KB (includes DER certificate and parsed metadata). Since the TLS client already has the certificate from the handshake itself, we strip `cert_der` and `cert_meta` from the stapled JSON. This keeps the SCT payload under 1KB.

### 3. HTTP API clients, not database clients

Both binaries communicate with mtc-bridge via its HTTP API (`/assertion/{serial}`, `/checkpoint`). They don't import `internal/store` or access PostgreSQL directly. This keeps Phase 4 entirely decoupled from bridge internals and means the binaries can run on different machines.

### 4. Graceful degradation

The TLS server starts and serves connections even when no assertion is available yet. The background refresh will eventually pick it up. The verifier reports `[FAIL] Assertion not present` rather than crashing, giving clear diagnostic output.

### 5. Port 4443

The TLS server listens on `:4443` by default to avoid collisions with the ACME server (`:8443`) and the main bridge (`:8080`).

## File Locations

| File | What |
|---|---|
| `cmd/mtc-tls-server/main.go` | TLS server: assertion fetch, SCT stapling, status page, background refresh |
| `cmd/mtc-tls-verify/main.go` | Verification client: TLS handshake, proof extraction, checkpoint comparison, report output |
| `demo-tls.sh` | Automated demo: cert issuance, assertion wait, server start, verification |

## Reused Code

| Package/Function | Used For |
|---|---|
| `assertion.Bundle` (assertion/bundle.go) | JSON serialization/deserialization of the stapled payload |
| `assertion.Verify()` (assertion/format.go:94) | Merkle inclusion proof verification |
| `certutil.formatSerial` pattern (certutil/parse.go:110) | Certificate serial number formatting |
| Checkpoint parsing (conformance/main.go:193) | Parsing tree size + root hash from checkpoint text |
