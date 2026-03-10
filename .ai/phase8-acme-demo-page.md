# Phase 8 — Browser-Based ACME Enrollment Demo Page

## Overview

Phase 8 adds an **interactive ACME enrollment demo page** to the admin dashboard at `/admin/acme-demo`. The page runs a complete RFC 8555 certificate enrollment flow entirely from the browser using the Web Crypto API, displays the issued certificate with a visual X.509 breakdown, and verifies both the Merkle inclusion proof and consistency proof — all client-side.

This eliminates the need for CLI tools (`mtc-conformance`, `demo-acme.sh`) when demonstrating the ACME→MTC pipeline, making it accessible to non-technical stakeholders and enabling live demos from any browser.

## Design Decisions

### 1. Reverse Proxy for ACME Requests

**Problem:** The ACME server runs on HTTPS port 8443 with self-signed TLS certificates. Browser JavaScript on the admin dashboard (HTTP port 8080) cannot call the ACME server due to: (a) CORS policy (no Access-Control headers configured), and (b) self-signed TLS certificate rejection.

**Decision:** Add a reverse proxy at `/admin/acme-proxy/*` in the admin handler on port 8080 that forwards requests to the ACME server. Uses `httputil.NewSingleHostReverseProxy` with `http.StripPrefix` and `InsecureSkipVerify: true` transport.

**Alternatives considered:**
- Adding CORS headers to ACME server — still blocked by self-signed TLS cert in browser
- Running ACME on same port — breaks separation of concerns and existing architecture
- Passing ACME handler directly to admin — tighter coupling than a proxy

**Trade-off:** The proxy adds ~30 lines of Go code and one network hop (localhost→localhost), but completely solves both CORS and TLS issues transparently.

### 2. ECDSA P-256 for Both Keys

**Decision:** Use ECDSA P-256 for both the ACME account key (JWS signing) and the certificate key (CSR). The conformance tests use different keys (ES256 for account, RSA-2048 for CSR), but P-256 for both simplifies the browser implementation because:
- Web Crypto API natively supports P-256 key generation and signing
- The CSR ASN.1 encoding for P-256 is simpler than RSA (65-byte uncompressed point vs variable-length modulus)
- The ACME server accepts ES256 JWS (verified in `internal/acme/jws.go`)

### 3. Inline ASN.1 CSR Builder (No External Library)

**Problem:** Web Crypto API has no CSR generation capability. Need to build a PKCS#10 CertificationRequest DER.

**Decision:** Implement a minimal inline ASN.1 DER encoder in ~120 lines of JavaScript. The CSR structure for ECDSA P-256 with a single DNS SAN extension is fixed and compact.

**Alternatives considered:**
- `@peculiar/x509` CDN — could generate CSRs, but adds a heavy dependency for one operation
- Server-side CSR generation — requires sending the private key to the server, defeats the demo purpose
- `forge` (node-forge) CDN — large bundle, not maintained actively

**Key OIDs:**
- `1.2.840.10045.2.1` (ecPublicKey)
- `1.2.840.10045.3.1.7` (prime256v1 / P-256)
- `1.2.840.10045.4.3.2` (ecdsaWithSHA256)
- `2.5.29.17` (subjectAltName)
- `1.2.840.113549.1.9.14` (extensionRequest)

### 4. X.509 Certificate Visualizer via PKI.js

**Decision:** Use `pkijs` + `asn1js` (PeculiarVentures) from CDN for client-side certificate parsing and visualization.

**Why these libraries:**
- MIT licensed, actively maintained by PeculiarVentures
- Used by Mozilla Firefox for certificate handling
- Available via unpkg CDN — no build step needed
- Can parse PEM→full X.509 field extraction (subject, issuer, extensions, public key, signature algorithm)
- Specifically handles custom OIDs well (important for `id-alg-mtcProof` OID `1.3.6.1.4.1.44363.47.0`)

**CDN dependencies (4 scripts):**
```html
<script src="https://unpkg.com/asn1js@3.0.5/build/asn1.min.js"></script>
<script src="https://unpkg.com/pvtsutils@1.3.5/build/index.js"></script>
<script src="https://unpkg.com/pvutils@1.1.3/build/utils.min.js"></script>
<script src="https://unpkg.com/pkijs@3.2.4/build/index.min.js"></script>
```

**Fallback:** If CDN libraries fail to load, display raw PEM with a note. The ACME demo flow still works — only the visual X.509 breakdown degrades.

**Alternatives considered:**
- `jsrsasign` — lighter but less actively maintained, weaker extension parsing
- `@lapo/asn1js` — great for raw ASN.1 tree view but not structured certificate fields
- Server-side parsing — defeats the "everything in browser" goal

### 5. Proof Verification After Enrollment

**Decision:** After downloading the certificate, automatically fetch and display both:
- **Inclusion proof** via existing `GET /proof/inclusion?serial=<hex>` — proves the certificate is in the Merkle tree
- **Consistency proof** via existing `GET /proof/consistency?old=M&new=N` — proves the tree grew honestly (append-only) since before the enrollment started

These endpoints are on port 8080 (same origin as the dashboard), so no proxy is needed.

**Client-side verification:** The JavaScript recomputes the Merkle root from the leaf hash and proof hashes using `SHA-256(0x01 || left || right)` via Web Crypto `SubtleCrypto.digest()`, then compares against the checkpoint's root hash.

### 6. ECDSA Signature Format Conversion

**Problem:** Web Crypto's `ECDSA` sign operation returns DER-encoded signatures (`SEQUENCE { INTEGER r, INTEGER s }`), but ACME ES256 requires raw 64-byte `r||s` format (per `internal/acme/jws.go` lines 207-211).

**Decision:** Include a `derToRaw()` function that parses the DER SEQUENCE and extracts/zero-pads r and s to exactly 32 bytes each. This is a well-understood conversion (~15 lines of code).

### 7. JWS URL Field vs Proxy Path

**Problem:** The ACME server validates that the JWS protected header's `url` field matches `ExternalURL + request_path` (see `internal/acme/jws.go` line 70). But the browser sends requests to the proxy path (`/admin/acme-proxy/acme/...`), not the ACME server path.

**Decision:** The JavaScript puts the real ACME ExternalURL in the JWS `url` field (e.g., `https://localhost:8443/acme/new-account`), while sending the HTTP request to the proxy path (`/admin/acme-proxy/acme/new-account`). The proxy strips `/admin/acme-proxy`, so the ACME server sees the request at `/acme/new-account` and the URL check passes.

The ACME ExternalURL is passed to the template as a Go template variable `{{ .ACMEExternalURL }}`.

## What Will Be Built

### New Package/Files

| File | Lines | Purpose |
|---|---|---|
| `.ai/phase8-acme-demo-page.md` | ~200 | This design document |

### Modified Files

| File | Changes |
|---|---|
| `internal/admin/handler.go` | Add `acmeURL` field to Handler struct. Update `New()` to accept ACME external URL. Add `handleACMEDemo()` handler. Add `acmeProxy()` reverse proxy method. Register two new routes. New imports: `net/http/httputil`, `net/url`, `crypto/tls`. |
| `internal/admin/templates.go` | Add `acmeDemoHTML` template constant (~1000 lines: HTML + inline JS). Update nav bar in 4 existing templates to include "ACME Demo" link. |
| `cmd/mtc-bridge/main.go` | Pass `cfg.ACME.ExternalURL` to `admin.New()` call. |

### Demo Page: 15 Steps

**ACME Enrollment (Steps 1-12):**

| Step | Title | Method |
|---|---|---|
| 1 | Generate Account Key Pair | Web Crypto `generateKey` (ECDSA P-256) |
| 2 | Fetch ACME Directory | `GET /acme/directory` |
| 3 | Get Initial Nonce | `HEAD /acme/new-nonce` |
| 4 | Create Account | JWS POST with `jwk` to `/acme/new-account` |
| 5 | Create Order | JWS POST with `kid` to `/acme/new-order` |
| 6 | Fetch Authorization | POST-as-GET to authorization URL |
| 7 | Respond to Challenge | POST `{}` to challenge URL (auto-approved) |
| 8 | Poll Order Status | POST-as-GET until `status: ready` |
| 9 | Generate Certificate Key Pair | Web Crypto `generateKey` (ECDSA P-256) |
| 10 | Build CSR | Inline PKCS#10 DER with SAN extension |
| 11 | Finalize Order | JWS POST CSR, poll until `status: valid` |
| 12 | Download Certificate | POST-as-GET to certificate URL (PEM text) |

**Proof Verification (Steps 13-15):**

| Step | Title | Method |
|---|---|---|
| 13 | Fetch Inclusion Proof | `GET /proof/inclusion?serial=<hex>` |
| 14 | Fetch Consistency Proof | `GET /proof/consistency?old=M&new=N` |
| 15 | Verify Proofs | Client-side SHA-256 hash chain verification |

### Results Section (3 Tabs)

**Certificate Tab:**
- Visual X.509 breakdown (Subject, Issuer, Validity, Serial, Signature Algorithm, Public Key, Extensions)
- Special highlighting for `id-alg-mtcProof` signature algorithm
- Raw PEM display (collapsible)

**Inclusion Proof Tab:**
- Leaf index, tree size, leaf hash, root hash
- Proof path with L/R sibling indicators
- Client-side verification: PASS/FAIL badge
- Signed checkpoint (collapsible)

**Consistency Proof Tab:**
- Old tree size → New tree size
- Old root → New root
- Proof hashes (numbered)
- Append-only verification: PASS/FAIL badge

## Reused Existing Code

| Component | Location | How Reused |
|---|---|---|
| Inclusion proof endpoint | `internal/tlogtiles/handler.go` `handleInclusionProof()` | Called directly from JS (same origin) |
| Consistency proof endpoint | `internal/tlogtiles/handler.go` `handleConsistencyProof()` | Called directly from JS (same origin) |
| Checkpoint endpoint | `internal/tlogtiles/handler.go` `handleCheckpoint()` | Parsed in JS to get tree size before/after |
| Nav bar pattern | `internal/admin/templates.go` all 4 templates | Copied and extended with ACME Demo link |
| Card/grid styling | All admin templates | Reused Tailwind patterns: `bg-white rounded-lg shadow p-6` |
| ACME JWS format | `internal/acme/jws.go` `verifyJWS()` | JS mirrors the exact JWS structure the server validates |
| ACME order flow | `internal/acme/handlers.go` + `finalize.go` | JS follows the exact endpoint sequence |

## Prerequisites

- ACME server must be enabled (`acme.enabled: true` in config.yaml)
- Auto-approve challenge mode recommended for demo (`acme.auto_approve_challenge: true`)
- Local CA mode recommended (`local_ca.enabled: true`) — otherwise finalize proxies to DigiCert CA
- For consistency proof: the tree must have at least 1 entry before the demo runs

## Testing

1. `make build` — verify compilation
2. `make test` — verify existing unit tests pass
3. Start service with ACME + local CA enabled
4. Open `http://localhost:8080/admin/acme-demo`
5. Click "Run Demo" — all 15 steps should show green checkmarks
6. Verify X.509 visualizer shows parsed certificate fields
7. Verify inclusion proof with client-side PASS
8. Verify consistency proof with client-side PASS
9. Check nav links from all dashboard pages
10. Test with ACME disabled — graceful "not configured" message
