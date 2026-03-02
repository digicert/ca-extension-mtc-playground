# MTC Bridge — 4-Phase Build Plan

## Background

This roadmap was developed after researching how MTC assertion bundles can be delivered to web servers without modifying the DigiCert Private CA itself. The chosen approach is **post-issuance stapling** — mtc-bridge watches the CA for new certificates, constructs Merkle inclusion proofs, and delivers them as assertion bundles that can be stapled to TLS handshakes.

The plan implements Phases 1-3 fully, then pauses at Phase 4 (TLS handshake integration requires TLS library modifications beyond our current scope).

---

## Phase 1 — Assertion Bundle API & Certificate Browser (COMPLETE)

**Goal:** On-demand assertion bundles — any party can fetch a proof for any certificate in the log.

**Delivered:**
- `internal/certutil` — X.509 DER metadata extraction (stdlib only)
- `internal/assertion` — bundle builder, JSON/PEM formatter, proof verifier
- `cmd/mtc-assertion` — standalone CLI (fetch, verify, inspect)
- `GET /assertion/{query}` and `/assertion/{query}/pem` API endpoints
- Admin certificate browser with search and status filters
- 3 new conformance tests (14 total)
- Store search/detail methods with revocation status

**Status:** Committed as `8fea50a` on `main`.

See [phase1-assertion-bundles.md](phase1-assertion-bundles.md) for full details.

---

## Phase 2 — MTC Assertion Issuer (COMPLETE)

**Goal:** Proactive assertion generation — automatically pre-compute and cache assertion bundles as certificates enter the log, keep them fresh as the tree grows, and provide delivery mechanisms.

**Motivation:** Phase 1 builds bundles on-demand per request. Phase 2 shifts to a pipeline model where bundles are pre-computed after each checkpoint, stored persistently, and available for push (webhook) or pull (polling) delivery. This is the prerequisite for Phase 3's ACME integration.

### Deliverables

1. **Assertion store** (`internal/store`)
   - New PostgreSQL table `assertion_bundles` to persist pre-computed bundles
   - Columns: entry_idx, serial_hex, checkpoint_id, tree_size, bundle_json, bundle_pem, created_at, stale (bool)
   - Methods: UpsertBundle, GetBundle, ListPendingEntries, MarkStale, GetFreshBundles

2. **Issuer pipeline** (`internal/assertionissuer`)
   - New package that runs as a background goroutine alongside the watcher
   - After each checkpoint event, scans for log entries without fresh bundles
   - Batch-generates assertion bundles using `assertion.Builder`
   - Stores results via the assertion store
   - Configurable concurrency and batch size

3. **Proof freshness management**
   - When the tree grows (new checkpoint with larger tree_size), existing proofs become stale
   - Mark all bundles with tree_size < current as stale
   - Regeneration prioritizes recent entries, then works backward
   - Configurable staleness threshold (e.g., regenerate if proof is >N checkpoints old)

4. **Webhook notifications** (`internal/assertionissuer`)
   - Optional POST callback when new assertions are ready
   - Configurable URL patterns (per-domain, per-serial pattern, or global)
   - Payload: list of {serial, index, assertion_url} for newly generated bundles
   - Retry with exponential backoff (3 attempts)
   - Config section: `assertion_issuer.webhooks[]`

5. **Polling endpoint** (`internal/tlogtiles`)
   - `GET /assertions/pending?since=<checkpoint_id>&limit=N` — returns bundles generated since a given checkpoint
   - `GET /assertions/stats` — JSON stats for monitoring
   - Designed for Phase 3 ACME server to poll for new assertions

6. **Admin dashboard metrics** (`internal/admin`)
   - Assertion issuance stats: total issued, pending, stale, last generation time
   - Generation rate and average latency
   - Display on existing dashboard stats panel

7. **Conformance tests** (`cmd/mtc-conformance`)
   - `assertion_auto_generation` — verify bundles appear after new certs are ingested
   - `assertion_freshness` — verify stale bundles are regenerated after checkpoint
   - `assertion_polling` — verify polling endpoint returns correct results

### Configuration

```yaml
assertion_issuer:
  enabled: true
  batch_size: 100          # entries per generation batch
  concurrency: 4           # parallel bundle builders
  staleness_threshold: 5   # regenerate if proof is >N checkpoints old
  webhooks:
    - url: "https://example.com/mtc-webhook"
      pattern: "*.example.com"    # match CN/SAN pattern
      secret: "webhook-secret"    # HMAC-SHA256 signature header
```

### Data Flow

```
Watcher detects new cert → appends to log → new checkpoint created
                                                      │
                                                      ▼
                                            Assertion Issuer
                                            ┌─────────────┐
                                            │ scan for     │
                                            │ entries w/o  │
                                            │ fresh bundle │
                                            │              │
                                            │ batch build  │
                                            │ assertions   │
                                            │              │
                                            │ store in DB  │
                                            │              │
                                            │ fire webhooks│
                                            └──────┬───────┘
                                                   │
                                    ┌──────────────┼──────────────┐
                                    ▼              ▼              ▼
                              Webhook POST    Polling API    Admin Stats
                              (push)          (pull)         (monitoring)
```

---

## Phase 3 — ACME Server Integration (COMPLETE)

**Goal:** Deliver assertion bundles to web servers via the ACME protocol, so servers can staple MTC proofs to TLS handshakes without manual intervention.

**Delivered:**
- `internal/acme` — RFC 8555 ACME server (6 files, 1,173 lines)
  - JWS verification (ES256 + RS256), nonce management, account/order/authorization/challenge handlers
  - CA proxy (finalize → DigiCert CA REST API), assertion bundle waiting
  - Certificate download with appended assertion bundle PEM
- 4 ACME tables in `internal/store` with 6 indexes and ~16 CRUD methods
- `ACMEConfig` in `internal/config` with 12 fields and sensible defaults
- Wired into `cmd/mtc-bridge` on separate port (:8443)
- 5 new conformance tests (22 total)
- Auto-approve challenge mode for internal CA development

**Status:** Committed on `main`.

See [phase3-acme-server.md](phase3-acme-server.md) for full details.

---

## Phase 4 — TLS Assertion Stapling Demo (COMPLETE)

**Goal:** Demonstrate MTC assertion delivery through a TLS handshake, completing the full transparency pipeline from CA issuance through client-side proof verification.

**Delivered:**
- `cmd/mtc-tls-server` — HTTPS server that fetches assertion bundles from mtc-bridge and staples them to TLS handshakes via the `SignedCertificateTimestamps` extension field
- `cmd/mtc-tls-verify` — CLI client that connects, extracts the assertion, and verifies the Merkle inclusion proof against the bridge's checkpoint
- `demo-tls.sh` — Automated end-to-end demo script
- Background assertion refresh with thread-safe access
- 5-point verification: assertion presence, serial match, proof validity, checkpoint match, revocation status

**Approach:** Go's `crypto/tls` doesn't support custom TLS extensions (golang/go#51497). The demo uses `tls.Certificate.SignedCertificateTimestamps` to carry the assertion JSON — repurposing CT's SCT delivery mechanism for MTC.

**Status:** Committed on `main`.

See [phase4-tls-stapling.md](phase4-tls-stapling.md) for full details.

### Remaining TLS Scope (not implemented)

- Custom TLS extension per MTC §6 (requires `crypto/tls` fork or uTLS)
- Signatureless certificates per MTC §4
- Browser relying-party verification per MTC §8

---

## Phase 5 — Embedded MTC Inclusion Proofs in X.509 Certificates (COMPLETE)

**Goal:** Embed Merkle inclusion proofs directly into X.509 certificates as a custom extension, solving the "chicken-and-egg" problem where the proof needs to be in the certificate but the certificate must exist to compute its hash.

**Delivered:**
- `internal/localca` — Local intermediate CA package (3 files, ~450 lines)
  - `extension.go` — OID `1.3.6.1.4.1.99999.1.1`, ASN.1 marshal/unmarshal, embedded proof verification
  - `canonical.go` — TBSCertificate DER extraction, MTC extension stripping
  - `localca.go` — ECDSA P-256 CA: `IssuePrecert`, `IssueWithProof`, `GenerateCA`
  - `localca_test.go` — 10 tests (ASN.1 round-trip, canonical reconstruction, full Merkle verification)
- `internal/issuancelog` — `EntryTypePrecert=2`, `BuildPrecertEntry`, `AppendDirectEntry`
- `internal/acme/finalize.go` — `processFinalizeLocalCA` two-phase signing flow
- `internal/config` — `LocalCAConfig` struct
- `internal/store` — `final_cert_der` + `ca_cert_der` columns, getter/setter methods
- `cmd/mtc-verify-cert` — Standalone offline verification CLI
- `demo-embedded-proof.sh` — Automated demo script
- `-generate-local-ca` flag on `mtc-bridge` binary + Makefile target

**Approach:** Two-phase signing following CT pre-certificate pattern (RFC 6962):
1. Issue pre-cert (no MTC extension) → hash canonical TBSCertificate into tree
2. Create immediate checkpoint → compute inclusion proof
3. Re-sign with identical template + MTC extension → final certificate
4. Verifiers strip extension → reconstruct canonical form → verify proof offline

**Status:** Committed on `main`.

---

## Timeline & Dependencies

```
Phase 1 (DONE) ──► Phase 2 (DONE) ──► Phase 3 (DONE) ──► Phase 4 (DONE) ──► Phase 5 (DONE)
```

- Phase 2 depends on Phase 1's assertion package and store methods
- Phase 3 depends on Phase 2's polling endpoint and assertion store
- Phase 4 depends on Phase 3 for end-to-end cert + assertion delivery
- Phase 5 depends on Phase 3's ACME server and Phase 2's issuance log
- All 5 phases complete
