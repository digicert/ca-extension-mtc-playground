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

## Phase 3 — ACME Server Integration

**Goal:** Deliver assertion bundles to web servers via the ACME protocol, so servers can staple MTC proofs to TLS handshakes without manual intervention.

### Approach

Build a lightweight ACME server (RFC 8555 subset) that:
1. Accepts standard ACME certificate orders
2. Proxies the CSR to DigiCert Private CA for issuance
3. Waits for mtc-bridge to ingest the cert and generate an assertion bundle
4. Returns the certificate + assertion bundle together in the ACME finalize response

### Key Design Decisions

- **Post-issuance stapling**: The ACME server does NOT modify the CA. It issues a normal X.509 cert, then waits for the assertion pipeline (Phase 2) to produce a proof.
- **Polling loop**: After cert issuance, the ACME server polls `GET /assertions/pending` until the bundle appears (typically <60s).
- **Bundle delivery**: The assertion bundle is returned as an additional field in the ACME order object, or as a separate download URL.
- **Challenge types**: Initially support `http-01` only. DNS challenges can be added later.

### Deliverables

1. `internal/acme` — ACME server implementation (RFC 8555 subset)
   - Directory, newNonce, newAccount, newOrder, authz, challenge, finalize, certificate
   - JWS request validation
   - http-01 challenge verification
2. `cmd/mtc-acme` — standalone ACME server binary (or integrated into mtc-bridge)
3. Config section for ACME endpoints, CA proxy settings
4. Integration tests with a standard ACME client (certbot or lego)
5. Conformance tests for ACME protocol basics

### Data Flow

```
ACME Client (certbot/lego)
    │
    ▼
mtc-acme Server (:8443)
    │
    ├── newOrder → create order, return authz
    ├── challenge → verify http-01
    ├── finalize → proxy CSR to DigiCert CA
    │               │
    │               ▼
    │         DigiCert CA issues cert
    │               │
    │               ▼
    │         mtc-bridge watcher ingests cert
    │               │
    │               ▼
    │         Assertion issuer generates bundle
    │               │
    │               ▼
    └── certificate → return cert + assertion bundle
```

---

## Phase 4 — TLS Handshake Integration (DEFERRED)

**Goal:** Enable web servers to staple MTC assertion bundles into the TLS 1.3 handshake, allowing clients to verify certificate transparency inline.

### Why Deferred

- Requires modifications to TLS libraries (Go's `crypto/tls` or OpenSSL)
- MTC §6 defines a new TLS extension and Certificate message format
- Browser/client-side relying-party logic also needed
- Significantly more complex than Phases 1-3

### Future Scope

1. TLS 1.3 extension for MTC assertion delivery (MTC §6)
2. Modified Certificate message with assertion bundle
3. Go TLS server integration (patched `crypto/tls`)
4. Client-side verification library
5. Browser extension proof-of-concept

---

## Timeline & Dependencies

```
Phase 1 (DONE) ──► Phase 2 (assertion issuer)
                        │
                        ▼
                   Phase 3 (ACME server) ──► Phase 4 (TLS, deferred)
```

- Phase 2 depends on Phase 1's assertion package and store methods
- Phase 3 depends on Phase 2's polling endpoint and assertion store
- Phase 4 depends on Phase 3 for end-to-end cert + assertion delivery
- Phases 1-3 are implemented continuously; Phase 4 paused pending TLS ecosystem readiness
