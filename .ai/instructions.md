# MTC Bridge — AI Guidance

## Project Purpose

**mtc-bridge** is a standalone Go service that runs alongside a DigiCert Private CA, watches the CA's MariaDB database for new certificate issuances and revocations, constructs and maintains an MTC-compliant issuance log (a Merkle Tree over all issued certificates per IETF draft-ietf-plants-merkle-tree-certs-01), and exposes it via the C2SP tlog-tiles HTTP API. It also provides an admin dashboard for monitoring.

This is an **experimental/internal** implementation — simplified scope (no external cosigners, no TLS 1.3 integration, no signatureless certificate construction for TLS handshakes). The focus is on the issuance log, Merkle tree integrity, HTTP tile serving, and revocation tracking.

## Key Spec References

- **MTC Draft**: [draft-ietf-plants-merkle-tree-certs-01](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-01.html)
- **tlog-tiles**: [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) — HTTP API for serving Merkle tree tiles
- **RFC 9162**: [Certificate Transparency v2](https://www.rfc-editor.org/rfc/rfc9162) — Merkle Tree Hash definitions
- **C2SP signed-note**: [Signed Note](https://c2sp.org/signed-note) — Checkpoint signature format
- **C2SP tlog-checkpoint**: [Checkpoint](https://c2sp.org/tlog-checkpoint) — Checkpoint text format

## Architecture Summary

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
                            │  │ metrics     │  │    /admin/...
                            │  └─────────────┘  │
                            └──────────────────┘
```

## Package Responsibilities

| Package | One-liner |
|---|---|
| `cmd/mtc-bridge` | Main entry point: parse config, wire dependencies, start HTTP + watcher |
| `cmd/mtc-conformance` | Independent conformance test client (shares ZERO code with internal/) |
| `cmd/mtc-assertion` | CLI tool: fetch, verify, inspect assertion bundles (shares ZERO code with server) |
| `internal/merkle` | RFC 9162 Merkle tree core: hashing, proofs, subtrees, tile computation |
| `internal/config` | YAML configuration loading with env var substitution |
| `internal/store` | PostgreSQL state store: log entries, tree nodes, checkpoints, events, cert search |
| `internal/cadb` | MariaDB adapter for the DigiCert CA database (read-only) |
| `internal/cosigner` | Ed25519 key management + MTC subtree/checkpoint signing |
| `internal/issuancelog` | Issuance log management: TBSCertificateLogEntry construction, append, tree update |
| `internal/revocation` | Revocation-by-index tracking: serial→index mapping, range compaction |
| `internal/watcher` | Background polling loop: CA DB → issuance log → checkpoint |
| `internal/tlogtiles` | HTTP handlers for the C2SP tlog-tiles API + assertion bundle API |
| `internal/admin` | Admin dashboard + certificate browser: Go templates + HTMX, SSE for live events |
| `internal/assertion` | Assertion bundle builder + JSON/PEM formatter + proof verifier |
| `internal/certutil` | X.509 DER parser for certificate metadata extraction (stdlib only) |
| `internal/assertionissuer` | Background assertion generation pipeline: batch build, freshness tracking, webhooks |
| `internal/acme` | RFC 8555 ACME server: JWS verification, nonce management, account/order/challenge handlers, CA proxy, certificate+assertion delivery |

## Critical Invariants

1. **Append-only log**: Entries MUST never be deleted or modified once appended. The log is append-only.
2. **Index 0 is null_entry**: Per MTC §5.3, the first entry (index 0) MUST be of type `null_entry` to avoid zero serial numbers.
3. **Leaf hash**: `SHA-256(0x00 || entry_bytes)` per RFC 9162 §2.1.1
4. **Interior hash**: `SHA-256(0x01 || left_hash || right_hash)` per RFC 9162 §2.1.1
5. **Subtree validity**: `[start, end)` where `start` is a multiple of `BIT_CEIL(end - start)` per MTC §4.1
6. **Tile width**: Full tiles are exactly 256 hashes (8192 bytes). Partial tiles are 1-255 hashes.
7. **Checkpoint format**: C2SP signed-note format with Ed25519 signature
8. **Log entry format**: `MerkleTreeCertEntry` = type (uint16 BE) + body per MTC §5.3
9. **TBSCertificateLogEntry**: Issuer MUST be the log ID as PKIX DN; `subjectPublicKeyInfoHash` = SHA-256 of the SPKI DER
10. **CA DB is read-only**: mtc-bridge NEVER writes to the DigiCert CA database

## CA Database Details (DigiCert Private CA)

- **Engine**: MariaDB 10.11.16
- **Database**: `digicert_ca`
- **Key table**: `certificate` — columns: `id` (PK), `serial_number`, `cert_blob` (DER), `valid_from`, `valid_to`, `created_date`, `is_revoked`, `revoked_date`, `revoked_reason`, `issuer_id`
- **CA table**: `ca` — columns: `id`, `name`, `cert_type` (root/intermediate), `status`, `cert_blob`
- **Ordering**: Use `created_date` + `id` for cursor-based polling (no auto-increment, IDs are UUIDs)
- **Revocation**: `is_revoked` boolean on certificate table, with `revoked_date` and `revoked_reason`
- **~7,966 existing certificates** as of 2026-02-27

## Naming Conventions

- Go standard: `camelCase` for unexported, `PascalCase` for exported
- No abbreviations except well-known: MTC, TLS, CA, DB, DER, PEM, SPKI, DN, HTTP, SSE
- Test files mirror source: `foo.go` → `foo_test.go`
- Table-driven tests with `t.Run` subtests named after the scenario
- Error wrapping: `fmt.Errorf("context: %w", err)`

## Concurrency Model

- The watcher goroutine owns a mutex on the log append path
- Tile reads from PostgreSQL are lock-free (read-only queries against committed data)
- SSE event broadcast via a channel-based fan-out
- HTTP handlers are stateless — all state comes from PostgreSQL queries

## Error Handling

- Never panic in library code
- Wrap errors with `fmt.Errorf("package.Function: %w", err)`
- Use `log/slog` structured logging — never `fmt.Printf` in library code
- All public methods take `context.Context` as first argument

## Testing Strategy

Four tiers + conformance client:
1. **Unit tests** (`make test-unit`): Pure Go, no external deps
2. **Integration tests** (`make test-integration`): testcontainers-go for MariaDB + PostgreSQL
3. **E2E tests** (`make test-e2e`): Full docker-compose stack
4. **CLI verify commands** (`mtc-bridge verify ...`): Operator-facing verification
5. **Conformance client** (`mtc-conformance`): Independent standards validation — shares ZERO code with internal/

## Links to ADRs

- [ADR-001: Go language choice](../docs/adr/001-go-language-choice.md)
- [ADR-002: Simplified MTC scope](../docs/adr/002-simplified-mtc-scope.md)
- [ADR-003: PostgreSQL state store](../docs/adr/003-postgres-state-store.md)
- [ADR-004: MariaDB CA adapter](../docs/adr/004-mariadb-ca-adapter.md)
- [ADR-005: Ed25519 cosigner](../docs/adr/005-ed25519-cosigner.md)
- [ADR-006: HTMX admin dashboard](../docs/adr/006-htmx-admin-dashboard.md)
- [ADR-007: tlog-tiles serving protocol](../docs/adr/007-tlog-tiles-serving-protocol.md)
- [ADR-008: Conformance test isolation](../docs/adr/008-conformance-test-isolation.md)

## Phase Guides

- [Build Plan: 4-Phase Roadmap](build-plan.md)
- [Phase 1: Assertion Bundle API](phase1-assertion-bundles.md)
- [Phase 2: MTC Assertion Issuer](phase2-assertion-issuer.md)
- [Phase 1: Assertion Bundle API & Certificate Browser](phase1-assertion-bundles.md)
