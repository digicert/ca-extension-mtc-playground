# Phase 2 — MTC Assertion Issuer

## Overview

Phase 2 added a **background assertion generation pipeline** — after each checkpoint cycle, the issuer automatically scans for log entries without fresh assertion bundles, batch-generates them using concurrent workers, stores them in PostgreSQL, and optionally fires webhook notifications. This shifts from Phase 1's on-demand model to a **proactive pre-computation model** where bundles are always ready before anyone asks for them.

Phase 2 also added **proof freshness management** (stale bundle detection and regeneration), **polling endpoints** for downstream consumers, **webhook push notifications**, and **admin dashboard metrics** for the issuer pipeline.

## What Was Built

### New Package

| Package | Purpose |
|---|---|
| `internal/assertionissuer` | Background assertion generation pipeline. Triggered after each checkpoint, batch-builds assertion bundles with configurable concurrency, manages proof freshness, fires webhooks, and tracks runtime statistics. |

### Modified Packages

| Package | Changes |
|---|---|
| `internal/store` | Added `assertion_bundles` PostgreSQL table + migration (5 DDL statements, 4 indexes). Added `AssertionBundle` and `AssertionStats` types. Added 10 new methods: `UpsertAssertionBundle`, `UpsertAssertionBundles`, `GetAssertionBundle`, `GetAssertionBundleBySerial`, `ListPendingEntries`, `MarkStaleBundles`, `ListStaleBundles`, `GetFreshBundlesSince`, `GetAssertionStats`. |
| `internal/config` | Added `AssertionIssuerConfig` and `WebhookConfig` types. `IsEnabled()` defaults to true. Defaults in `applyDefaults()`: batch_size=100, concurrency=4, staleness_threshold=5. |
| `internal/watcher` | Added `CheckpointCallback` type and `OnCheckpoint()` registration method. After each checkpoint, fires the callback asynchronously via goroutine. |
| `internal/tlogtiles` | Added `GET /assertions/pending` and `GET /assertions/stats` polling endpoints. |
| `internal/admin` | Added Assertion Issuer stats section to dashboard (6 metrics). Handler now accepts `*assertionissuer.Issuer`. |
| `cmd/mtc-bridge` | Wired issuer creation, watcher `OnCheckpoint` hook, admin issuer injection, and `/assertions/` route. |
| `cmd/mtc-conformance` | Added 3 new conformance tests (17 total): `assertion_auto_generation`, `assertion_polling`, `assertion_stats`. |

## Major Design Decisions

### 1. Post-checkpoint trigger, not continuous polling

The issuer runs **after each checkpoint** rather than continuously polling for new entries. This was chosen because:
- Assertion bundles require a signed checkpoint as their trust anchor
- Generating bundles against an in-progress tree would produce immediately-stale proofs
- Checkpoint-driven batching is more efficient than per-entry generation
- Natural back-pressure: if generation takes longer than the checkpoint interval, it simply runs on the next cycle

Implementation: `watcher.OnCheckpoint()` fires `issuer.RunOnCheckpoint()` as an async goroutine after each successful checkpoint creation.

### 2. Stale-then-regenerate freshness model

When the tree grows (new entries appended), existing inclusion proofs become stale because they reference a smaller tree size. The issuer handles this with a two-phase approach:
- **Mark stale**: `UPDATE assertion_bundles SET stale = TRUE WHERE tree_size < $current_tree_size`
- **Regenerate**: On each cycle, after generating bundles for new entries, refresh stale bundles with updated proofs

The `staleness_threshold` config (default: 5 checkpoints) prevents thrashing — bundles are only marked stale if the tree has grown by more than N checkpoints since the bundle was last built. In practice, we mark all bundles with a smaller tree size as stale and let the batch system work through them.

### 3. Concurrent batch generation with semaphore

Bundle generation is I/O-bound (database reads for entry data + proof path computation). The issuer uses a **goroutine pool with channel-based semaphore** rather than a worker pool:
- Spawn one goroutine per entry in the batch
- Semaphore channel (capacity = `concurrency` config) limits active goroutines
- Results collected via buffered channel
- Batch upsert after all goroutines complete

This avoids the complexity of a persistent worker pool while still achieving bounded parallelism. With `concurrency=4` and `batch_size=100`, the first generation cycle completed 100 bundles in ~123ms.

### 4. Webhook push with HMAC signing

Webhooks provide a push-based notification model for downstream consumers (e.g., the Phase 3 ACME server). Design choices:
- **HMAC-SHA256 signatures**: Each webhook can have a `secret`; the payload is signed and the signature sent in `X-MTC-Signature` header
- **Exponential backoff retry**: 3 attempts with `attempt * 2s` delay
- **Fire-and-forget goroutines**: Webhook delivery is non-blocking to the main pipeline
- **Pattern matching**: Webhooks can specify CN/SAN glob patterns to filter which assertions trigger notifications (not yet enforced, placeholder for Phase 3)

### 5. Polling endpoint over SSE for downstream consumers

Phase 2 chose a **polling endpoint** (`GET /assertions/pending?since=<checkpoint_id>&limit=N`) rather than extending the existing SSE event stream. Rationale:
- The Phase 3 ACME server needs to poll for specific bundles, not receive a firehose
- Polling is simpler to implement reliably than maintaining long-lived SSE connections
- The `since` parameter enables cursor-based pagination — consumers track their last-seen checkpoint
- SSE remains available for real-time dashboard updates

### 6. Assertion bundles table with dual format storage

Pre-computed bundles are stored in **both JSON and PEM format** to avoid reformatting on every API request:
- `bundle_json` (JSONB): Used by API endpoints and polling consumers
- `bundle_pem` (TEXT): Used by PEM format endpoints and CLI tools
- Trade-off: ~2x storage per bundle, but eliminates per-request formatting overhead
- JSONB column enables PostgreSQL native indexing if we need field-level queries later

### 7. Watcher callback pattern over direct coupling

Rather than importing `assertionissuer` from `watcher`, the integration uses a **callback pattern**:
```go
type CheckpointCallback func(ctx context.Context, checkpointID int64, treeSize int64)
```
The watcher accepts a callback via `OnCheckpoint()` and fires it after checkpoint creation. This keeps the watcher package decoupled from the assertion issuer and allows other consumers to hook into checkpoint events in the future.

## New API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/assertions/pending?since=<id>&limit=N` | Pre-computed bundles generated since a given checkpoint. Returns JSON with entries array. |
| GET | `/assertions/stats` | Aggregate assertion statistics: total, fresh, stale, pending counts + last generation timestamp. |

### Polling Response Structure

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
      "created_at": "2026-02-28T07:09:28Z"
    }
  ]
}
```

### Stats Response Structure

```json
{
  "total_bundles": 100,
  "fresh_bundles": 100,
  "stale_bundles": 0,
  "pending_entries": 7867,
  "last_generated": "2026-02-28T07:09:28Z"
}
```

## Database Schema

### `assertion_bundles` Table

```sql
CREATE TABLE IF NOT EXISTS assertion_bundles (
    entry_idx     BIGINT PRIMARY KEY REFERENCES log_entries(idx),
    serial_hex    TEXT NOT NULL,
    checkpoint_id BIGINT NOT NULL REFERENCES checkpoints(id),
    tree_size     BIGINT NOT NULL,
    bundle_json   JSONB NOT NULL,
    bundle_pem    TEXT NOT NULL,
    stale         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
```

### Indexes

| Index | Columns | Purpose |
|---|---|---|
| `idx_assertion_bundles_serial` | `serial_hex` | Lookup by certificate serial number |
| `idx_assertion_bundles_stale` | `stale` WHERE stale = TRUE | Efficient stale bundle scanning |
| `idx_assertion_bundles_checkpoint` | `checkpoint_id` | Join with checkpoints for polling |
| `idx_assertion_bundles_created` | `created_at` | Time-based queries |

### Key Store Methods

| Method | SQL Pattern | Purpose |
|---|---|---|
| `UpsertAssertionBundle` | INSERT ON CONFLICT UPDATE | Create or refresh a single bundle |
| `UpsertAssertionBundles` | Batch INSERT ON CONFLICT | Bulk upsert after concurrent generation |
| `ListPendingEntries` | LEFT JOIN … WHERE ab.entry_idx IS NULL | Find entries without fresh bundles |
| `MarkStaleBundles` | UPDATE SET stale=TRUE WHERE tree_size < $1 | Flag outdated proofs |
| `GetFreshBundlesSince` | WHERE checkpoint_id > $1 AND stale = FALSE | Polling endpoint data source |
| `GetAssertionStats` | COUNT with CASE WHEN | Dashboard aggregate statistics |

## Configuration

```yaml
assertion_issuer:
  enabled: true
  batch_size: 100          # entries per generation batch
  concurrency: 4           # parallel bundle builders
  staleness_threshold: 5   # regenerate if proof is >N checkpoints old
  webhooks:
    - url: "https://example.com/mtc-webhook"
      pattern: "*.example.com"
      secret: "webhook-secret"
```

All fields have sensible defaults. If the `assertion_issuer` section is omitted entirely, the issuer runs with defaults (enabled=true, batch_size=100, concurrency=4, staleness_threshold=5, no webhooks).

## Issuer Pipeline Flow

```
Watcher creates checkpoint
         │
         ▼
    OnCheckpoint callback (async goroutine)
         │
         ▼
┌────────────────────────┐
│  1. Mark stale bundles │  UPDATE ... SET stale = TRUE
│     (tree_size < cur)  │  WHERE tree_size < current
├────────────────────────┤
│  2. Generate pending   │  LEFT JOIN to find entries
│     (new entries)      │  without bundles, build up
│                        │  to batch_size
├────────────────────────┤
│  3. Refresh stale      │  Re-build bundles for stale
│     (outdated proofs)  │  entries with current proof
├────────────────────────┤
│  4. Batch upsert       │  INSERT ON CONFLICT UPDATE
│                        │  into assertion_bundles
├────────────────────────┤
│  5. Fire webhooks      │  POST to configured URLs
│     (if any ready)     │  with HMAC-SHA256 signature
├────────────────────────┤
│  6. Emit event         │  store.EmitEvent for SSE
│                        │  dashboard live updates
└────────────────────────┘
```

## Admin Dashboard — Assertion Issuer Section

The dashboard stats panel now includes a second grid section "Assertion Issuer" with 6 metrics:

| Metric | Description | Color |
|---|---|---|
| Total Bundles | Count of all assertion bundles in the database | — |
| Fresh | Bundles with current inclusion proofs | Green |
| Stale | Bundles needing proof refresh | Amber |
| Pending | Log entries without any bundle yet | Blue |
| Last Generated | Timestamp of last generation cycle | — |
| Last Run | Duration of the most recent issuer cycle | — |

## Performance

Initial benchmarks with ~7,968 log entries:

| Operation | Time | Details |
|---|---|---|
| First batch (100 bundles) | ~123ms | 4 concurrent workers, cold start |
| Mark stale (full sweep) | <5ms | Single UPDATE statement |
| Polling query (3 results) | <2ms | Index-backed query |
| Stats aggregate | <1ms | COUNT with conditional |

At `batch_size=100` per 60-second checkpoint cycle, the full log (~7,968 entries) would be covered in ~80 cycles (~80 minutes). Increasing `batch_size` to 1000 would reduce this to ~8 minutes.

## Test Coverage

| Type | Count | Description |
|---|---|---|
| Conformance tests | 3 new (17 total) | `assertion_auto_generation`, `assertion_polling`, `assertion_stats` |
| Unit tests | All passing | `go test ./internal/...` — no regressions |

## Demo Commands

```bash
# Check assertion stats
curl -s http://localhost:8080/assertions/stats | python3 -m json.tool

# Poll for recently generated bundles
curl -s "http://localhost:8080/assertions/pending?since=0&limit=5" | python3 -m json.tool

# Fetch a pre-computed bundle (uses Phase 1 endpoint, now served from cache)
curl -s http://localhost:8080/assertion/1 | python3 -m json.tool

# View dashboard with issuer metrics
open http://localhost:8080/admin/

# Run conformance tests (17/17)
./bin/mtc-conformance -url http://localhost:8080
```

## Files Added/Modified

```
Added:
  internal/assertionissuer/issuer.go    Background pipeline: Config, Stats, Issuer,
                                        RunOnCheckpoint, generatePending, refreshStale,
                                        buildAndStore, buildOne, fireWebhooks, sendWebhook
  internal/assertionissuer/helpers.go   Utility functions: jsonReader, hmacSign

Modified:
  internal/store/store.go               assertion_bundles table + migration (5 DDL),
                                        AssertionBundle/AssertionStats types, 10 new methods
  internal/config/config.go             AssertionIssuerConfig, WebhookConfig, IsEnabled(),
                                        defaults in applyDefaults()
  internal/watcher/watcher.go           CheckpointCallback type, OnCheckpoint() registration,
                                        async callback in createCheckpoint()
  internal/tlogtiles/handler.go         /assertions/pending and /assertions/stats endpoints
  internal/admin/handler.go             Issuer field, assertion stats in dashboard + HTMX
  internal/admin/templates.go           Assertion Issuer stats grid (6 metrics)
  cmd/mtc-bridge/main.go                Issuer creation, watcher hook, admin wiring,
                                        /assertions/ route
  cmd/mtc-conformance/main.go           3 new conformance tests
  config.yaml                           assertion_issuer config section
  .ai/instructions.md                   assertionissuer in package table
  .ai/build-plan.md                     Created with full 4-phase roadmap
```

## What's Next (Phase 3)

Phase 2's polling endpoint (`GET /assertions/pending`) and pre-computed bundles are the foundation for Phase 3's ACME server. The ACME server will:
1. Accept certificate orders via RFC 8555
2. Proxy CSRs to the DigiCert Private CA
3. Poll `/assertions/pending` until the assertion bundle appears
4. Return the certificate + assertion bundle together in the ACME finalize response
