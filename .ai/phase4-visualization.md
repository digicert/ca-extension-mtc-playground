# Phase 4 — Visualization Explorer

## Overview

Phase 4 added an interactive **certificate visualization module** to the admin dashboard at `/admin/viz`. It provides three views — **Sunburst**, **Treemap**, and **Proof Explorer** — for exploring the Merkle tree certificate distribution across CAs, batch windows, and key algorithms, with drill-down navigation, revocation highlighting, assertion coverage overlays, and interactive Merkle proof rendering.

All rendering uses HTML5 Canvas (no external charting libraries). The frontend is a single Go template constant (`vizExplorerHTML`) with embedded JavaScript (~1000 lines), following the project's existing pattern of keeping all templates in `internal/admin/templates.go`.

## What Was Built

### Modified Packages

| Package | Changes |
|---|---|
| `internal/store` | Added `cert_metadata` cache table migration + 2 indexes. Added `VizSummary`, `VizCertificate`, `VizStats` types. Added 4 new methods: `PopulateCertMetadata`, `GetVizSummary`, `GetVizCertificates`, `GetVizStats`. Added helpers: `isPQAlgorithm`, `batchWindowTime`, `vizCAColor`. |
| `internal/admin` | Added `caNames map[string]string` field to Handler. Updated `New()` signature to accept CA name map. Added 6 routes and handlers: `handleVisualization`, `handleVizSummary`, `handleVizCertificates`, `handleVizRevocations`, `handleVizStats`, `handleVizProof`. Added `vizExplorerHTML` template. Added "Visualization" nav link to all 3 existing templates. |
| `cmd/mtc-bridge` | Built `caNameMap` from `caAdapter.GetCAs()`, passed to `admin.New()`. |

### No New Packages

Everything fits in existing files: `store.go`, `handler.go`, `templates.go`, `main.go`.

## Architecture

### Data Pipeline

```
log_entries (DER blobs)
    │
    ▼  PopulateCertMetadata() — incremental, 1000 at a time
cert_metadata (denormalized cache)
    │
    ▼  GetVizSummary() — single aggregation query
VizSummary tree (JSON) ──► JavaScript Canvas rendering
```

**Why `cert_metadata`?** The visualization needs to group by key algorithm, which is buried inside DER-encoded certificates in `log_entries.entry_data`. Parsing thousands of DER blobs per request is impractical. The cache table parses each certificate once via `certutil.ParseLogEntry()` and stores the extracted fields for efficient GROUP BY queries.

**Incremental population:** `PopulateCertMetadata` selects unpopulated entries via LEFT JOIN, processes up to 1000 per call in a single transaction, and is triggered asynchronously when the visualization page loads. Multiple invocations drain the backlog.

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS cert_metadata (
    entry_idx     BIGINT PRIMARY KEY REFERENCES log_entries(idx),
    ca_cert_id    TEXT NOT NULL,
    ca_name       TEXT NOT NULL DEFAULT '',
    key_algorithm TEXT NOT NULL,
    sig_algorithm TEXT NOT NULL,
    common_name   TEXT NOT NULL DEFAULT '',
    is_pq         BOOLEAN NOT NULL DEFAULT FALSE,
    batch_window  TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- `batch_window`: `created_at` truncated to 6-hour intervals
- `is_pq`: true if algorithm contains ML-DSA, ML-KEM, SLH-DSA, DILITHIUM, FALCON, SPHINCS
- `ca_name`: resolved from `ca_cert_id` via the CA name map (falls back to raw ID)

### Visualization Hierarchy

The certificate data is organized as a 4-level tree:

```
Root ("All CAs")
 ├── CA 1 (e.g., "DigiCert Private CA")
 │    ├── Batch "Feb 28 06:00"
 │    │    ├── RSA (152 certs)
 │    │    └── ECDSA (48 certs)
 │    └── Batch "Feb 28 12:00"
 │         └── RSA (200 certs)
 └── CA 2
      └── ...
```

The `GetVizSummary` query returns flat rows grouped by (ca_name, batch_window, key_algorithm, is_pq) with aggregated counts. Go code assembles these into a nested `VizSummary` tree with propagated counts for revocations, PQ, and assertion coverage.

### Three Viewing Modes

1. **Sunburst** — Concentric rings: inner = CAs, middle = batches, outer = algorithms. Post-quantum glow ring at outermost level. Revocation overlays as red arcs.

2. **Treemap** — Squarified rectangles (Brandes & Kase algorithm). Size = cert count. Bottom strip = revocation ratio. Top-left bar = PQ ratio.

3. **Proof Explorer** — Binary tree rendered top-down showing the Merkle inclusion proof path for a specific leaf. Green nodes = path from root to leaf, blue nodes = proof sibling hashes. Uses `merkle.InclusionProofFromNodes()` from the existing merkle package.

### Four Color Modes

| Mode | Coloring Logic |
|---|---|
| Trust Status | CA-assigned stable color (FNV hash of name into 12-color palette) |
| Key Algorithm | Same CA-based colors; leaf dots distinguish PQ (purple) vs classical (blue) |
| Certificate Age | Green → amber → red gradient based on issuance date |
| Assertion Coverage | Green (>80% fresh), amber (>30% stale), red (>50% missing), blue (mixed) |

### Assertion Coverage Integration

The `GetVizSummary` query joins three tables:

```sql
cert_metadata cm
LEFT JOIN revoked_indices ri ON cm.entry_idx = ri.entry_idx
LEFT JOIN assertion_bundles ab ON cm.entry_idx = ab.entry_idx
```

This produces per-group counts for fresh (non-stale bundle), stale (stale bundle), and missing (no bundle) assertion coverage, propagated up the hierarchy alongside revocation counts.

### Proof Explorer Endpoint

`GET /admin/viz/proof/{index}` is a thin handler that:
1. Fetches the latest checkpoint for tree size
2. Gets the entry data and computes `merkle.LeafHash()`
3. Calls `merkle.InclusionProofFromNodes()` with `store.GetTreeNode` as the hash callback
4. Computes proof sides from bit decomposition of the leaf index
5. Returns JSON with leafHash, rootHash, proofPath, proofSides, treeDepth

No new store methods were needed — this reuses existing `LatestCheckpoint`, `GetEntryDetail`, and `GetTreeNode`.

## Major Design Decisions

### 1. `cert_metadata` cache table instead of on-the-fly DER parsing

Parsing DER certificates is CPU-intensive and the key algorithm field is not stored anywhere except inside the DER blob. A cache table trades disk space for query performance. The table can be dropped and rebuilt from `log_entries` at any time.

### 2. Canvas-based rendering instead of a charting library

The project avoids external JavaScript dependencies (no npm, no build step). Canvas provides pixel-level control needed for custom sunburst arcs, squarified treemaps, and proof tree visualizations. The original requirements included a working Canvas implementation that was adapted for real data.

### 3. Server-side aggregation, client-side rendering

The Go backend performs SQL aggregation and assembles the hierarchy tree. The JavaScript client receives a pre-built tree and only handles rendering and interaction. This keeps the client simple and avoids shipping raw cert data to the browser.

### 4. Async metadata population on page load

`PopulateCertMetadata` runs in a background goroutine when the visualization page is loaded. It processes 1000 entries at a time in a loop until caught up. This avoids blocking the page render and handles incremental growth as new certificates are ingested.

### 5. Stable CA colors via FNV hash

CA colors are deterministic — `hash/fnv` of the CA name selects from a 12-color palette. This ensures the same CA always gets the same color across page loads and across different viewing modes.

### 6. Batch windows as 6-hour intervals

Certificates are grouped into 6-hour windows by truncating `created_at` to `(hour / 6) * 6`. This provides meaningful grouping without creating too many or too few segments. The batch label format is "Jan 2 15:04" for readability.

### 7. Focused proof tree rendering

The Proof Explorer only renders the path + siblings (O(log n) nodes) rather than the full binary tree (which could have millions of nodes). At each level, it draws the path node and its proof sibling, connected to their parent. This keeps the visualization clear and performant regardless of tree size.

## API Endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/admin/viz` | HTML page with embedded JavaScript visualization |
| GET | `/admin/viz/summary` | `VizSummary` tree JSON (root → ca → batch → algo) |
| GET | `/admin/viz/certificates?ca=X&batch=Y&algo=Z&page=N` | Paginated `VizCertificate[]` + total count |
| GET | `/admin/viz/revocations` | `{revokedIndices: int64[]}` |
| GET | `/admin/viz/stats` | `VizStats` JSON (total, valid, revoked, PQ, CAs, rates, assertion coverage) |
| GET | `/admin/viz/proof/{index}` | `{leafIndex, treeSize, leafHash, rootHash, proofPath[], proofSides[], treeDepth}` |

## Key Types

```go
// VizSummary is a hierarchical aggregation for visualization.
type VizSummary struct {
    Name           string        `json:"name"`
    Level          string        `json:"level"`      // root, ca, batch, algo
    CertCount      int64         `json:"certCount"`
    RevokedCount   int64         `json:"revokedCount"`
    PQCount        int64         `json:"pqCount"`
    ClassicalCount int64         `json:"classicalCount"`
    FreshCount     int64         `json:"freshCount"`   // assertion coverage
    StaleCount     int64         `json:"staleCount"`
    MissingCount   int64         `json:"missingCount"`
    Children       []*VizSummary `json:"children,omitempty"`
    Color          string        `json:"color,omitempty"`
}

// VizStats holds aggregate statistics.
type VizStats struct {
    Total        int64   `json:"total"`
    Valid        int64   `json:"valid"`
    Revoked      int64   `json:"revoked"`
    PQCount      int64   `json:"pqCount"`
    CACount      int64   `json:"caCount"`
    RevRate      float64 `json:"revocationRate"`
    FreshCount   int64   `json:"freshCount"`
    StaleCount   int64   `json:"staleCount"`
    MissingCount int64   `json:"missingCount"`
    CoverageRate float64 `json:"coverageRate"`
}
```

## File Locations

| File | What |
|---|---|
| `internal/store/store.go` | `cert_metadata` migration, VizSummary/VizCertificate/VizStats types, PopulateCertMetadata, GetVizSummary, GetVizCertificates, GetVizStats, isPQAlgorithm, batchWindowTime, vizCAColor |
| `internal/admin/handler.go` | 6 viz handlers, caNames field, proof endpoint using merkle.InclusionProofFromNodes |
| `internal/admin/templates.go` | vizExplorerHTML (~1000 lines): Sunburst, Treemap, Proof Explorer, 4 color modes, drill-down, breadcrumbs, stats bar, side panel, revocation highlighting, assertion coverage |
| `cmd/mtc-bridge/main.go` | caNameMap construction from caAdapter.GetCAs() |
