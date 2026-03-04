# Phase 7b: Consistency Proof Admin UI

## Context

Phase 7 added consistency proofs (RFC 9162 §2.1.4) to the backend — `ConsistencyProofFromNodes`, `VerifyConsistency`, `RootFromNodes` in `internal/merkle/merkle.go`, and the `GET /proof/consistency?old=M&new=N` API endpoint. But the admin panel has no visibility into this feature. The user wants to "put a face" on consistency proofs:

1. **Dashboard stats** — A "Log Integrity" section with proof depth, landmarks, live consistency verification
2. **Recent Consistency Proofs table** — A running list of proofs that have been generated
3. **Interactive visualization** — A 5th tab on the Visualization page to generate/verify/visualize consistency proofs

---

## Step 1: Record consistency proof events + store query

**File:** `internal/tlogtiles/handler.go` (handleConsistencyProof)

After successfully generating a consistency proof, emit an event to the existing events table:

```go
h.store.EmitEvent(r.Context(), "consistency_proof", map[string]interface{}{
    "old_size":     oldSize,
    "new_size":     newSize,
    "proof_length": len(proof),
})
```

Reuses existing events infrastructure — proofs also appear in the "Recent Events" table with a badge. No new database table needed.

**File:** `internal/store/store.go`

Add a type-filtered query:

```go
func (s *Store) RecentEventsByType(ctx context.Context, eventType string, limit int) ([]*Event, error)
```

Simple `SELECT ... FROM events WHERE event_type = $1 ORDER BY id DESC LIMIT $2`.

---

## Step 2: Dashboard — Log Integrity stats section

**File:** `internal/admin/handler.go` (handleStats)

Append a "Log Integrity" subsection to the existing `handleStats` HTMX partial (auto-refreshes every 5s, zero additional requests).

- Fetch landmark count via `h.store.ListLandmarks(ctx)` → `len(landmarks)`
- Compute proof depth: `bits.Len64(uint64(stats.TreeSize - 1))` when TreeSize > 1
- Auto-verify between two most recent checkpoints:
  - Build `nodeAt` from `h.store.GetTreeNode`
  - Call `merkle.ConsistencyProofFromNodes` + `merkle.RootFromNodes` + `merkle.VerifyConsistency`
  - Green "Verified" or red "FAILED"
- Make "Consistency" status a clickable link → `/admin/viz?tab=consistency&old=M&new=N`

**Stats shown:** Proof Depth, Landmarks, Consistency (Verified/Failed, linked), Proof Range (1→N), Last Verified detail

---

## Step 3: Dashboard — Recent Consistency Proofs table + initial load

**File:** `internal/admin/templates.go` (dashboardHTML)

### 3a. Log Integrity section in Go template
Add `<h2>Log Integrity</h2>` and grid block after Assertion Issuer section for initial page load.

**In `handleDashboard`**: Fetch landmark count, compute integrity values, add to template data map.

### 3b. Recent Consistency Proofs table
Add a new section below the existing 2-column grid (Recent Checkpoints / Recent Events):

- Table with columns: Old Size, New Size, Hashes, Time
- HTMX auto-refresh every 10s via `hx-get="/admin/consistency-proofs"`

### 3c. New handler + route

**Route:** `GET /admin/consistency-proofs`

**Handler:** Query `store.RecentEventsByType(ctx, "consistency_proof", 10)`, parse each event's JSON payload, render HTML `<tr>` rows.

---

## Step 4: Add viz backend endpoints

**File:** `internal/admin/handler.go`

**`GET /admin/checkpoints/list`**: JSON array of recent checkpoints (20) for dropdown — `{id, treeSize, rootHash (truncated), time}`.

**`GET /admin/viz/consistency`**: Generates consistency proof with verification result:
- Parse/validate `old`, `new` query params against current tree size
- Build `nodeAt` from store, call `ConsistencyProofFromNodes`, `RootFromNodes`, `VerifyConsistency`
- Return JSON: `{oldSize, newSize, oldRoot, newRoot, proof[], proofLen, verified, treeDepth}`

---

## Step 5: Add "Consistency" tab to Visualization page

**File:** `internal/admin/templates.go` (vizExplorerHTML)

### 5a. Tab bar
Add 5th tab: "Consistency"

### 5b. Controls div
Two `<select>` dropdowns (old size, new size) populated from `/admin/checkpoints/list`, "Verify Consistency" button, status span.

### 5c. JavaScript

**New state:** `consistencyData`, `consistencySegments`, `checkpointsList`

**New functions:**
- `loadCheckpoints()` — populate dropdowns from `/admin/checkpoints/list`
- `loadConsistencyProof()` — fetch and render proof
- `drawConsistencyProof()` — canvas rendering: old/new root nodes, proof hash chain, verification badge
- `drawConsistencyNode()` — individual node renderer
- `renderConsistencyLegend()` — color legend
- `renderConsistencySidePanel()` — proof details, hash cards, explainer

**Modified functions:**
- `switchView()` — add consistency tab handling
- `redraw()` — add consistency rendering path
- mousemove handler — add consistency tooltip support
- URL param handling — support `?tab=consistency&old=M&new=N`

---

## Files Modified

| Step | File | Changes |
|------|------|---------|
| 1 | `internal/tlogtiles/handler.go` | Add `EmitEvent` call after proof generation |
| 1 | `internal/store/store.go` | Add `RecentEventsByType` method |
| 2 | `internal/admin/handler.go` | Extend `handleStats` with Log Integrity section |
| 3 | `internal/admin/templates.go` | Add integrity + proofs table to `dashboardHTML` |
| 3 | `internal/admin/handler.go` | Extend `handleDashboard`, add `handleRecentConsistencyProofs` + route |
| 4 | `internal/admin/handler.go` | Add `handleCheckpointsList`, `handleVizConsistency` + routes |
| 5 | `internal/admin/templates.go` | Add 5th tab, controls, ~200 lines JS to `vizExplorerHTML` |

**Reuses (no changes needed):**
- `internal/merkle/merkle.go` — `ConsistencyProofFromNodes`, `VerifyConsistency`, `RootFromNodes`
- `internal/store/store.go` — `ListLandmarks`, `RecentCheckpoints`, `GetTreeNode`, `GetStats`, `EmitEvent`

---

## Verification

1. `go vet ./...` — clean
2. `make build` — all binaries compile
3. `make test` — all existing tests pass
4. Manual: Open `/admin` — "Log Integrity" section visible with Proof Depth, Landmarks, Consistency status
5. Manual: "Recent Consistency Proofs" table visible (initially empty, populates after API calls)
6. Manual: `curl "/proof/consistency?old=1&new=5"` — generates proof AND creates event
7. Manual: Refresh admin dashboard — new proof appears in "Recent Consistency Proofs" table
8. Manual: Click Consistency status link → opens viz page at Consistency tab with pre-populated values
9. Manual: Open `/admin/viz?tab=consistency` — 5th tab visible, dropdowns populated
10. Manual: Select two checkpoints, click "Verify Consistency" → canvas renders proof, side panel shows details
