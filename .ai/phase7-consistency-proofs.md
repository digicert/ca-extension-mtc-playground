# Phase 7: Consistency Proofs (RFC 9162 §2.1.4)

## Context

The MTC spec requires transparency logs to support **consistency proofs** — cryptographic evidence that a smaller tree (size `m`) is a prefix of a larger tree (size `n`) with no entries modified or removed. This is the append-only guarantee that makes transparency logs trustworthy.

### What Consistency Proofs Provide

1. **External monitors** can audit log operation by periodically fetching consistency proofs between checkpoints, verifying the log never rewrote history
2. **Cosigners** can validate log consistency before signing subtrees — refusing to sign if the log operator tampered with earlier entries
3. **Landmark verification** becomes stronger — a client holding an old landmark can verify it's still consistent with a newer one
4. **RFC 9162 compliance** — fills a gap; we have inclusion proofs but not consistency proofs exposed via API

### What Already Existed

- `ConsistencyProof(oldSize, newSize, hashAt)` in `internal/merkle/merkle.go` — core algorithm using leaf-level `hashAt` callback
- Unit tests: `TestConsistencyProof`, `TestConsistencyProofEdgeCases` in `merkle_test.go`
- `InclusionProofFromNodes()` pattern + `subtreeHashFromNodes()` — optimized store-backed proof generation
- `handleInclusionProof` HTTP handler — JSON API pattern

### What Was Added

1. `ConsistencyProofFromNodes()` — store-optimized version (O(log n) node reads vs O(n) leaf reads)
2. `VerifyConsistency()` — verification function that reconstructs both old and new roots from a single proof
3. `RootFromNodes()` — compute root hash from stored tree nodes for any tree size
4. HTTP endpoint `GET /proof/consistency?old=M&new=N`
5. 3 conformance tests (total: 29)

## Implementation

### Step 1: `ConsistencyProofFromNodes()` — `internal/merkle/merkle.go`

Mirrors `InclusionProofFromNodes` / `inclusionProofFromNodes` pattern. The internal recursive function follows the same structure as `consistencyProof()`, but calls `subtreeHashFromNodes()` instead of `computeSubtreeHash()`.

### Step 2: `VerifyConsistency()` — `internal/merkle/merkle.go`

RFC 9162 §2.1.4.2 verification. A single proof path reconstructs **both** the old root and the new root:
- Handle edge cases: oldSize=0, oldSize=newSize
- If oldSize is a power of 2, both running hashes start from the first proof element
- Otherwise, walk down to find the old tree boundary first
- Walk remaining proof elements, combining left/right based on bit patterns
- Final check: reconstructed hashes match both oldRoot and newRoot

### Step 3: `RootFromNodes()` — `internal/merkle/merkle.go`

Computes root hash from stored tree nodes for any tree size. Used by the HTTP handler to compute oldRoot without needing leaf data.

### Step 4: Unit Tests — `internal/merkle/merkle_test.go`

- `TestConsistencyProofFromNodes` — build tree, store nodes, verify output matches `ConsistencyProof`
- `TestVerifyConsistency` — generate proofs for various (old, new) pairs, verify against known roots
- `TestVerifyConsistencyRejectsInvalid` — tampered proof, wrong roots, swapped sizes
- `TestConsistencyProofFromNodesEdgeCases` — old=0, old=new, single element tree

### Step 5: HTTP Endpoint — `internal/tlogtiles/handler.go`

`GET /proof/consistency?old=M&new=N` returns:
```json
{
  "old_size": 2,
  "new_size": 5,
  "old_root": "hex...",
  "new_root": "hex...",
  "proof": ["hex...", "hex..."],
  "checkpoint": "signed note..."
}
```

### Step 6: Conformance Tests — `cmd/mtc-conformance/main.go`

- `consistency_proof_api` — fetch proof, verify JSON response structure
- `consistency_proof_verify` — cryptographic verification of proof against both roots
- `consistency_proof_edge_cases` — error handling for invalid params

### Step 7: README Updates

- API Reference table: new endpoint
- Conformance test count: 26 → 29
- Feature list: consistency proofs

## Files Modified

| File | Changes |
|------|---------|
| `internal/merkle/merkle.go` | `ConsistencyProofFromNodes`, `VerifyConsistency`, `RootFromNodes` |
| `internal/merkle/merkle_test.go` | 4 new test functions |
| `internal/tlogtiles/handler.go` | Route, response type, handler |
| `cmd/mtc-conformance/main.go` | 3 conformance tests |
| `README.md` | API docs, test counts, feature list |

## Verification

1. `go vet ./...` — clean
2. `make test` — all existing + new consistency proof tests pass
3. `make build` — all binaries compile
4. `curl http://localhost:8080/proof/consistency?old=1&new=3` — valid JSON
5. `mtc-conformance` — 29/29 pass
6. `make demo-mtc` and `make demo-embedded` — existing demos work
