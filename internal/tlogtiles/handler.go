// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package tlogtiles implements HTTP handlers for the C2SP tlog-tiles API.
//
// Endpoints served:
//   - GET /checkpoint                 — latest signed checkpoint (signed note)
//   - GET /tile/<L>/<N>               — 256-wide hash tile at level L, tile index N
//   - GET /tile/entries/<N>           — entry data bundle for tile index N
//   - GET /revocation                 — revocation bitmap (extension)
//   - GET /proof/inclusion?serial=X   — inclusion proof for certificate by serial
//   - GET /proof/inclusion?index=N    — inclusion proof for certificate by log index
//   - GET /proof/consistency?old=M&new=N — consistency proof between tree sizes M and N
//
// Tile path encoding follows C2SP spec: tile indices are encoded as
// zero-padded 3-digit "x"-prefixed path segments.
package tlogtiles

import (
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/assertion"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/revocation"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Handler serves the tlog-tiles HTTP API.
type Handler struct {
	store     *store.Store
	revMgr    *revocation.Manager
	assertBld *assertion.Builder
	logger    *slog.Logger
	mux       *http.ServeMux
}

// New creates a new tlog-tiles Handler.
func New(s *store.Store, revMgr *revocation.Manager, logOrigin string, logger *slog.Logger) *Handler {
	h := &Handler{
		store:     s,
		revMgr:    revMgr,
		assertBld: assertion.NewBuilder(s, logOrigin),
		logger:    logger,
		mux:       http.NewServeMux(),
	}
	h.mux.HandleFunc("GET /checkpoint", h.handleCheckpoint)
	h.mux.HandleFunc("GET /tile/", h.handleTile)
	h.mux.HandleFunc("GET /revocation", h.handleRevocation)
	h.mux.HandleFunc("GET /proof/inclusion", h.handleInclusionProof)
	h.mux.HandleFunc("GET /proof/consistency", h.handleConsistencyProof)
	h.mux.HandleFunc("GET /assertion/{query}", h.handleAssertion)
	h.mux.HandleFunc("GET /assertion/{query}/pem", h.handleAssertionPEM)
	h.mux.HandleFunc("GET /assertions/pending", h.handleAssertionsPending)
	h.mux.HandleFunc("GET /assertions/stats", h.handleAssertionsStats)
	h.mux.HandleFunc("GET /landmarks", h.handleLandmarks)
	h.mux.HandleFunc("GET /landmark/{tree_size}", h.handleLandmarkByTreeSize)
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// handleCheckpoint serves the latest signed checkpoint.
func (h *Handler) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	cp, err := h.store.LatestCheckpoint(r.Context())
	if err != nil {
		h.logger.Error("serve checkpoint", "error", err)
		http.Error(w, "no checkpoint available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, cp.Body)
}

// handleTile routes /tile/entries/<N> and /tile/<L>/<N> requests.
func (h *Handler) handleTile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/tile/")

	if strings.HasPrefix(path, "entries/") {
		h.handleEntryTile(w, r, strings.TrimPrefix(path, "entries/"))
		return
	}

	h.handleHashTile(w, r, path)
}

// handleHashTile serves a hash tile at level L, tile index N.
// Path format: <L>/<encoded_N> where encoded_N uses x-prefixed 3-digit segments.
func (h *Handler) handleHashTile(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid tile path", http.StatusBadRequest)
		return
	}

	level, err := strconv.Atoi(parts[0])
	if err != nil || level < 0 {
		http.Error(w, "invalid tile level", http.StatusBadRequest)
		return
	}

	tileIdx, err := decodeTileIndex(parts[1])
	if err != nil {
		http.Error(w, "invalid tile index", http.StatusBadRequest)
		return
	}

	// Determine how many hashes this tile should have.
	treeSize, err := h.store.TreeSize(r.Context())
	if err != nil {
		h.logger.Error("serve hash tile: tree size", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Calculate node range for this tile.
	nodeStart := tileIdx * merkle.TileWidth
	nodesAtLevel := (treeSize + (1 << uint(level)) - 1) >> uint(level)
	if nodeStart >= nodesAtLevel {
		http.Error(w, "tile not found", http.StatusNotFound)
		return
	}

	count := int64(merkle.TileWidth)
	if nodeStart+count > nodesAtLevel {
		count = nodesAtLevel - nodeStart
	}

	hashes, err := h.store.GetTileHashes(r.Context(), level, nodeStart, int(count))
	if err != nil {
		h.logger.Error("serve hash tile", "error", err, "level", level, "tile", tileIdx)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Serialize: concatenated 32-byte hashes.
	data := make([]byte, len(hashes)*merkle.HashSize)
	for i, hash := range hashes {
		copy(data[i*merkle.HashSize:], hash[:])
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	if int64(len(hashes)) == int64(merkle.TileWidth) {
		// Full tile — can be cached indefinitely.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		// Partial tile — don't cache.
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Write(data)
}

// handleEntryTile serves an entry data bundle for tile index N.
func (h *Handler) handleEntryTile(w http.ResponseWriter, r *http.Request, indexPath string) {
	tileIdx, err := decodeTileIndex(indexPath)
	if err != nil {
		http.Error(w, "invalid tile index", http.StatusBadRequest)
		return
	}

	start := tileIdx * merkle.TileWidth
	end := start + merkle.TileWidth

	treeSize, err := h.store.TreeSize(r.Context())
	if err != nil {
		h.logger.Error("serve entry tile: tree size", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if start >= treeSize {
		http.Error(w, "tile not found", http.StatusNotFound)
		return
	}
	if end > treeSize {
		end = treeSize
	}

	entries, err := h.store.GetEntries(r.Context(), start, end)
	if err != nil {
		h.logger.Error("serve entry tile", "error", err, "tile", tileIdx)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Serialize: for each entry, 4-byte LE length prefix + entry data.
	var totalLen int
	for _, e := range entries {
		totalLen += 4 + len(e.EntryData)
	}

	data := make([]byte, 0, totalLen)
	for _, e := range entries {
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(e.EntryData)))
		data = append(data, lenBuf[:]...)
		data = append(data, e.EntryData...)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	if end-start == merkle.TileWidth {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Write(data)
}

// handleRevocation serves the revocation bitmap.
func (h *Handler) handleRevocation(w http.ResponseWriter, r *http.Request) {
	treeSize, err := h.store.TreeSize(r.Context())
	if err != nil {
		h.logger.Error("serve revocation: tree size", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	bitmap, err := h.revMgr.BuildRevocationBitmap(r.Context(), treeSize)
	if err != nil {
		h.logger.Error("serve revocation: bitmap", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(bitmap)
}

// InclusionProofResponse is the JSON response for the inclusion proof API.
type InclusionProofResponse struct {
	LeafIndex  int64    `json:"leaf_index"`
	TreeSize   int64    `json:"tree_size"`
	LeafHash   string   `json:"leaf_hash"`
	Proof      []string `json:"proof"`
	RootHash   string   `json:"root_hash"`
	Checkpoint string   `json:"checkpoint"`
}

// handleInclusionProof serves inclusion proofs by serial number or log index.
func (h *Handler) handleInclusionProof(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Resolve the leaf index from query params.
	var leafIdx int64
	serialParam := r.URL.Query().Get("serial")
	indexParam := r.URL.Query().Get("index")

	switch {
	case serialParam != "":
		idx, err := h.store.FindEntryBySerial(ctx, serialParam)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "certificate not found", http.StatusNotFound)
				return
			}
			h.logger.Error("inclusion proof: find by serial", "error", err, "serial", serialParam)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		leafIdx = idx
	case indexParam != "":
		idx, err := strconv.ParseInt(indexParam, 10, 64)
		if err != nil || idx < 0 {
			http.Error(w, "invalid index parameter", http.StatusBadRequest)
			return
		}
		leafIdx = idx
	default:
		http.Error(w, "missing 'serial' or 'index' query parameter", http.StatusBadRequest)
		return
	}

	// Get latest checkpoint for root hash and tree size.
	cp, err := h.store.LatestCheckpoint(ctx)
	if err != nil {
		h.logger.Error("inclusion proof: latest checkpoint", "error", err)
		http.Error(w, "no checkpoint available", http.StatusServiceUnavailable)
		return
	}

	if leafIdx >= cp.TreeSize {
		http.Error(w, fmt.Sprintf("index %d >= tree size %d", leafIdx, cp.TreeSize), http.StatusNotFound)
		return
	}

	// Get the leaf entry to compute its hash.
	entry, err := h.store.GetEntry(ctx, leafIdx)
	if err != nil {
		h.logger.Error("inclusion proof: get entry", "error", err, "index", leafIdx)
		http.Error(w, "entry not found", http.StatusNotFound)
		return
	}
	leafHash := merkle.LeafHash(entry.EntryData)

	// Compute inclusion proof from precomputed tree nodes.
	nodeAt := func(level int, idx int64) merkle.Hash {
		h, err := h.store.GetTreeNode(ctx, level, idx)
		if err != nil {
			// Log the error; the proof will be incorrect but we don't
			// panic — verification will catch it.
			return merkle.EmptyHash
		}
		return h
	}

	proof, err := merkle.InclusionProofFromNodes(leafIdx, cp.TreeSize, nodeAt)
	if err != nil {
		h.logger.Error("inclusion proof: compute", "error", err, "index", leafIdx, "size", cp.TreeSize)
		http.Error(w, "failed to compute proof", http.StatusInternalServerError)
		return
	}

	// Encode proof hashes as hex strings.
	proofHex := make([]string, len(proof))
	for i, ph := range proof {
		proofHex[i] = hex.EncodeToString(ph[:])
	}

	resp := InclusionProofResponse{
		LeafIndex:  leafIdx,
		TreeSize:   cp.TreeSize,
		LeafHash:   hex.EncodeToString(leafHash[:]),
		Proof:      proofHex,
		RootHash:   hex.EncodeToString(cp.RootHash),
		Checkpoint: cp.Body,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// ConsistencyProofResponse is the JSON response for the consistency proof API.
type ConsistencyProofResponse struct {
	OldSize    int64    `json:"old_size"`
	NewSize    int64    `json:"new_size"`
	OldRoot    string   `json:"old_root"`
	NewRoot    string   `json:"new_root"`
	Proof      []string `json:"proof"`
	Checkpoint string   `json:"checkpoint"`
}

// handleConsistencyProof serves consistency proofs between two tree sizes.
func (h *Handler) handleConsistencyProof(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	oldParam := r.URL.Query().Get("old")
	newParam := r.URL.Query().Get("new")

	if oldParam == "" || newParam == "" {
		http.Error(w, "missing 'old' and 'new' query parameters", http.StatusBadRequest)
		return
	}

	oldSize, err := strconv.ParseInt(oldParam, 10, 64)
	if err != nil || oldSize < 1 {
		http.Error(w, "invalid 'old' parameter: must be a positive integer", http.StatusBadRequest)
		return
	}

	newSize, err := strconv.ParseInt(newParam, 10, 64)
	if err != nil || newSize < 1 {
		http.Error(w, "invalid 'new' parameter: must be a positive integer", http.StatusBadRequest)
		return
	}

	if oldSize > newSize {
		http.Error(w, "'old' must be <= 'new'", http.StatusBadRequest)
		return
	}

	// Get latest checkpoint to bound newSize.
	cp, err := h.store.LatestCheckpoint(ctx)
	if err != nil {
		h.logger.Error("consistency proof: latest checkpoint", "error", err)
		http.Error(w, "no checkpoint available", http.StatusServiceUnavailable)
		return
	}

	if newSize > cp.TreeSize {
		http.Error(w, fmt.Sprintf("'new' (%d) exceeds tree size (%d)", newSize, cp.TreeSize), http.StatusBadRequest)
		return
	}

	// Build nodeAt callback from stored tree nodes.
	nodeAt := func(level int, idx int64) merkle.Hash {
		h, err := h.store.GetTreeNode(ctx, level, idx)
		if err != nil {
			return merkle.EmptyHash
		}
		return h
	}

	proof, err := merkle.ConsistencyProofFromNodes(oldSize, newSize, nodeAt)
	if err != nil {
		h.logger.Error("consistency proof: compute", "error", err, "old", oldSize, "new", newSize)
		http.Error(w, "failed to compute proof", http.StatusInternalServerError)
		return
	}

	// Compute root hashes for both sizes from stored nodes.
	oldRoot := merkle.RootFromNodes(oldSize, nodeAt)
	newRoot := merkle.RootFromNodes(newSize, nodeAt)

	proofHex := make([]string, len(proof))
	for i, ph := range proof {
		proofHex[i] = hex.EncodeToString(ph[:])
	}

	resp := ConsistencyProofResponse{
		OldSize:    oldSize,
		NewSize:    newSize,
		OldRoot:    hex.EncodeToString(oldRoot[:]),
		NewRoot:    hex.EncodeToString(newRoot[:]),
		Proof:      proofHex,
		Checkpoint: cp.Body,
	}

	// Record the consistency proof event for admin dashboard visibility.
	_ = h.store.EmitEvent(ctx, "consistency_proof", map[string]interface{}{
		"old_size":     oldSize,
		"new_size":     newSize,
		"proof_length": len(proof),
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// handleAssertion serves an assertion bundle as JSON for a certificate
// identified by serial number or log index.
func (h *Handler) handleAssertion(w http.ResponseWriter, r *http.Request) {
	query := r.PathValue("query")
	if query == "" {
		http.Error(w, "missing certificate serial or index", http.StatusBadRequest)
		return
	}

	bundle, err := h.assertBld.Resolve(r.Context(), query)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "null sentinel") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.logger.Error("assertion: build bundle", "error", err, "query", query)
		http.Error(w, "failed to build assertion bundle", http.StatusInternalServerError)
		return
	}

	data, err := assertion.FormatJSON(bundle)
	if err != nil {
		h.logger.Error("assertion: format JSON", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

// handleAssertionPEM serves an assertion bundle in PEM text format.
func (h *Handler) handleAssertionPEM(w http.ResponseWriter, r *http.Request) {
	query := r.PathValue("query")
	if query == "" {
		http.Error(w, "missing certificate serial or index", http.StatusBadRequest)
		return
	}

	bundle, err := h.assertBld.Resolve(r.Context(), query)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "null sentinel") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.logger.Error("assertion: build bundle PEM", "error", err, "query", query)
		http.Error(w, "failed to build assertion bundle", http.StatusInternalServerError)
		return
	}

	data, err := assertion.FormatPEM(bundle)
	if err != nil {
		h.logger.Error("assertion: format PEM", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

// handleAssertionsPending returns pre-computed assertion bundles generated since a given checkpoint.
// Query params: since=<checkpoint_id>, limit=<n> (default 100, max 500).
func (h *Handler) handleAssertionsPending(w http.ResponseWriter, r *http.Request) {
	sinceStr := r.URL.Query().Get("since")
	if sinceStr == "" {
		sinceStr = "0"
	}
	sinceID, err := strconv.ParseInt(sinceStr, 10, 64)
	if err != nil || sinceID < 0 {
		http.Error(w, "invalid 'since' parameter", http.StatusBadRequest)
		return
	}

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}

	bundles, err := h.store.GetFreshBundlesSince(r.Context(), sinceID, limit)
	if err != nil {
		h.logger.Error("assertions pending", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type pendingEntry struct {
		EntryIdx     int64  `json:"entry_idx"`
		SerialHex    string `json:"serial_hex"`
		CheckpointID int64  `json:"checkpoint_id"`
		AssertionURL string `json:"assertion_url"`
		CreatedAt    string `json:"created_at"`
	}

	entries := make([]pendingEntry, 0, len(bundles))
	for _, ab := range bundles {
		entries = append(entries, pendingEntry{
			EntryIdx:     ab.EntryIdx,
			SerialHex:    ab.SerialHex,
			CheckpointID: ab.CheckpointID,
			AssertionURL: fmt.Sprintf("/assertion/%s", ab.SerialHex),
			CreatedAt:    ab.CreatedAt.Format(time.RFC3339),
		})
	}

	resp := map[string]interface{}{
		"since":   sinceID,
		"count":   len(entries),
		"entries": entries,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// handleAssertionsStats returns aggregate assertion statistics as JSON.
func (h *Handler) handleAssertionsStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetAssertionStats(r.Context())
	if err != nil {
		h.logger.Error("assertion stats", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(stats)
}

// handleLandmarks returns the list of known landmarks as JSON.
func (h *Handler) handleLandmarks(w http.ResponseWriter, r *http.Request) {
	landmarks, err := h.store.ListLandmarks(r.Context())
	if err != nil {
		h.logger.Error("list landmarks", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type landmarkJSON struct {
		TreeSize     int64  `json:"tree_size"`
		RootHash     string `json:"root_hash"`
		CheckpointID int64  `json:"checkpoint_id"`
		CreatedAt    string `json:"created_at"`
	}

	result := make([]landmarkJSON, len(landmarks))
	for i, lm := range landmarks {
		result[i] = landmarkJSON{
			TreeSize:     lm.TreeSize,
			RootHash:     hex.EncodeToString(lm.RootHash),
			CheckpointID: lm.CheckpointID,
			CreatedAt:    lm.CreatedAt.Format(time.RFC3339),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(result)
}

// handleLandmarkByTreeSize returns a specific landmark by tree size.
func (h *Handler) handleLandmarkByTreeSize(w http.ResponseWriter, r *http.Request) {
	treeSizeStr := r.PathValue("tree_size")
	treeSize, err := strconv.ParseInt(treeSizeStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid tree_size", http.StatusBadRequest)
		return
	}

	lm, err := h.store.GetLandmark(r.Context(), treeSize)
	if err != nil {
		http.Error(w, "landmark not found", http.StatusNotFound)
		return
	}

	// Fetch associated subtree signatures.
	sigs, err := h.store.GetSubtreeSignatures(r.Context(), 0, treeSize)
	if err != nil {
		h.logger.Warn("landmark subtree signatures", "tree_size", treeSize, "error", err)
		sigs = nil
	}

	type sigJSON struct {
		CosignerID string `json:"cosigner_id"`
		Algorithm  int    `json:"algorithm"`
		Signature  string `json:"signature"`
	}
	sigResults := make([]sigJSON, len(sigs))
	for i, s := range sigs {
		sigResults[i] = sigJSON{
			CosignerID: s.CosignerID,
			Algorithm:  int(s.Algorithm),
			Signature:  hex.EncodeToString(s.Signature),
		}
	}

	result := map[string]interface{}{
		"tree_size":     lm.TreeSize,
		"root_hash":     hex.EncodeToString(lm.RootHash),
		"checkpoint_id": lm.CheckpointID,
		"created_at":    lm.CreatedAt.Format(time.RFC3339),
		"signatures":    sigResults,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// decodeTileIndex decodes a C2SP tile index path.
// Format: segments of "x" + 3-digit number, e.g., "x001/x234" = 1*1000 + 234 = 1234.
func decodeTileIndex(path string) (int64, error) {
	path = strings.TrimSuffix(path, ".p")  // partial tile suffix
	path = strings.TrimSuffix(path, ".pb") // partial tile suffix variant
	segments := strings.Split(path, "/")
	var result int64
	for _, seg := range segments {
		if !strings.HasPrefix(seg, "x") && len(seg) != 3 {
			// Last segment can be just digits.
			n, err := strconv.ParseInt(seg, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid tile index segment %q", seg)
			}
			result = result*1000 + n
			continue
		}
		seg = strings.TrimPrefix(seg, "x")
		n, err := strconv.ParseInt(seg, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid tile index segment %q", seg)
		}
		result = result*1000 + n
	}
	return result, nil
}
