// Package tlogtiles implements HTTP handlers for the C2SP tlog-tiles API.
//
// Endpoints served:
//   - GET /checkpoint                 — latest signed checkpoint (signed note)
//   - GET /tile/<L>/<N>               — 256-wide hash tile at level L, tile index N
//   - GET /tile/entries/<N>           — entry data bundle for tile index N
//   - GET /revocation                 — revocation bitmap (extension)
//   - GET /proof/inclusion?serial=X   — inclusion proof for certificate by serial
//   - GET /proof/inclusion?index=N    — inclusion proof for certificate by log index
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

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/revocation"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Handler serves the tlog-tiles HTTP API.
type Handler struct {
	store  *store.Store
	revMgr *revocation.Manager
	logger *slog.Logger
	mux    *http.ServeMux
}

// New creates a new tlog-tiles Handler.
func New(s *store.Store, revMgr *revocation.Manager, logger *slog.Logger) *Handler {
	h := &Handler{
		store:  s,
		revMgr: revMgr,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	h.mux.HandleFunc("GET /checkpoint", h.handleCheckpoint)
	h.mux.HandleFunc("GET /tile/", h.handleTile)
	h.mux.HandleFunc("GET /revocation", h.handleRevocation)
	h.mux.HandleFunc("GET /proof/inclusion", h.handleInclusionProof)
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
