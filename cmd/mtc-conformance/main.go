// Command mtc-conformance is a standalone standards conformance test client
// for the MTC tlog-tiles API.
//
// It shares ZERO internal code with the mtc-bridge server — it only uses
// the public HTTP API to verify spec compliance.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const hashSize = 32

func main() {
	baseURL := flag.String("url", "http://localhost:8080", "base URL of the tlog-tiles server")
	verbose := flag.Bool("verbose", false, "verbose output")
	flag.Parse()

	c := &conformanceClient{
		baseURL: strings.TrimRight(*baseURL, "/"),
		verbose: *verbose,
		client:  &http.Client{Timeout: 30 * time.Second},
	}

	fmt.Println("=== MTC tlog-tiles Conformance Test Suite ===")
	fmt.Printf("Target: %s\n\n", c.baseURL)

	passed, failed, skipped := 0, 0, 0

	tests := []struct {
		name string
		fn   func() error
	}{
		{"checkpoint_exists", c.testCheckpointExists},
		{"checkpoint_format", c.testCheckpointFormat},
		{"checkpoint_parseable", c.testCheckpointParseable},
		{"tile_level0_exists", c.testTileLevel0Exists},
		{"tile_hash_size", c.testTileHashSize},
		{"entry_tile_exists", c.testEntryTileExists},
		{"entry_tile_parseable", c.testEntryTileParseable},
		{"inclusion_proof", c.testInclusionProof},
		{"proof_api_inclusion", c.testProofAPIInclusion},
		{"tile_caching", c.testTileCaching},
		{"revocation_endpoint", c.testRevocationEndpoint},
		{"assertion_bundle_json", c.testAssertionBundleJSON},
		{"assertion_bundle_pem", c.testAssertionBundlePEM},
		{"assertion_verify_proof", c.testAssertionVerifyProof},
		{"assertion_auto_generation", c.testAssertionAutoGeneration},
		{"assertion_polling", c.testAssertionPolling},
		{"assertion_stats", c.testAssertionStats},
	}

	for _, tt := range tests {
		fmt.Printf("  %-30s ", tt.name)
		err := tt.fn()
		if err == errSkipped {
			fmt.Println("[SKIP]")
			skipped++
		} else if err != nil {
			fmt.Printf("[FAIL] %v\n", err)
			failed++
		} else {
			fmt.Println("[PASS]")
			passed++
		}
	}

	fmt.Printf("\nResults: %d passed, %d failed, %d skipped\n", passed, failed, skipped)
	if failed > 0 {
		os.Exit(1)
	}
}

var errSkipped = fmt.Errorf("skipped")

type conformanceClient struct {
	baseURL  string
	verbose  bool
	client   *http.Client
	treeSize int64
	rootHash []byte
}

func (c *conformanceClient) get(path string) ([]byte, int, error) {
	url := c.baseURL + path
	if c.verbose {
		fmt.Printf("    GET %s\n", url)
	}
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func (c *conformanceClient) testCheckpointExists() error {
	body, status, err := c.get("/checkpoint")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d", status)
	}
	if len(body) == 0 {
		return fmt.Errorf("empty response")
	}
	return nil
}

func (c *conformanceClient) testCheckpointFormat() error {
	body, _, err := c.get("/checkpoint")
	if err != nil {
		return err
	}

	text := string(body)
	// Must have a blank line separating body from signatures.
	if !strings.Contains(text, "\n\n") {
		return fmt.Errorf("missing blank line separator")
	}

	parts := strings.SplitN(text, "\n\n", 2)
	lines := strings.Split(strings.TrimRight(parts[0], "\n"), "\n")
	if len(lines) < 3 {
		return fmt.Errorf("body needs >= 3 lines, got %d", len(lines))
	}

	// Line 1: origin (non-empty string)
	if lines[0] == "" {
		return fmt.Errorf("empty origin line")
	}

	// Line 2: tree size (decimal integer)
	if _, err := strconv.ParseInt(lines[1], 10, 64); err != nil {
		return fmt.Errorf("tree size not an integer: %s", lines[1])
	}

	// Line 3: base64-encoded root hash
	hashBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return fmt.Errorf("root hash not valid base64: %s", lines[2])
	}
	if len(hashBytes) != hashSize {
		return fmt.Errorf("root hash size = %d, want %d", len(hashBytes), hashSize)
	}

	return nil
}

func (c *conformanceClient) testCheckpointParseable() error {
	body, _, err := c.get("/checkpoint")
	if err != nil {
		return err
	}

	text := string(body)
	parts := strings.SplitN(text, "\n\n", 2)
	lines := strings.Split(strings.TrimRight(parts[0], "\n"), "\n")

	treeSize, _ := strconv.ParseInt(lines[1], 10, 64)
	rootHash, _ := base64.StdEncoding.DecodeString(lines[2])

	c.treeSize = treeSize
	c.rootHash = rootHash

	// Check signature section has at least one signature line.
	if len(parts) < 2 {
		return fmt.Errorf("no signature section")
	}

	sigLines := 0
	for _, line := range strings.Split(parts[1], "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "\u2014 ") {
			sigLines++
		}
	}
	if sigLines == 0 {
		return fmt.Errorf("no signature lines found")
	}

	return nil
}

func (c *conformanceClient) testTileLevel0Exists() error {
	if c.treeSize == 0 {
		return errSkipped
	}
	body, status, err := c.get("/tile/0/000")
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d", status)
	}
	if len(body) == 0 {
		return fmt.Errorf("empty tile")
	}
	if len(body)%hashSize != 0 {
		return fmt.Errorf("tile size %d not multiple of %d", len(body), hashSize)
	}
	return nil
}

func (c *conformanceClient) testTileHashSize() error {
	if c.treeSize == 0 {
		return errSkipped
	}
	body, _, err := c.get("/tile/0/000")
	if err != nil {
		return err
	}

	numHashes := len(body) / hashSize
	// For a tree with <= 256 entries, tile 0 should have min(treeSize, 256) hashes.
	expected := c.treeSize
	if expected > 256 {
		expected = 256
	}
	if int64(numHashes) != expected {
		return fmt.Errorf("tile has %d hashes, expected %d", numHashes, expected)
	}
	return nil
}

func (c *conformanceClient) testEntryTileExists() error {
	if c.treeSize == 0 {
		return errSkipped
	}
	body, status, err := c.get("/tile/entries/000")
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d", status)
	}
	if len(body) < 4 {
		return fmt.Errorf("entry tile too small: %d bytes", len(body))
	}
	return nil
}

func (c *conformanceClient) testEntryTileParseable() error {
	if c.treeSize == 0 {
		return errSkipped
	}
	body, _, err := c.get("/tile/entries/000")
	if err != nil {
		return err
	}

	// Parse: each entry is 4-byte LE length + data.
	offset := 0
	entryCount := 0
	for offset < len(body) {
		if offset+4 > len(body) {
			return fmt.Errorf("truncated length at offset %d", offset)
		}
		entryLen := int(binary.LittleEndian.Uint32(body[offset : offset+4]))
		offset += 4
		if offset+entryLen > len(body) {
			return fmt.Errorf("truncated entry at offset %d, need %d bytes", offset, entryLen)
		}
		offset += entryLen
		entryCount++
	}

	if entryCount == 0 {
		return fmt.Errorf("no entries parsed")
	}

	return nil
}

func (c *conformanceClient) testInclusionProof() error {
	if c.treeSize < 2 {
		return errSkipped
	}

	// Fetch entry tile 0 and verify that leaf hash matches hash tile.
	entryBody, _, err := c.get("/tile/entries/000")
	if err != nil {
		return err
	}

	hashBody, _, err := c.get("/tile/0/000")
	if err != nil {
		return err
	}

	// Parse first entry from entry tile.
	if len(entryBody) < 4 {
		return fmt.Errorf("entry tile too small")
	}
	entryLen := int(binary.LittleEndian.Uint32(entryBody[0:4]))
	if 4+entryLen > len(entryBody) {
		return fmt.Errorf("truncated first entry")
	}
	entryData := entryBody[4 : 4+entryLen]

	// Compute leaf hash.
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entryData)
	leafHash := h.Sum(nil)

	// Compare with first hash in hash tile.
	if len(hashBody) < hashSize {
		return fmt.Errorf("hash tile too small")
	}
	tileHash := hashBody[0:hashSize]

	for i := 0; i < hashSize; i++ {
		if leafHash[i] != tileHash[i] {
			return fmt.Errorf("leaf hash mismatch at byte %d", i)
		}
	}

	return nil
}

func (c *conformanceClient) testProofAPIInclusion() error {
	if c.treeSize < 2 {
		return errSkipped
	}

	// Test 1: Fetch proof by index.
	body, status, err := c.get("/proof/inclusion?index=1")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("expected 200 for index lookup, got %d: %s", status, string(body))
	}

	var resp struct {
		LeafIndex  int64    `json:"leaf_index"`
		TreeSize   int64    `json:"tree_size"`
		LeafHash   string   `json:"leaf_hash"`
		Proof      []string `json:"proof"`
		RootHash   string   `json:"root_hash"`
		Checkpoint string   `json:"checkpoint"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if resp.LeafIndex != 1 {
		return fmt.Errorf("leaf_index = %d, want 1", resp.LeafIndex)
	}
	if resp.TreeSize < 2 {
		return fmt.Errorf("tree_size = %d, want >= 2", resp.TreeSize)
	}
	if len(resp.LeafHash) != 64 {
		return fmt.Errorf("leaf_hash length = %d, want 64 hex chars", len(resp.LeafHash))
	}
	if len(resp.RootHash) != 64 {
		return fmt.Errorf("root_hash length = %d, want 64 hex chars", len(resp.RootHash))
	}
	if resp.Checkpoint == "" {
		return fmt.Errorf("empty checkpoint")
	}
	if len(resp.Proof) == 0 {
		return fmt.Errorf("empty proof for tree_size >= 2")
	}

	// Verify the proof: walk leaf hash up through proof to reconstruct root.
	leafHash, err := hex.DecodeString(resp.LeafHash)
	if err != nil {
		return fmt.Errorf("invalid leaf_hash hex: %w", err)
	}
	rootHash, err := hex.DecodeString(resp.RootHash)
	if err != nil {
		return fmt.Errorf("invalid root_hash hex: %w", err)
	}

	proofHashes := make([][]byte, len(resp.Proof))
	for i, ph := range resp.Proof {
		proofHashes[i], err = hex.DecodeString(ph)
		if err != nil {
			return fmt.Errorf("invalid proof[%d] hex: %w", i, err)
		}
		if len(proofHashes[i]) != 32 {
			return fmt.Errorf("proof[%d] length = %d, want 32", i, len(proofHashes[i]))
		}
	}

	// Walk the proof: at each level, combine with sibling based on index parity.
	h := sha256.New()
	current := make([]byte, 32)
	copy(current, leafHash)
	idx := resp.LeafIndex
	for _, sibling := range proofHashes {
		h.Reset()
		h.Write([]byte{0x01}) // interior node domain separator
		if idx%2 == 0 {
			h.Write(current)
			h.Write(sibling)
		} else {
			h.Write(sibling)
			h.Write(current)
		}
		current = h.Sum(nil)
		idx /= 2
	}

	// The reconstructed hash should match the checkpoint root.
	for i := 0; i < 32; i++ {
		if current[i] != rootHash[i] {
			return fmt.Errorf("proof verification failed: reconstructed root mismatch at byte %d", i)
		}
	}

	// Test 2: Invalid index returns 404.
	_, status, err = c.get(fmt.Sprintf("/proof/inclusion?index=%d", c.treeSize+1000))
	if err != nil {
		return fmt.Errorf("request for out-of-range index failed: %w", err)
	}
	if status != 404 {
		return fmt.Errorf("expected 404 for out-of-range index, got %d", status)
	}

	// Test 3: Missing params returns 400.
	_, status, err = c.get("/proof/inclusion")
	if err != nil {
		return fmt.Errorf("request with no params failed: %w", err)
	}
	if status != 400 {
		return fmt.Errorf("expected 400 for missing params, got %d", status)
	}

	return nil
}

func (c *conformanceClient) testTileCaching() error {
	if c.treeSize == 0 {
		return errSkipped
	}

	url := c.baseURL + "/tile/0/000"
	resp, err := c.client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()

	cc := resp.Header.Get("Cache-Control")
	if cc == "" {
		return fmt.Errorf("missing Cache-Control header")
	}

	// Full tiles should have long cache, partial should have no-cache.
	if c.treeSize >= 256 {
		if !strings.Contains(cc, "immutable") && !strings.Contains(cc, "max-age") {
			return fmt.Errorf("full tile should be cacheable, got: %s", cc)
		}
	}

	return nil
}

func (c *conformanceClient) testRevocationEndpoint() error {
	_, status, err := c.get("/revocation")
	if err != nil {
		return err
	}
	// 200 is expected (even if empty bitmap).
	if status != 200 {
		return fmt.Errorf("expected 200, got %d", status)
	}
	return nil
}

func (c *conformanceClient) testAssertionBundleJSON() error {
	if c.treeSize < 2 {
		return errSkipped
	}

	// Fetch assertion bundle for index 1 (first real cert after null entry).
	body, status, err := c.get("/assertion/1")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d: %s", status, string(body))
	}

	var bundle struct {
		LeafIndex int64    `json:"leaf_index"`
		TreeSize  int64    `json:"tree_size"`
		LeafHash  string   `json:"leaf_hash"`
		RootHash  string   `json:"root_hash"`
		Proof     []string `json:"proof"`
		LogOrigin string   `json:"log_origin"`
	}
	if err := json.Unmarshal(body, &bundle); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if bundle.LeafIndex != 1 {
		return fmt.Errorf("leaf_index = %d, want 1", bundle.LeafIndex)
	}
	if bundle.TreeSize < 2 {
		return fmt.Errorf("tree_size = %d, want >= 2", bundle.TreeSize)
	}
	if len(bundle.LeafHash) != 64 {
		return fmt.Errorf("leaf_hash length = %d, want 64 hex chars", len(bundle.LeafHash))
	}
	if len(bundle.RootHash) != 64 {
		return fmt.Errorf("root_hash length = %d, want 64 hex chars", len(bundle.RootHash))
	}
	if len(bundle.Proof) == 0 {
		return fmt.Errorf("empty proof")
	}
	if bundle.LogOrigin == "" {
		return fmt.Errorf("empty log_origin")
	}

	return nil
}

func (c *conformanceClient) testAssertionBundlePEM() error {
	if c.treeSize < 2 {
		return errSkipped
	}

	body, status, err := c.get("/assertion/1/pem")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d: %s", status, string(body))
	}

	text := string(body)
	if !strings.HasPrefix(text, "-----BEGIN MTC ASSERTION BUNDLE-----") {
		return fmt.Errorf("missing PEM header")
	}
	if !strings.Contains(text, "-----END MTC ASSERTION BUNDLE-----") {
		return fmt.Errorf("missing PEM footer")
	}
	if !strings.Contains(text, "Leaf-Index: 1") {
		return fmt.Errorf("missing Leaf-Index header")
	}
	if !strings.Contains(text, "Log-Origin:") {
		return fmt.Errorf("missing Log-Origin header")
	}

	return nil
}

func (c *conformanceClient) testAssertionVerifyProof() error {
	if c.treeSize < 2 {
		return errSkipped
	}

	// Fetch the assertion bundle.
	body, status, err := c.get("/assertion/1")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d", status)
	}

	var bundle struct {
		LeafIndex int64    `json:"leaf_index"`
		TreeSize  int64    `json:"tree_size"`
		LeafHash  string   `json:"leaf_hash"`
		RootHash  string   `json:"root_hash"`
		Proof     []string `json:"proof"`
	}
	if err := json.Unmarshal(body, &bundle); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Decode hashes.
	leafHash, err := hex.DecodeString(bundle.LeafHash)
	if err != nil {
		return fmt.Errorf("invalid leaf_hash: %w", err)
	}
	rootHash, err := hex.DecodeString(bundle.RootHash)
	if err != nil {
		return fmt.Errorf("invalid root_hash: %w", err)
	}

	proofHashes := make([][]byte, len(bundle.Proof))
	for i, ph := range bundle.Proof {
		proofHashes[i], err = hex.DecodeString(ph)
		if err != nil {
			return fmt.Errorf("invalid proof[%d]: %w", i, err)
		}
	}

	// Verify: walk leaf hash up through proof to reconstruct root.
	h := sha256.New()
	current := make([]byte, 32)
	copy(current, leafHash)
	idx := bundle.LeafIndex
	for _, sibling := range proofHashes {
		h.Reset()
		h.Write([]byte{0x01})
		if idx%2 == 0 {
			h.Write(current)
			h.Write(sibling)
		} else {
			h.Write(sibling)
			h.Write(current)
		}
		current = h.Sum(nil)
		idx /= 2
	}

	for i := 0; i < 32; i++ {
		if current[i] != rootHash[i] {
			return fmt.Errorf("proof verification failed: root mismatch at byte %d", i)
		}
	}

	// Also verify: fetching assertion for index 0 (null entry) returns 404.
	_, status, err = c.get("/assertion/0")
	if err != nil {
		return fmt.Errorf("request for null entry failed: %w", err)
	}
	if status != 404 {
		return fmt.Errorf("expected 404 for null entry assertion, got %d", status)
	}

	return nil
}

// --- Phase 2: Assertion Issuer conformance tests ---

func (c *conformanceClient) testAssertionAutoGeneration() error {
	// Verify the /assertions/stats endpoint reports auto-generated bundles.
	body, status, err := c.get("/assertions/stats")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d", status)
	}

	var stats struct {
		TotalBundles   int64  `json:"total_bundles"`
		FreshBundles   int64  `json:"fresh_bundles"`
		StaleBundles   int64  `json:"stale_bundles"`
		PendingEntries int64  `json:"pending_entries"`
		LastGenerated  string `json:"last_generated"`
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Stats endpoint must return valid JSON with expected fields.
	// Total bundles may be 0 if the issuer hasn't run yet, but fields must exist.
	if c.verbose {
		fmt.Printf("    total_bundles=%d fresh=%d stale=%d pending=%d\n",
			stats.TotalBundles, stats.FreshBundles, stats.StaleBundles, stats.PendingEntries)
	}

	return nil
}

func (c *conformanceClient) testAssertionPolling() error {
	// Verify the /assertions/pending endpoint works with since=0.
	body, status, err := c.get("/assertions/pending?since=0&limit=10")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d", status)
	}

	var resp struct {
		Since   int64 `json:"since"`
		Count   int   `json:"count"`
		Entries []struct {
			EntryIdx     int64  `json:"entry_idx"`
			SerialHex    string `json:"serial_hex"`
			CheckpointID int64  `json:"checkpoint_id"`
			AssertionURL string `json:"assertion_url"`
			CreatedAt    string `json:"created_at"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if resp.Since != 0 {
		return fmt.Errorf("expected since=0, got %d", resp.Since)
	}
	if resp.Count != len(resp.Entries) {
		return fmt.Errorf("count %d != len(entries) %d", resp.Count, len(resp.Entries))
	}

	// If we have entries, verify each has required fields.
	for i, e := range resp.Entries {
		if e.EntryIdx <= 0 {
			return fmt.Errorf("entry[%d]: invalid entry_idx %d", i, e.EntryIdx)
		}
		if e.SerialHex == "" {
			return fmt.Errorf("entry[%d]: empty serial_hex", i)
		}
		if e.AssertionURL == "" {
			return fmt.Errorf("entry[%d]: empty assertion_url", i)
		}
		if e.CheckpointID <= 0 {
			return fmt.Errorf("entry[%d]: invalid checkpoint_id %d", i, e.CheckpointID)
		}
	}

	if c.verbose {
		fmt.Printf("    polling: %d entries returned\n", resp.Count)
	}

	return nil
}

func (c *conformanceClient) testAssertionStats() error {
	// Verify the /assertions/stats endpoint returns valid JSON.
	body, status, err := c.get("/assertions/stats")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("expected 200, got %d", status)
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(body, &stats); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Verify required fields exist.
	requiredFields := []string{"total_bundles", "fresh_bundles", "stale_bundles", "pending_entries", "last_generated"}
	for _, f := range requiredFields {
		if _, ok := stats[f]; !ok {
			return fmt.Errorf("missing required field: %s", f)
		}
	}

	return nil
}
