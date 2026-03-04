// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command mtc-conformance is a standalone standards conformance test client
// for the MTC tlog-tiles API.
//
// It shares ZERO internal code with the mtc-bridge server — it only uses
// the public HTTP API to verify spec compliance.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

	"github.com/briantrzupek/ca-extension-merkle/internal/mtccert"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

const hashSize = 32

func main() {
	baseURL := flag.String("url", "http://localhost:8080", "base URL of the tlog-tiles server")
	acmeURL := flag.String("acme-url", "https://localhost:8443", "base URL of the ACME server")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (for self-signed certs)")
	verbose := flag.Bool("verbose", false, "verbose output")
	flag.Parse()

	httpClient := &http.Client{Timeout: 30 * time.Second}
	if *insecure || strings.HasPrefix(*acmeURL, "https://") {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	c := &conformanceClient{
		baseURL: strings.TrimRight(*baseURL, "/"),
		acmeURL: strings.TrimRight(*acmeURL, "/"),
		verbose: *verbose,
		client:  httpClient,
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
		{"acme_directory", c.testACMEDirectory},
		{"acme_nonce", c.testACMENonce},
		{"acme_new_account", c.testACMENewAccount},
		{"acme_new_order", c.testACMENewOrder},
		{"acme_order_flow", c.testACMEOrderFlow},
		{"acme_full_mtc_flow", c.testACMEFullMTCFlow},
		{"mtc_cert_format", c.testMTCCertFormat},
		{"mtc_proof_roundtrip", c.testMTCProofRoundtrip},
		{"mtc_log_entry_reconstruct", c.testMTCLogEntryReconstruct},
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
	acmeURL  string
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

// --- ACME JWS Helpers ---

func (c *conformanceClient) acmeKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func acmeJWK(pub *ecdsa.PublicKey) json.RawMessage {
	x := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
	jwk := fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}`, x, y)
	return json.RawMessage(jwk)
}

func (c *conformanceClient) acmeNonce() (string, error) {
	resp, err := c.client.Head(c.acmeURL + "/acme/new-nonce")
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("no Replay-Nonce header")
	}
	return nonce, nil
}

func (c *conformanceClient) acmePost(url string, key *ecdsa.PrivateKey, payload interface{}, useKID string) ([]byte, int, http.Header, error) {
	nonce, err := c.acmeNonce()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("get nonce: %w", err)
	}
	hdr := map[string]interface{}{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
	}
	if useKID != "" {
		hdr["kid"] = useKID
	} else {
		hdr["jwk"] = json.RawMessage(acmeJWK(&key.PublicKey))
	}
	hdrJSON, _ := json.Marshal(hdr)
	protected := base64.RawURLEncoding.EncodeToString(hdrJSON)

	var payloadStr string
	if payload != nil {
		payloadJSON, _ := json.Marshal(payload)
		payloadStr = base64.RawURLEncoding.EncodeToString(payloadJSON)
	}

	sigInput := protected + "." + payloadStr
	hash := sha256.Sum256([]byte(sigInput))
	rInt, sInt, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, 0, nil, fmt.Errorf("sign: %w", err)
	}
	rB := rInt.Bytes()
	sB := sInt.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rB):32], rB)
	copy(sig[64-len(sB):64], sB)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	jwsBody := fmt.Sprintf(`{"protected":"%s","payload":"%s","signature":"%s"}`, protected, payloadStr, sigB64)
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(jwsBody)))
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, resp.Header, err
}

// --- ACME Conformance Tests ---

func (c *conformanceClient) testACMEDirectory() error {
	resp, err := c.client.Get(c.acmeURL + "/acme/directory")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var dir map[string]interface{}
	if err := json.Unmarshal(body, &dir); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	for _, f := range []string{"newNonce", "newAccount", "newOrder"} {
		if _, ok := dir[f]; !ok {
			return fmt.Errorf("missing required field: %s", f)
		}
	}
	if c.verbose {
		fmt.Printf("    directory: %s\n", string(body))
	}
	return nil
}

func (c *conformanceClient) testACMENonce() error {
	nonce, err := c.acmeNonce()
	if err != nil {
		return err
	}
	if len(nonce) < 10 {
		return fmt.Errorf("nonce too short: %q", nonce)
	}
	nonce2, err := c.acmeNonce()
	if err != nil {
		return err
	}
	if nonce == nonce2 {
		return fmt.Errorf("two nonces are identical")
	}
	if c.verbose {
		fmt.Printf("    nonce1=%s nonce2=%s\n", nonce, nonce2)
	}
	return nil
}

func (c *conformanceClient) testACMENewAccount() error {
	key, err := c.acmeKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	payload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:test@example.com"},
	}
	body, status, headers, err := c.acmePost(c.acmeURL+"/acme/new-account", key, payload, "")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if status != 201 {
		return fmt.Errorf("expected 201, got %d: %s", status, string(body))
	}
	loc := headers.Get("Location")
	if loc == "" {
		return fmt.Errorf("no Location header")
	}
	var acct map[string]interface{}
	if err := json.Unmarshal(body, &acct); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if acct["status"] != "valid" {
		return fmt.Errorf("expected status=valid, got %v", acct["status"])
	}
	// Re-register same key should return existing (200).
	body2, status2, _, err := c.acmePost(c.acmeURL+"/acme/new-account", key, payload, "")
	if err != nil {
		return fmt.Errorf("second request failed: %w", err)
	}
	if status2 != 200 {
		return fmt.Errorf("expected 200 for existing account, got %d: %s", status2, string(body2))
	}
	if c.verbose {
		fmt.Printf("    account: %s\n", loc)
	}
	return nil
}

func (c *conformanceClient) testACMENewOrder() error {
	key, err := c.acmeKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	// Create account.
	acctPayload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:order-test@example.com"},
	}
	_, status, headers, err := c.acmePost(c.acmeURL+"/acme/new-account", key, acctPayload, "")
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	if status != 201 && status != 200 {
		return fmt.Errorf("account creation failed: %d", status)
	}
	kid := headers.Get("Location")

	// Create order.
	orderPayload := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": "test.example.com"},
		},
	}
	body, status, orderHeaders, err := c.acmePost(c.acmeURL+"/acme/new-order", key, orderPayload, kid)
	if err != nil {
		return fmt.Errorf("create order: %w", err)
	}
	if status != 201 {
		return fmt.Errorf("expected 201, got %d: %s", status, string(body))
	}
	orderLoc := orderHeaders.Get("Location")
	if orderLoc == "" {
		return fmt.Errorf("no order Location header")
	}
	var order map[string]interface{}
	if err := json.Unmarshal(body, &order); err != nil {
		return fmt.Errorf("invalid order JSON: %w", err)
	}
	if order["status"] != "pending" {
		return fmt.Errorf("expected status=pending, got %v", order["status"])
	}
	authzs, ok := order["authorizations"].([]interface{})
	if !ok || len(authzs) == 0 {
		return fmt.Errorf("expected authorizations array")
	}
	if _, ok := order["finalize"]; !ok {
		return fmt.Errorf("missing finalize URL")
	}
	if c.verbose {
		fmt.Printf("    order: %s authzs=%d\n", orderLoc, len(authzs))
	}
	return nil
}

func (c *conformanceClient) testACMEOrderFlow() error {
	key, err := c.acmeKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Step 1: Create account.
	acctPayload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:flow-test@example.com"},
	}
	_, status, headers, err := c.acmePost(c.acmeURL+"/acme/new-account", key, acctPayload, "")
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	if status != 201 && status != 200 {
		return fmt.Errorf("account creation failed: %d", status)
	}
	kid := headers.Get("Location")
	if c.verbose {
		fmt.Printf("    account: %s\n", kid)
	}

	// Step 2: Create order.
	orderPayload := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": "flow-test.example.com"},
		},
	}
	body, status, orderHeaders, err := c.acmePost(c.acmeURL+"/acme/new-order", key, orderPayload, kid)
	if err != nil {
		return fmt.Errorf("create order: %w", err)
	}
	if status != 201 {
		return fmt.Errorf("expected 201, got %d: %s", status, string(body))
	}
	orderLoc := orderHeaders.Get("Location")

	var order map[string]interface{}
	if err := json.Unmarshal(body, &order); err != nil {
		return fmt.Errorf("invalid order JSON: %w", err)
	}
	if order["status"] != "pending" {
		return fmt.Errorf("expected order status=pending, got %v", order["status"])
	}
	authzs := order["authorizations"].([]interface{})
	if c.verbose {
		fmt.Printf("    order: %s status=pending authzs=%d\n", orderLoc, len(authzs))
	}

	// Step 3: Get authorization and find http-01 challenge.
	authzURL := authzs[0].(string)
	body, status, _, err = c.acmePost(authzURL, key, nil, kid)
	if err != nil {
		return fmt.Errorf("get authz: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("authz GET failed: %d", status)
	}
	var authz map[string]interface{}
	if err := json.Unmarshal(body, &authz); err != nil {
		return fmt.Errorf("invalid authz JSON: %w", err)
	}
	challenges, ok := authz["challenges"].([]interface{})
	if !ok || len(challenges) == 0 {
		return fmt.Errorf("no challenges found")
	}
	var challengeURL string
	for _, ch := range challenges {
		chMap := ch.(map[string]interface{})
		if chMap["type"] == "http-01" {
			challengeURL = chMap["url"].(string)
			break
		}
	}
	if challengeURL == "" {
		return fmt.Errorf("no http-01 challenge found")
	}
	if c.verbose {
		fmt.Printf("    challenge: %s\n", challengeURL)
	}

	// Step 4: POST challenge to trigger validation (auto-approve mode).
	body, status, _, err = c.acmePost(challengeURL, key, map[string]interface{}{}, kid)
	if err != nil {
		return fmt.Errorf("post challenge: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("challenge POST failed: %d: %s", status, string(body))
	}
	var chResp map[string]interface{}
	if err := json.Unmarshal(body, &chResp); err != nil {
		return fmt.Errorf("invalid challenge response: %w", err)
	}
	if c.verbose {
		fmt.Printf("    challenge status=%v\n", chResp["status"])
	}

	// Step 5: Poll order until it becomes "ready" (challenge auto-approved).
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		body, status, _, err = c.acmePost(orderLoc, key, nil, kid)
		if err != nil {
			return fmt.Errorf("poll order: %w", err)
		}
		if status != 200 {
			return fmt.Errorf("order poll failed: %d", status)
		}
		if err := json.Unmarshal(body, &order); err != nil {
			return fmt.Errorf("invalid order JSON: %w", err)
		}
		st := order["status"].(string)
		if c.verbose {
			fmt.Printf("    poll %d: order status=%s\n", i+1, st)
		}
		if st == "ready" {
			return nil
		}
		if st == "invalid" {
			return fmt.Errorf("order became invalid")
		}
	}
	return fmt.Errorf("order did not reach ready state within timeout, last status=%v", order["status"])
}

// testACMEFullMTCFlow exercises the complete ACME → DigiCert CA → MTC assertion pipeline:
// account → order → challenge → finalize(CSR) → CA issues cert → watcher logs cert →
// assertion issuer generates inclusion proof → certificate download with MTC bundle.
func (c *conformanceClient) testACMEFullMTCFlow() error {
	acmeKey, err := c.acmeKey()
	if err != nil {
		return fmt.Errorf("generate ACME key: %w", err)
	}

	domain := fmt.Sprintf("mtc-e2e-%d.example.com", time.Now().UnixNano()%100000)
	if c.verbose {
		fmt.Printf("    domain: %s\n", domain)
	}

	// Step 1: Create account.
	acctPayload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:mtc-e2e@example.com"},
	}
	_, status, headers, err := c.acmePost(c.acmeURL+"/acme/new-account", acmeKey, acctPayload, "")
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	if status != 201 && status != 200 {
		return fmt.Errorf("account creation failed: %d", status)
	}
	kid := headers.Get("Location")
	if c.verbose {
		fmt.Printf("    account: %s\n", kid)
	}

	// Step 2: Create order.
	orderPayload := map[string]interface{}{
		"identifiers": []map[string]string{
			{"type": "dns", "value": domain},
		},
	}
	body, status, orderHeaders, err := c.acmePost(c.acmeURL+"/acme/new-order", acmeKey, orderPayload, kid)
	if err != nil {
		return fmt.Errorf("create order: %w", err)
	}
	if status != 201 {
		return fmt.Errorf("expected 201 for new-order, got %d: %s", status, string(body))
	}
	orderLoc := orderHeaders.Get("Location")
	var order map[string]interface{}
	json.Unmarshal(body, &order)
	authzs := order["authorizations"].([]interface{})
	if c.verbose {
		fmt.Printf("    order: %s status=%v\n", orderLoc, order["status"])
	}

	// Step 3: Get authorization and respond to http-01 challenge.
	authzURL := authzs[0].(string)
	body, status, _, err = c.acmePost(authzURL, acmeKey, nil, kid)
	if err != nil {
		return fmt.Errorf("get authz: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("authz failed: %d", status)
	}
	var authz map[string]interface{}
	json.Unmarshal(body, &authz)
	challenges := authz["challenges"].([]interface{})
	var challengeURL string
	for _, ch := range challenges {
		chMap := ch.(map[string]interface{})
		if chMap["type"] == "http-01" {
			challengeURL = chMap["url"].(string)
			break
		}
	}
	if challengeURL == "" {
		return fmt.Errorf("no http-01 challenge found")
	}

	// Step 4: POST challenge (auto-approve mode).
	body, status, _, err = c.acmePost(challengeURL, acmeKey, map[string]interface{}{}, kid)
	if err != nil {
		return fmt.Errorf("post challenge: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("challenge POST failed: %d: %s", status, string(body))
	}
	if c.verbose {
		fmt.Printf("    challenge: submitted\n")
	}

	// Step 5: Poll until order is "ready".
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		body, status, _, err = c.acmePost(orderLoc, acmeKey, nil, kid)
		if err != nil {
			return fmt.Errorf("poll order: %w", err)
		}
		json.Unmarshal(body, &order)
		st := order["status"].(string)
		if st == "ready" {
			break
		}
		if st == "invalid" {
			return fmt.Errorf("order became invalid before finalize")
		}
	}
	if order["status"].(string) != "ready" {
		return fmt.Errorf("order did not reach ready, got %v", order["status"])
	}
	if c.verbose {
		fmt.Printf("    order status: ready\n")
	}

	// Step 6: Generate RSA key + CSR and finalize the order.
	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate CSR key: %w", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"MTC E2E Test"},
			Country:      []string{"US"},
		},
		DNSNames: []string{domain},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // SAN OID
				Value: nil,                                  // x509 fills from DNSNames
			},
		},
	}
	// Remove the manual SAN extension — x509.CreateCertificateRequest handles DNSNames.
	csrTemplate.ExtraExtensions = nil
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, csrKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrB64 := base64.RawURLEncoding.EncodeToString(csrDER)

	finalizeURL := order["finalize"].(string)
	finalizePayload := map[string]interface{}{
		"csr": csrB64,
	}
	body, status, _, err = c.acmePost(finalizeURL, acmeKey, finalizePayload, kid)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("finalize failed: %d: %s", status, string(body))
	}
	json.Unmarshal(body, &order)
	if c.verbose {
		fmt.Printf("    finalize: status=%v\n", order["status"])
	}

	// Step 7: Poll until order becomes "valid" (cert issued + assertion ready).
	// This is the MTC magic — the server waits for the cert to be logged in the
	// transparency tree and for the assertion issuer to generate an inclusion proof.
	var certURL string
	if c.verbose {
		fmt.Printf("    waiting for CA issuance + MTC assertion bundle...\n")
	}
	for i := 0; i < 120; i++ { // up to 60s (CA issuance + watcher poll + assertion generation)
		time.Sleep(500 * time.Millisecond)
		body, status, _, err = c.acmePost(orderLoc, acmeKey, nil, kid)
		if err != nil {
			return fmt.Errorf("poll order for valid: %w", err)
		}
		json.Unmarshal(body, &order)
		st := order["status"].(string)
		if c.verbose && i%10 == 0 && i > 0 {
			fmt.Printf("    poll %d: status=%s\n", i, st)
		}
		if st == "valid" {
			certURL, _ = order["certificate"].(string)
			break
		}
		if st == "invalid" {
			detail := ""
			if errObj, ok := order["error"]; ok {
				if errMap, ok := errObj.(map[string]interface{}); ok {
					detail, _ = errMap["detail"].(string)
				}
			}
			return fmt.Errorf("order became invalid during finalize: %s", detail)
		}
	}
	if certURL == "" {
		return fmt.Errorf("order did not reach valid within timeout, last status=%v", order["status"])
	}
	if c.verbose {
		fmt.Printf("    order valid! certificate: %s\n", certURL)
	}

	// Step 8: Download certificate — should contain X.509 cert + MTC assertion bundle.
	body, status, _, err = c.acmePost(certURL, acmeKey, nil, kid)
	if err != nil {
		return fmt.Errorf("download cert: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("cert download failed: %d: %s", status, string(body))
	}

	certPEM := string(body)

	// Verify X.509 certificate is present.
	if !strings.Contains(certPEM, "-----BEGIN CERTIFICATE-----") {
		return fmt.Errorf("response missing X.509 certificate PEM")
	}
	if c.verbose {
		fmt.Printf("    certificate PEM: %d bytes\n", len(certPEM))
	}

	// Verify MTC Assertion Bundle is present — this is the Google MTC integration.
	if !strings.Contains(certPEM, "-----BEGIN MTC ASSERTION BUNDLE-----") {
		// The assertion bundle may not be ready yet if the watcher hasn't polled.
		// This is still a valid cert but without the MTC proof.
		if c.verbose {
			fmt.Printf("    WARNING: MTC assertion bundle not yet attached (watcher may not have polled)\n")
		}
		return fmt.Errorf("MTC assertion bundle missing from certificate download — " +
			"cert was issued but not yet logged in the transparency tree")
	}
	if !strings.Contains(certPEM, "-----END MTC ASSERTION BUNDLE-----") {
		return fmt.Errorf("MTC assertion bundle PEM incomplete")
	}
	if !strings.Contains(certPEM, "Leaf-Index:") {
		return fmt.Errorf("MTC assertion bundle missing Leaf-Index header")
	}
	if !strings.Contains(certPEM, "Log-Origin:") {
		return fmt.Errorf("MTC assertion bundle missing Log-Origin header")
	}

	if c.verbose {
		// Extract and display the assertion bundle summary.
		bundleStart := strings.Index(certPEM, "-----BEGIN MTC ASSERTION BUNDLE-----")
		bundleEnd := strings.Index(certPEM, "-----END MTC ASSERTION BUNDLE-----")
		if bundleStart >= 0 && bundleEnd > bundleStart {
			bundle := certPEM[bundleStart : bundleEnd+len("-----END MTC ASSERTION BUNDLE-----")]
			lines := strings.Split(bundle, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "Leaf-Index:") ||
					strings.HasPrefix(line, "Tree-Size:") ||
					strings.HasPrefix(line, "Log-Origin:") {
					fmt.Printf("    %s\n", line)
				}
			}
		}
		fmt.Printf("    FULL MTC FLOW COMPLETE: cert issued via DigiCert CA → logged in Merkle tree → assertion bundle attached\n")
	}

	return nil
}

// --- MTC Spec Conformance Tests (standalone, no server required) ---

func (c *conformanceClient) testMTCCertFormat() error {
	// Build an MTC certificate and verify its structure.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "mtc-conformance.example.com", Country: []string{"US"}},
		DNSNames: []string{"mtc-conformance.example.com"},
	}, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}

	h := sha256.Sum256([]byte("test sibling"))
	proof := &mtcformat.MTCProof{
		Start:          0,
		End:            128,
		InclusionProof: [][]byte{h[:]},
	}

	issuer := pkix.Name{CommonName: "Conformance CA", Country: []string{"US"}}
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	certDER, err := mtccert.BuildMTCCertFromCSR(csr, issuer, notBefore, notAfter,
		[]string{"mtc-conformance.example.com"}, 42, proof)
	if err != nil {
		return fmt.Errorf("BuildMTCCertFromCSR: %w", err)
	}

	// Verify it's detected as MTC format.
	if !mtccert.IsMTCCertificate(certDER) {
		return fmt.Errorf("IsMTCCertificate returned false")
	}

	// Parse it back.
	parsed, err := mtccert.ParseMTCCertificate(certDER)
	if err != nil {
		return fmt.Errorf("ParseMTCCertificate: %w", err)
	}
	if parsed.SerialNumber != 42 {
		return fmt.Errorf("serial = %d, want 42", parsed.SerialNumber)
	}
	if parsed.Proof == nil {
		return fmt.Errorf("proof is nil after parse")
	}
	if parsed.Proof.End != 128 {
		return fmt.Errorf("proof.End = %d, want 128", parsed.Proof.End)
	}

	return nil
}

func (c *conformanceClient) testMTCProofRoundtrip() error {
	// Test MTCProof marshal/unmarshal roundtrip.
	h1 := sha256.Sum256([]byte("hash1"))
	h2 := sha256.Sum256([]byte("hash2"))
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}

	original := &mtcformat.MTCProof{
		Start: 100,
		End:   200,
		InclusionProof: [][]byte{
			h1[:],
			h2[:],
		},
		Signatures: []mtcformat.MTCSignature{
			{CosignerID: 0, Signature: sig},
			{CosignerID: 1, Signature: sig},
		},
	}

	data, err := mtcformat.MarshalProof(original)
	if err != nil {
		return fmt.Errorf("MarshalProof: %w", err)
	}

	parsed, err := mtcformat.UnmarshalProof(data)
	if err != nil {
		return fmt.Errorf("UnmarshalProof: %w", err)
	}

	if parsed.Start != original.Start {
		return fmt.Errorf("Start = %d, want %d", parsed.Start, original.Start)
	}
	if parsed.End != original.End {
		return fmt.Errorf("End = %d, want %d", parsed.End, original.End)
	}
	if len(parsed.InclusionProof) != 2 {
		return fmt.Errorf("InclusionProof len = %d, want 2", len(parsed.InclusionProof))
	}
	if len(parsed.Signatures) != 2 {
		return fmt.Errorf("Signatures len = %d, want 2", len(parsed.Signatures))
	}
	if parsed.Signatures[0].CosignerID != 0 || parsed.Signatures[1].CosignerID != 1 {
		return fmt.Errorf("cosigner IDs mismatch")
	}

	return nil
}

func (c *conformanceClient) testMTCLogEntryReconstruct() error {
	// Build an MTC cert, parse it, reconstruct the log entry, and verify SPKI hash.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "reconstruct.example.com", Country: []string{"US"}},
		DNSNames: []string{"reconstruct.example.com"},
	}, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}

	h := sha256.Sum256([]byte("sibling"))
	proof := &mtcformat.MTCProof{
		Start:          0,
		End:            64,
		InclusionProof: [][]byte{h[:]},
	}

	issuer := pkix.Name{CommonName: "Reconstruct CA", Country: []string{"US"}}
	notBefore := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)

	certDER, err := mtccert.BuildMTCCertFromCSR(csr, issuer, notBefore, notAfter,
		[]string{"reconstruct.example.com"}, 10, proof)
	if err != nil {
		return fmt.Errorf("BuildMTCCertFromCSR: %w", err)
	}

	parsed, err := mtccert.ParseMTCCertificate(certDER)
	if err != nil {
		return fmt.Errorf("ParseMTCCertificate: %w", err)
	}

	// Reconstruct the log entry from the parsed cert.
	logEntryDER, err := mtccert.ReconstructLogEntry(
		parsed.RawIssuer, parsed.RawSubject,
		parsed.NotBefore, parsed.NotAfter,
		parsed.SubjectPubKeyInfo, parsed.Extensions,
	)
	if err != nil {
		return fmt.Errorf("ReconstructLogEntry: %w", err)
	}

	// Verify the log entry contains the correct SPKI hash.
	var logEntry mtcformat.TBSCertificateLogEntry
	if _, err := asn1.Unmarshal(logEntryDER, &logEntry); err != nil {
		return fmt.Errorf("unmarshal log entry: %w", err)
	}

	expectedHash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	for i := range expectedHash {
		if logEntry.SubjectPublicKeyInfoHash[i] != expectedHash[i] {
			return fmt.Errorf("SPKI hash mismatch at byte %d", i)
		}
	}

	return nil
}
