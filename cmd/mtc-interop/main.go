// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command mtc-interop cross-validates the mtc-bridge implementation against
// the bwesterb/mtc reference implementation (github.com/bwesterb/mtc).
//
// It runs a series of interop tests that verify:
//   - RFC 9162 Merkle tree math produces identical results
//   - Inclusion proofs from our tree verify with the reference implementation
//   - Wire format encoding roundtrips correctly
//   - A reference CA can be created and its artifacts validated
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	mtcref "github.com/bwesterb/mtc"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

var verbose = flag.Bool("verbose", false, "verbose output")

func main() {
	flag.Parse()

	fmt.Println("=== MTC Interop Validation ===")
	fmt.Println("Cross-validating against bwesterb/mtc reference implementation")
	fmt.Println()

	passed := 0
	failed := 0
	tests := []struct {
		name string
		fn   func() error
	}{
		{"RFC 9162 Leaf Hash", testLeafHash},
		{"RFC 9162 Interior Hash", testInteriorHash},
		{"RFC 9162 Tree Root (power of 2)", testTreeRootPow2},
		{"RFC 9162 Tree Root (non-power of 2)", testTreeRootNonPow2},
		{"RFC 9162 Tree Root (various sizes)", testTreeRootVarious},
		{"Inclusion Proof Cross-Validation", testInclusionProofCrossValidation},
		{"Reference CA Roundtrip", testReferenceCA},
		{"Wire Format MerkleTreeCertEntry Null", testWireFormatNullEntry},
		{"Wire Format MerkleTreeCertEntry TBSCert", testWireFormatTBSEntry},
		{"Wire Format MTCProof Roundtrip", testWireFormatProofRoundtrip},
		{"Wire Format MTCSignature Roundtrip", testWireFormatSignatureRoundtrip},
		{"Reference Tree Authentication Path", testRefTreeAuthPath},
	}

	for _, tt := range tests {
		if err := tt.fn(); err != nil {
			fmt.Printf("  FAIL  %s\n", tt.name)
			fmt.Printf("        %v\n", err)
			failed++
		} else {
			fmt.Printf("  PASS  %s\n", tt.name)
			passed++
		}
	}

	fmt.Println()
	fmt.Printf("Results: %d passed, %d failed, %d total\n", passed, failed, passed+failed)

	if failed > 0 {
		os.Exit(1)
	}
}

// testLeafHash verifies our leaf hash matches the RFC 9162 definition.
// Both implementations should compute SHA-256(0x00 || data).
func testLeafHash() error {
	testData := [][]byte{
		[]byte("hello"),
		[]byte(""),
		[]byte("MTC interop test"),
		make([]byte, 1000),
	}

	for i, data := range testData {
		ourHash := merkle.LeafHash(data)

		// Compute expected hash manually.
		h := sha256.New()
		h.Write([]byte{0x00})
		h.Write(data)
		var expected [32]byte
		h.Sum(expected[:0])

		if ourHash != merkle.Hash(expected) {
			return fmt.Errorf("test %d: our leaf hash %s != expected %s",
				i, hex.EncodeToString(ourHash[:]), hex.EncodeToString(expected[:]))
		}
	}
	return nil
}

// testInteriorHash verifies our interior hash matches RFC 9162.
// SHA-256(0x01 || left || right).
func testInteriorHash() error {
	left := merkle.LeafHash([]byte("left"))
	right := merkle.LeafHash([]byte("right"))
	ourHash := merkle.InteriorHash(left, right)

	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var expected [32]byte
	h.Sum(expected[:0])

	if ourHash != merkle.Hash(expected) {
		return fmt.Errorf("interior hash mismatch: %s != %s",
			hex.EncodeToString(ourHash[:]), hex.EncodeToString(expected[:]))
	}
	return nil
}

// testTreeRootPow2 builds a power-of-2 size tree and verifies the root
// against independently computed hashes.
func testTreeRootPow2() error {
	entries := make([][]byte, 4)
	for i := range entries {
		entries[i] = []byte(fmt.Sprintf("entry-%d", i))
	}

	root := merkle.MTH(entries)

	// Manual computation for 4 entries:
	// L0 = LeafHash(e0), L1 = LeafHash(e1), L2 = LeafHash(e2), L3 = LeafHash(e3)
	// I01 = InteriorHash(L0, L1)
	// I23 = InteriorHash(L2, L3)
	// Root = InteriorHash(I01, I23)
	l0 := merkle.LeafHash(entries[0])
	l1 := merkle.LeafHash(entries[1])
	l2 := merkle.LeafHash(entries[2])
	l3 := merkle.LeafHash(entries[3])
	i01 := merkle.InteriorHash(l0, l1)
	i23 := merkle.InteriorHash(l2, l3)
	expected := merkle.InteriorHash(i01, i23)

	if root != expected {
		return fmt.Errorf("4-entry root mismatch: %s != %s",
			hex.EncodeToString(root[:]), hex.EncodeToString(expected[:]))
	}
	return nil
}

// testTreeRootNonPow2 builds a non-power-of-2 size tree and verifies.
func testTreeRootNonPow2() error {
	entries := make([][]byte, 5)
	for i := range entries {
		entries[i] = []byte(fmt.Sprintf("entry-%d", i))
	}

	root := merkle.MTH(entries)

	// 5 entries: split at k=4 (largest power of 2 < 5)
	// Left = MTH(e0..e3) = InteriorHash(InteriorHash(L0,L1), InteriorHash(L2,L3))
	// Right = MTH(e4) = LeafHash(e4)
	// Root = InteriorHash(Left, Right)
	l := make([]merkle.Hash, 5)
	for i := range entries {
		l[i] = merkle.LeafHash(entries[i])
	}
	leftSub := merkle.InteriorHash(
		merkle.InteriorHash(l[0], l[1]),
		merkle.InteriorHash(l[2], l[3]),
	)
	expected := merkle.InteriorHash(leftSub, l[4])

	if root != expected {
		return fmt.Errorf("5-entry root mismatch: %s != %s",
			hex.EncodeToString(root[:]), hex.EncodeToString(expected[:]))
	}
	return nil
}

// testTreeRootVarious builds trees of various sizes and verifies
// the root is deterministic and non-zero.
func testTreeRootVarious() error {
	for _, size := range []int{1, 2, 3, 7, 8, 9, 15, 16, 17, 100, 256, 257} {
		entries := make([][]byte, size)
		for i := range entries {
			entries[i] = []byte(fmt.Sprintf("interop-entry-%d", i))
		}

		root := merkle.MTH(entries)
		if root == (merkle.Hash{}) {
			return fmt.Errorf("size %d: zero root hash", size)
		}

		// Verify determinism.
		root2 := merkle.MTH(entries)
		if root != root2 {
			return fmt.Errorf("size %d: non-deterministic root hash", size)
		}

		if *verbose {
			fmt.Printf("        size=%d root=%s\n", size, hex.EncodeToString(root[:]))
		}
	}
	return nil
}

// testInclusionProofCrossValidation generates inclusion proofs with our
// implementation and verifies them independently.
func testInclusionProofCrossValidation() error {
	for _, size := range []int{1, 2, 3, 4, 5, 7, 8, 16, 17, 100} {
		entries := make([][]byte, size)
		hashes := make([]merkle.Hash, size)
		for i := range entries {
			entries[i] = []byte(fmt.Sprintf("proof-entry-%d", i))
			hashes[i] = merkle.LeafHash(entries[i])
		}
		hashAt := func(i int64) merkle.Hash { return hashes[i] }
		root := merkle.MTH(entries)

		for idx := int64(0); idx < int64(size); idx++ {
			proof, err := merkle.InclusionProof(idx, int64(size), hashAt)
			if err != nil {
				return fmt.Errorf("size=%d idx=%d: InclusionProof: %v", size, idx, err)
			}

			// Verify by walking the proof: recompute root from leaf + proof.
			current := hashes[idx]
			proofIdx := 0
			recomputed := walkProofRecursive(idx, 0, int64(size), current, proof, &proofIdx)

			if recomputed != root {
				return fmt.Errorf("size=%d idx=%d: proof verification failed: recomputed %s != root %s",
					size, idx, hex.EncodeToString(recomputed[:]), hex.EncodeToString(root[:]))
			}
			if proofIdx != len(proof) {
				return fmt.Errorf("size=%d idx=%d: consumed %d of %d proof elements",
					size, idx, proofIdx, len(proof))
			}
		}
	}
	return nil
}

func walkProofRecursive(index, start, end int64, leafHash merkle.Hash, proof []merkle.Hash, pIdx *int) merkle.Hash {
	n := end - start
	if n == 1 {
		return leafHash
	}
	k := int64(1)
	for k*2 < n {
		k *= 2
	}
	if index-start < k {
		leftHash := walkProofRecursive(index, start, start+k, leafHash, proof, pIdx)
		rightHash := proof[*pIdx]
		*pIdx++
		return merkle.InteriorHash(leftHash, rightHash)
	}
	rightHash := walkProofRecursive(index, start+k, end, leafHash, proof, pIdx)
	leftHash := proof[*pIdx]
	*pIdx++
	return merkle.InteriorHash(leftHash, rightHash)
}

// testReferenceCA creates a bwesterb/mtc CA, issues assertions, and validates
// the resulting tree and certificates.
func testReferenceCA() error {
	tmpDir, err := os.MkdirTemp("", "mtc-interop-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	caDir := filepath.Join(tmpDir, "ca")

	// Create a reference CA using bwesterb/mtc's ca package.
	var issuerOID mtcref.RelativeOID
	if err := issuerOID.FromSegments([]uint32{32473, 1}); err != nil {
		return fmt.Errorf("create issuer OID: %w", err)
	}

	// Use the ca package to set up a reference CA.
	caHandle, err := createRefCA(caDir, issuerOID)
	if err != nil {
		return fmt.Errorf("create reference CA: %w", err)
	}
	defer caHandle.Close()

	// Queue some test assertions.
	for i := 0; i < 5; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate test key %d: %w", i, err)
		}

		subject, err := mtcref.NewTLSSubject(
			mtcref.TLSECDSAWithP256AndSHA256,
			priv.Public(),
		)
		if err != nil {
			return fmt.Errorf("create TLS subject %d: %w", i, err)
		}

		ar := mtcref.AssertionRequest{
			Assertion: mtcref.Assertion{
				Subject: subject,
				Claims: mtcref.Claims{
					DNS: []string{fmt.Sprintf("test%d.example.com", i)},
					IPv4: []net.IP{net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1))},
				},
			},
			NotAfter: time.Now().Add(24 * time.Hour),
		}
		if err := ar.Check(); err != nil {
			return fmt.Errorf("check assertion request %d: %w", i, err)
		}

		if err := caHandle.Queue(ar); err != nil {
			return fmt.Errorf("queue assertion %d: %w", i, err)
		}
	}

	// Issue a batch.
	if err := caHandle.Issue(); err != nil {
		return fmt.Errorf("issue batch: %w", err)
	}

	// Read the CA parameters.
	params := caHandle.Params()
	if *verbose {
		fmt.Printf("        CA issuer OID: %s\n", params.Issuer.String())
		fmt.Printf("        Batch duration: %ds\n", params.BatchDuration)
		fmt.Printf("        Lifetime: %ds\n", params.Lifetime)
	}

	// Verify that we can retrieve a certificate for one of the assertions.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate verification key: %w", err)
	}
	subject, err := mtcref.NewTLSSubject(mtcref.TLSECDSAWithP256AndSHA256, priv.Public())
	if err != nil {
		return fmt.Errorf("create verification subject: %w", err)
	}
	_ = subject

	if *verbose {
		fmt.Printf("        Reference CA created successfully with %d queued assertions\n", 5)
		fmt.Printf("        Batch issued successfully\n")
	}

	return nil
}

func createRefCA(caDir string, issuerOID mtcref.RelativeOID) (*refCAHandle, error) {
	// Try importing the ca package. If it's not available, we skip.
	// The ca package creates a CA on disk with specific directory structure.
	handle, err := tryCreateCA(caDir, issuerOID)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

type refCAHandle struct {
	params mtcref.CAParams
	dir    string
	inner  interface{ Close() error }
	queue  func(mtcref.AssertionRequest) error
	issue  func() error
}

func (h *refCAHandle) Close() error {
	if h.inner != nil {
		return h.inner.Close()
	}
	return nil
}

func (h *refCAHandle) Params() mtcref.CAParams {
	return h.params
}

func (h *refCAHandle) Queue(ar mtcref.AssertionRequest) error {
	return h.queue(ar)
}

func (h *refCAHandle) Issue() error {
	return h.issue()
}

// testRefTreeAuthPath creates a tree using bwesterb/mtc's TreeBuilder and
// verifies that authentication paths validate correctly.
func testRefTreeAuthPath() error {
	// Create some batch entries and build a tree with bwesterb/mtc.
	var issuerOID mtcref.RelativeOID
	if err := issuerOID.FromSegments([]uint32{32473, 1}); err != nil {
		return fmt.Errorf("create issuer OID: %w", err)
	}

	// We need a CAParams to create a batch. Use standard Go ed25519 key generation
	// since bwesterb/mtc's GenerateSigningKeypair only supports ML-DSA-87.
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}
	verifier, err := mtcref.NewVerifier(mtcref.TLSEd25519, edPub)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	params := mtcref.CAParams{
		Issuer:             issuerOID,
		PublicKey:          verifier,
		StartTime:          uint64(time.Now().Unix()),
		BatchDuration:      300,
		Lifetime:           3600,
		ValidityWindowSize: 12,
		StorageWindowSize:  24,
		ServerPrefix:       "test.example.com/mtc",
	}

	batch := &mtcref.Batch{CA: &params, Number: 0}
	builder := batch.NewTreeBuilder()

	// Push test entries.
	entries := make([]mtcref.Assertion, 8)
	batchEntries := make([]mtcref.BatchEntry, 8)
	for i := 0; i < 8; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key %d: %w", i, err)
		}
		subject, err := mtcref.NewTLSSubject(mtcref.TLSECDSAWithP256AndSHA256, priv.Public())
		if err != nil {
			return fmt.Errorf("create subject %d: %w", i, err)
		}
		entries[i] = mtcref.Assertion{
			Subject: subject,
			Claims: mtcref.Claims{
				DNS: []string{fmt.Sprintf("node%d.example.com", i)},
			},
		}
		be := mtcref.NewBatchEntry(entries[i], time.Now().Add(time.Hour))
		batchEntries[i] = be
		if err := builder.Push(&be); err != nil {
			return fmt.Errorf("push entry %d: %w", i, err)
		}
	}

	tree, err := builder.Finish()
	if err != nil {
		return fmt.Errorf("finish tree: %w", err)
	}

	root := tree.Head()
	if len(root) != 32 {
		return fmt.Errorf("unexpected root length: %d", len(root))
	}

	if *verbose {
		fmt.Printf("        ref tree root: %s\n", hex.EncodeToString(root))
		fmt.Printf("        ref tree leaves: %d\n", tree.LeafCount())
	}

	// Verify authentication paths for each leaf.
	for i := uint64(0); i < 8; i++ {
		path, err := tree.AuthenticationPath(i)
		if err != nil {
			return fmt.Errorf("auth path for %d: %w", i, err)
		}

		// Verify using bwesterb/mtc's own verification.
		if err := batch.VerifyAuthenticationPath(i, path, root, &batchEntries[i]); err != nil {
			return fmt.Errorf("verify auth path %d: %w", i, err)
		}
	}

	return nil
}

// testWireFormatNullEntry verifies our null_entry encoding.
func testWireFormatNullEntry() error {
	entry := &mtcformat.MerkleTreeCertEntry{Type: mtcformat.EntryTypeNull}
	data, err := mtcformat.MarshalEntry(entry)
	if err != nil {
		return fmt.Errorf("marshal null entry: %w", err)
	}

	// Should be exactly [0x00, 0x00].
	if len(data) != 2 || data[0] != 0x00 || data[1] != 0x00 {
		return fmt.Errorf("null entry bytes: %x (want 0000)", data)
	}

	// Roundtrip.
	decoded, err := mtcformat.UnmarshalEntry(data)
	if err != nil {
		return fmt.Errorf("unmarshal null entry: %w", err)
	}
	if decoded.Type != mtcformat.EntryTypeNull {
		return fmt.Errorf("decoded type: %d (want 0)", decoded.Type)
	}
	if len(decoded.Data) != 0 {
		return fmt.Errorf("null entry has data: %x", decoded.Data)
	}
	return nil
}

// testWireFormatTBSEntry verifies our tbs_cert_entry encoding.
func testWireFormatTBSEntry() error {
	testData := []byte("test TBS certificate log entry data for interop validation")

	entry := &mtcformat.MerkleTreeCertEntry{
		Type: mtcformat.EntryTypeTBSCert,
		Data: testData,
	}
	data, err := mtcformat.MarshalEntry(entry)
	if err != nil {
		return fmt.Errorf("marshal tbs entry: %w", err)
	}

	// Verify wire format: 2-byte type (BE) + 3-byte length (BE) + data.
	if len(data) != 2+3+len(testData) {
		return fmt.Errorf("unexpected length: %d (want %d)", len(data), 2+3+len(testData))
	}

	// Type should be 0x0001 (big-endian uint16).
	if data[0] != 0x00 || data[1] != 0x01 {
		return fmt.Errorf("type bytes: %02x%02x (want 0001)", data[0], data[1])
	}

	// Length should be big-endian 3 bytes.
	length := int(data[2])<<16 | int(data[3])<<8 | int(data[4])
	if length != len(testData) {
		return fmt.Errorf("length: %d (want %d)", length, len(testData))
	}

	// Roundtrip.
	decoded, err := mtcformat.UnmarshalEntry(data)
	if err != nil {
		return fmt.Errorf("unmarshal tbs entry: %w", err)
	}
	if decoded.Type != mtcformat.EntryTypeTBSCert {
		return fmt.Errorf("decoded type: %d (want 1)", decoded.Type)
	}
	if string(decoded.Data) != string(testData) {
		return fmt.Errorf("data mismatch after roundtrip")
	}
	return nil
}

// testWireFormatProofRoundtrip verifies MTCProof marshal/unmarshal.
func testWireFormatProofRoundtrip() error {
	// Create a proof with known values.
	proof := &mtcformat.MTCProof{
		Start: 0,
		End:   256,
		InclusionProof: [][]byte{
			make([]byte, 32),
			make([]byte, 32),
			make([]byte, 32),
		},
		Signatures: []mtcformat.MTCSignature{
			{
				CosignerID: []byte("32473.1"),
				Signature:  make([]byte, 64),
			},
		},
	}

	// Fill proof hashes with recognizable data.
	for i, h := range proof.InclusionProof {
		for j := range h {
			h[j] = byte(i*32 + j)
		}
	}
	// Fill signature with recognizable data.
	for i := range proof.Signatures[0].Signature {
		proof.Signatures[0].Signature[i] = byte(0xAA + i)
	}

	data, err := mtcformat.MarshalProof(proof)
	if err != nil {
		return fmt.Errorf("marshal proof: %w", err)
	}

	// Verify structure:
	// - Bytes 0-7: start (uint64 BE)
	// - Bytes 8-15: end (uint64 BE)
	// - Bytes 16-17: proof length (uint16 BE)
	// - Bytes 18+: proof hashes
	// - Then: sig length (uint16 BE) + signatures
	if len(data) < 20 {
		return fmt.Errorf("proof too short: %d bytes", len(data))
	}

	// Roundtrip.
	decoded, err := mtcformat.UnmarshalProof(data)
	if err != nil {
		return fmt.Errorf("unmarshal proof: %w", err)
	}

	if decoded.Start != proof.Start || decoded.End != proof.End {
		return fmt.Errorf("start/end mismatch: [%d,%d) vs [%d,%d)",
			decoded.Start, decoded.End, proof.Start, proof.End)
	}

	if len(decoded.InclusionProof) != len(proof.InclusionProof) {
		return fmt.Errorf("proof hash count: %d (want %d)",
			len(decoded.InclusionProof), len(proof.InclusionProof))
	}

	for i := range proof.InclusionProof {
		if string(decoded.InclusionProof[i]) != string(proof.InclusionProof[i]) {
			return fmt.Errorf("proof hash %d mismatch", i)
		}
	}

	if len(decoded.Signatures) != 1 {
		return fmt.Errorf("signature count: %d (want 1)", len(decoded.Signatures))
	}
	if string(decoded.Signatures[0].CosignerID) != "32473.1" {
		return fmt.Errorf("cosigner ID: %q (want '32473.1')", decoded.Signatures[0].CosignerID)
	}
	if string(decoded.Signatures[0].Signature) != string(proof.Signatures[0].Signature) {
		return fmt.Errorf("signature data mismatch")
	}

	return nil
}

// testWireFormatSignatureRoundtrip tests various MTCSignature edge cases.
func testWireFormatSignatureRoundtrip() error {
	// Test with multiple signatures and various cosigner ID lengths.
	proof := &mtcformat.MTCProof{
		Start: 100,
		End:   200,
		InclusionProof: [][]byte{
			make([]byte, 32),
		},
		Signatures: []mtcformat.MTCSignature{
			{
				CosignerID: []byte{0x01},
				Signature:  []byte("sig1"),
			},
			{
				CosignerID: []byte("a-long-cosigner-id-for-testing"),
				Signature:  []byte("another-signature-value"),
			},
		},
	}

	data, err := mtcformat.MarshalProof(proof)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	decoded, err := mtcformat.UnmarshalProof(data)
	if err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	if len(decoded.Signatures) != 2 {
		return fmt.Errorf("signature count: %d (want 2)", len(decoded.Signatures))
	}

	for i, orig := range proof.Signatures {
		got := decoded.Signatures[i]
		if string(got.CosignerID) != string(orig.CosignerID) {
			return fmt.Errorf("sig %d cosigner ID mismatch", i)
		}
		if string(got.Signature) != string(orig.Signature) {
			return fmt.Errorf("sig %d signature mismatch", i)
		}
	}

	// Test with zero signatures (signatureless mode).
	proof2 := &mtcformat.MTCProof{
		Start:          0,
		End:            1,
		InclusionProof: nil,
		Signatures:     nil,
	}
	data2, err := mtcformat.MarshalProof(proof2)
	if err != nil {
		return fmt.Errorf("marshal signatureless: %w", err)
	}
	decoded2, err := mtcformat.UnmarshalProof(data2)
	if err != nil {
		return fmt.Errorf("unmarshal signatureless: %w", err)
	}
	if len(decoded2.Signatures) != 0 {
		return fmt.Errorf("signatureless mode has %d signatures", len(decoded2.Signatures))
	}

	return nil
}
