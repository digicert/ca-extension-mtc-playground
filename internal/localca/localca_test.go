package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
)

// testCA creates a temporary LocalCA for testing.
func testCA(t *testing.T) *LocalCA {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "ca.key")
	certFile := filepath.Join(dir, "ca.crt")

	if err := GenerateCA(keyFile, certFile, "Test Org", "US"); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	ca, err := New(Config{
		KeyFile:  keyFile,
		CertFile: certFile,
		Validity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ca
}

// testCSR generates a test CSR with the given DNS names.
func testCSR(t *testing.T, dnsNames ...string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   dnsNames[0],
			Organization: []string{"Test Client"},
			Country:      []string{"US"},
		},
		DNSNames: dnsNames,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

func TestGenerateCA(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "ca.key")
	certFile := filepath.Join(dir, "ca.crt")

	if err := GenerateCA(keyFile, certFile, "Test Org", "US"); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Verify key file.
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatal("key file is not a valid EC PRIVATE KEY PEM")
	}

	// Verify cert file.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ = pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("cert file is not a valid CERTIFICATE PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Error("CA cert should have IsCA=true")
	}
	if cert.Subject.CommonName != "MTC Bridge Local CA" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}

	// Verify key file permissions.
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestIssuePrecert(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t, "example.com", "www.example.com")

	result, err := ca.IssuePrecert(csr, []string{"example.com", "www.example.com"}, 0)
	if err != nil {
		t.Fatalf("IssuePrecert: %v", err)
	}

	// Parse the pre-certificate.
	cert, err := x509.ParseCertificate(result.PrecertDER)
	if err != nil {
		t.Fatalf("parse precert: %v", err)
	}

	// Verify basic fields.
	if cert.Subject.CommonName != "example.com" {
		t.Errorf("CN: got %q, want %q", cert.Subject.CommonName, "example.com")
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("DNSNames: got %d, want 2", len(cert.DNSNames))
	}
	if cert.IsCA {
		t.Error("precert should not be a CA")
	}

	// Verify no MTC extension present.
	proof, err := ParseInclusionProof(cert)
	if err != nil {
		t.Fatalf("ParseInclusionProof: %v", err)
	}
	if proof != nil {
		t.Error("precert should not have MTC extension")
	}

	// Verify canonical TBS is non-empty and different from full DER.
	if len(result.CanonicalTBS) == 0 {
		t.Error("canonical TBS should not be empty")
	}
	if len(result.CanonicalTBS) >= len(result.PrecertDER) {
		t.Error("canonical TBS should be smaller than full cert DER")
	}

	// Verify serial and timestamps are set.
	if result.Serial == nil || result.Serial.Sign() <= 0 {
		t.Error("serial should be positive")
	}
	if result.NotBefore.IsZero() {
		t.Error("NotBefore should be set")
	}
}

func TestIssueWithProof(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t, "example.com")

	// Phase 1: Issue pre-certificate.
	precert, err := ca.IssuePrecert(csr, []string{"example.com"}, 0)
	if err != nil {
		t.Fatalf("IssuePrecert: %v", err)
	}

	// Create a dummy proof for testing.
	proof := &InclusionProofExt{
		LogOrigin: "localhost/mtc-bridge",
		LeafIndex: 42,
		TreeSize:  100,
		RootHash:  make([]byte, 32),
		ProofHashes: [][]byte{
			make([]byte, 32),
			make([]byte, 32),
		},
		Checkpoint: "localhost/mtc-bridge\n100\nAAAAAAAAAAAAAAAAAAAAAAAA==\n",
	}

	// Phase 2: Issue final certificate with proof.
	finalDER, err := ca.IssueWithProof(csr, precert, proof)
	if err != nil {
		t.Fatalf("IssueWithProof: %v", err)
	}

	// Parse final certificate.
	finalCert, err := x509.ParseCertificate(finalDER)
	if err != nil {
		t.Fatalf("parse final cert: %v", err)
	}

	// Verify MTC extension is present.
	parsedProof, err := ParseInclusionProof(finalCert)
	if err != nil {
		t.Fatalf("ParseInclusionProof: %v", err)
	}
	if parsedProof == nil {
		t.Fatal("final cert should have MTC extension")
	}
	if parsedProof.LeafIndex != 42 {
		t.Errorf("LeafIndex: got %d, want 42", parsedProof.LeafIndex)
	}
	if parsedProof.TreeSize != 100 {
		t.Errorf("TreeSize: got %d, want 100", parsedProof.TreeSize)
	}
	if parsedProof.LogOrigin != "localhost/mtc-bridge" {
		t.Errorf("LogOrigin: got %q", parsedProof.LogOrigin)
	}

	// Verify serial numbers match.
	if finalCert.SerialNumber.Cmp(precert.Serial) != 0 {
		t.Error("serial numbers should match between precert and final cert")
	}

	// Verify subject and SANs match.
	if finalCert.Subject.CommonName != "example.com" {
		t.Errorf("CN: got %q", finalCert.Subject.CommonName)
	}
}

func TestCanonicalTBSReconstruction(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t, "example.com", "test.example.com")

	// Phase 1: Issue pre-certificate.
	precert, err := ca.IssuePrecert(csr, []string{"example.com", "test.example.com"}, 0)
	if err != nil {
		t.Fatalf("IssuePrecert: %v", err)
	}

	// Phase 2: Issue final cert with proof.
	proof := &InclusionProofExt{
		LogOrigin:   "test-log",
		LeafIndex:   7,
		TreeSize:    16,
		RootHash:    make([]byte, 32),
		ProofHashes: [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32)},
		Checkpoint:  "test-log\n16\nBBBBBBBBBBBBBBBBBBBBBBBB==\n",
	}

	finalDER, err := ca.IssueWithProof(csr, precert, proof)
	if err != nil {
		t.Fatalf("IssueWithProof: %v", err)
	}

	// Parse final cert and strip the MTC extension.
	finalCert, err := x509.ParseCertificate(finalDER)
	if err != nil {
		t.Fatalf("parse final cert: %v", err)
	}

	strippedTBS, err := StripMTCExtension(finalCert.RawTBSCertificate)
	if err != nil {
		t.Fatalf("StripMTCExtension: %v", err)
	}

	// The stripped TBS should match the original precert's canonical TBS.
	// Note: Go's x509.CreateCertificate may produce slightly different DER
	// encodings due to extension ordering. We verify by parsing both and
	// comparing the non-extension fields, then verify that the stripped
	// version has no MTC extension.
	//
	// First, verify the stripped TBS has the same structure as the precert TBS.
	if len(strippedTBS) == 0 {
		t.Fatal("stripped TBS should not be empty")
	}

	// The key test: build entry data from both and verify leaf hashes match.
	precertEntry := BuildPrecertEntryData(precert.CanonicalTBS)
	strippedEntry := BuildPrecertEntryData(strippedTBS)

	precertLeaf := merkle.LeafHash(precertEntry)
	strippedLeaf := merkle.LeafHash(strippedEntry)

	if precertLeaf != strippedLeaf {
		t.Error("leaf hashes should match: precert canonical TBS vs stripped final cert TBS")
		t.Logf("  precert TBS len: %d", len(precert.CanonicalTBS))
		t.Logf("  stripped TBS len: %d", len(strippedTBS))
	}
}

func TestASN1RoundTrip(t *testing.T) {
	original := InclusionProofExt{
		LogOrigin: "localhost/mtc-bridge",
		LeafIndex: 12345,
		TreeSize:  67890,
		RootHash:  []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		ProofHashes: [][]byte{
			{0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			{0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		},
		Checkpoint: "localhost/mtc-bridge\n67890\nRootHashBase64==\n\n— sig-line\n",
	}

	// Marshal to extension.
	ext, err := original.MarshalExtension()
	if err != nil {
		t.Fatalf("MarshalExtension: %v", err)
	}

	if ext.Critical {
		t.Error("extension should be non-critical")
	}
	if !ext.Id.Equal(OIDMTCInclusionProof) {
		t.Errorf("OID mismatch: %v", ext.Id)
	}

	// Unmarshal from extension value.
	var decoded InclusionProofExt
	rest, err := asn1.Unmarshal(ext.Value, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("trailing data: %d bytes", len(rest))
	}

	// Compare fields.
	if decoded.LogOrigin != original.LogOrigin {
		t.Errorf("LogOrigin: got %q, want %q", decoded.LogOrigin, original.LogOrigin)
	}
	if decoded.LeafIndex != original.LeafIndex {
		t.Errorf("LeafIndex: got %d, want %d", decoded.LeafIndex, original.LeafIndex)
	}
	if decoded.TreeSize != original.TreeSize {
		t.Errorf("TreeSize: got %d, want %d", decoded.TreeSize, original.TreeSize)
	}
	if len(decoded.RootHash) != 32 {
		t.Errorf("RootHash length: got %d", len(decoded.RootHash))
	}
	for i, b := range decoded.RootHash {
		if b != original.RootHash[i] {
			t.Errorf("RootHash[%d]: got %d, want %d", i, b, original.RootHash[i])
			break
		}
	}
	if len(decoded.ProofHashes) != 2 {
		t.Fatalf("ProofHashes: got %d, want 2", len(decoded.ProofHashes))
	}
	if decoded.Checkpoint != original.Checkpoint {
		t.Errorf("Checkpoint: got %q, want %q", decoded.Checkpoint, original.Checkpoint)
	}
}

func TestBuildPrecertEntryData(t *testing.T) {
	tbs := []byte("test TBS data")
	data := BuildPrecertEntryData(tbs)

	// Check entry type (uint16 LE = 2).
	if data[0] != 2 || data[1] != 0 {
		t.Errorf("entry type: got [%d, %d], want [2, 0]", data[0], data[1])
	}

	// Check length (uint32 LE).
	length := int(data[2]) | int(data[3])<<8 | int(data[4])<<16 | int(data[5])<<24
	if length != len(tbs) {
		t.Errorf("length: got %d, want %d", length, len(tbs))
	}

	// Check payload.
	if string(data[6:]) != "test TBS data" {
		t.Errorf("payload mismatch")
	}
}

func TestExtractTBSCertificate(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t, "example.com")

	precert, err := ca.IssuePrecert(csr, []string{"example.com"}, 0)
	if err != nil {
		t.Fatalf("IssuePrecert: %v", err)
	}

	extracted, err := ExtractTBSCertificate(precert.PrecertDER)
	if err != nil {
		t.Fatalf("ExtractTBSCertificate: %v", err)
	}

	// The extracted TBS should match what Go's parser gives us.
	cert, _ := x509.ParseCertificate(precert.PrecertDER)
	if len(extracted) != len(cert.RawTBSCertificate) {
		t.Errorf("TBS length mismatch: extracted=%d, RawTBSCertificate=%d",
			len(extracted), len(cert.RawTBSCertificate))
	}
	for i := range extracted {
		if extracted[i] != cert.RawTBSCertificate[i] {
			t.Errorf("TBS byte mismatch at position %d", i)
			break
		}
	}
}

func TestVerifyEmbeddedProof(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t, "example.com")

	// Phase 1: Issue pre-certificate.
	precert, err := ca.IssuePrecert(csr, []string{"example.com"}, 0)
	if err != nil {
		t.Fatalf("IssuePrecert: %v", err)
	}

	// Simulate the Merkle tree: create a small tree with this entry.
	entryData := BuildPrecertEntryData(precert.CanonicalTBS)
	leafHash := merkle.LeafHash(entryData)

	// Build a tree with 4 entries (our cert at index 0, plus 3 dummy entries).
	leaves := [][]byte{
		entryData,
		{0x00, 0x00, 1, 0, 0, 0, 0xAA},
		{0x00, 0x00, 1, 0, 0, 0, 0xBB},
		{0x00, 0x00, 1, 0, 0, 0, 0xCC},
	}
	rootHash := merkle.MTH(leaves)

	// Compute inclusion proof for index 0, tree size 4.
	hashAt := func(idx int64) merkle.Hash { return merkle.LeafHash(leaves[idx]) }
	proofHashes, err := merkle.InclusionProof(0, 4, hashAt)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}

	// Verify the proof works with our leaf hash.
	if !merkle.VerifyInclusion(leafHash, 0, 4, proofHashes, rootHash) {
		t.Fatal("proof should verify before embedding")
	}

	// Convert to extension format.
	proofBytes := make([][]byte, len(proofHashes))
	for i, h := range proofHashes {
		ph := make([]byte, 32)
		copy(ph, h[:])
		proofBytes[i] = ph
	}
	proofExt := &InclusionProofExt{
		LogOrigin:   "test-log",
		LeafIndex:   0,
		TreeSize:    4,
		RootHash:    rootHash[:],
		ProofHashes: proofBytes,
		Checkpoint:  "test-log\n4\nTest==\n",
	}

	// Phase 2: Issue final cert with embedded proof.
	finalDER, err := ca.IssueWithProof(csr, precert, proofExt)
	if err != nil {
		t.Fatalf("IssueWithProof: %v", err)
	}

	// Verify the embedded proof.
	parsedProof, ok, err := VerifyEmbeddedProof(finalDER)
	if err != nil {
		t.Fatalf("VerifyEmbeddedProof: %v", err)
	}
	if !ok {
		t.Error("embedded proof should verify")
	}
	if parsedProof.LeafIndex != 0 {
		t.Errorf("LeafIndex: got %d, want 0", parsedProof.LeafIndex)
	}
	if parsedProof.TreeSize != 4 {
		t.Errorf("TreeSize: got %d, want 4", parsedProof.TreeSize)
	}
}

func TestVerifyEmbeddedProof_NoExtension(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t, "example.com")

	precert, err := ca.IssuePrecert(csr, []string{"example.com"}, 0)
	if err != nil {
		t.Fatalf("IssuePrecert: %v", err)
	}

	// Verifying a cert with no MTC extension should fail gracefully.
	_, _, err = VerifyEmbeddedProof(precert.PrecertDER)
	if err == nil {
		t.Error("should fail when no MTC extension present")
	}
}

func TestParseInclusionProof_Missing(t *testing.T) {
	// Create a cert without MTC extension.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	proof, err := ParseInclusionProof(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proof != nil {
		t.Error("should return nil when extension not found")
	}
}
