package cosigner

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

func TestGenerateAndLoad(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test.key")

	pub, err := GenerateKey(keyFile)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// Verify file permissions.
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file permissions = %o, want 0600", perm)
	}

	// Load the key back.
	cs, err := New(keyFile, "test-key", "test.example.com/log")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !pub.Equal(cs.PublicKey()) {
		t.Error("loaded public key doesn't match generated key")
	}
	if cs.KeyID() != "test-key" {
		t.Errorf("KeyID = %q, want %q", cs.KeyID(), "test-key")
	}
}

func TestNewFromSeed(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	cs, err := NewFromSeed(seed, "seed-key", "example.com/log")
	if err != nil {
		t.Fatalf("NewFromSeed: %v", err)
	}

	// Verify it produces the same key as ed25519.NewKeyFromSeed.
	expected := ed25519.NewKeyFromSeed(seed)
	if !expected.Public().(ed25519.PublicKey).Equal(cs.PublicKey()) {
		t.Error("NewFromSeed produced wrong key")
	}
}

func TestNewFromSeedBadSize(t *testing.T) {
	_, err := NewFromSeed([]byte("short"), "key", "origin")
	if err == nil {
		t.Error("expected error for short seed")
	}
}

func TestSignAndVerifyCheckpoint(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	cs, err := NewFromSeed(seed, "test-cosigner", "test.example.com/mtc-log")
	if err != nil {
		t.Fatalf("NewFromSeed: %v", err)
	}

	rootHash := merkle.LeafHash([]byte("test root"))

	note, sig, err := cs.SignCheckpoint(42, rootHash, fixedTime())
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature size = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if note == "" {
		t.Error("note is empty")
	}

	// Verify the checkpoint.
	treeSize, parsedRoot, err := cs.VerifyCheckpoint(note)
	if err != nil {
		t.Fatalf("VerifyCheckpoint: %v", err)
	}
	if treeSize != 42 {
		t.Errorf("tree size = %d, want 42", treeSize)
	}
	if parsedRoot != rootHash {
		t.Errorf("root hash mismatch")
	}
}

func TestSignAndVerifySubtree(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	cs, err := NewFromSeed(seed, "test-cosigner", "test.example.com/mtc-log")
	if err != nil {
		t.Fatalf("NewFromSeed: %v", err)
	}

	hash := merkle.LeafHash([]byte("subtree"))
	sig, err := cs.SignSubtree(0, 256, hash)
	if err != nil {
		t.Fatalf("SignSubtree: %v", err)
	}
	if !cs.VerifySubtree(0, 256, hash, sig) {
		t.Error("VerifySubtree failed")
	}

	// Tamper with range.
	if cs.VerifySubtree(1, 256, hash, sig) {
		t.Error("VerifySubtree should fail for wrong start")
	}

	// Tamper with hash.
	badHash := merkle.LeafHash([]byte("wrong"))
	if cs.VerifySubtree(0, 256, badHash, sig) {
		t.Error("VerifySubtree should fail for wrong hash")
	}
}

func TestVerifyCheckpointBadNote(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	cs, err := NewFromSeed(seed, "test", "origin")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = cs.VerifyCheckpoint("garbage")
	if err == nil {
		t.Error("expected error for garbage note")
	}
}

// fixedTime returns a fixed time for deterministic tests.
func fixedTime() time.Time {
	return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
}

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		input string
		want  SignatureAlgorithm
		ok    bool
	}{
		{"ed25519", AlgEd25519, true},
		{"", AlgEd25519, true},
		{"mldsa44", AlgMLDSA44, true},
		{"ml-dsa-44", AlgMLDSA44, true},
		{"mldsa65", AlgMLDSA65, true},
		{"ML-DSA-65", AlgMLDSA65, true},
		{"mldsa87", AlgMLDSA87, true},
		{"unknown", 0, false},
	}

	for _, tt := range tests {
		alg, err := ParseAlgorithm(tt.input)
		if tt.ok && err != nil {
			t.Errorf("ParseAlgorithm(%q): unexpected error: %v", tt.input, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("ParseAlgorithm(%q): expected error", tt.input)
		}
		if tt.ok && alg != tt.want {
			t.Errorf("ParseAlgorithm(%q) = %v, want %v", tt.input, alg, tt.want)
		}
	}
}

func TestMLDSA65GenerateAndLoad(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa65.key")

	pubBytes, err := GenerateMLDSAKey(keyFile, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}
	if len(pubBytes) == 0 {
		t.Fatal("empty public key bytes")
	}

	// Verify file permissions.
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file permissions = %o, want 0600", perm)
	}

	// Load the key back.
	cs, err := NewMLDSA(keyFile, AlgMLDSA65, "pq-cosigner", "test.example.com/log", 1)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}
	if cs.Algorithm() != AlgMLDSA65 {
		t.Errorf("algorithm = %v, want %v", cs.Algorithm(), AlgMLDSA65)
	}
	if cs.CosignerID() != 1 {
		t.Errorf("cosignerID = %d, want 1", cs.CosignerID())
	}
	if cs.KeyID() != "pq-cosigner" {
		t.Errorf("KeyID = %q, want %q", cs.KeyID(), "pq-cosigner")
	}
}

func TestMLDSA44GenerateSignVerify(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa44.key")

	_, err := GenerateMLDSAKey(keyFile, AlgMLDSA44)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	cs, err := NewMLDSA(keyFile, AlgMLDSA44, "test44", "example.com/log", 0)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}

	msg := []byte("test message for ML-DSA-44")
	sig, err := cs.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !cs.Verify(msg, sig) {
		t.Error("Verify failed for valid ML-DSA-44 signature")
	}

	// Tamper with message.
	if cs.Verify([]byte("tampered"), sig) {
		t.Error("Verify should fail for tampered message")
	}
}

func TestMLDSA65SignVerify(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa65.key")

	_, err := GenerateMLDSAKey(keyFile, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	cs, err := NewMLDSA(keyFile, AlgMLDSA65, "test65", "example.com/log", 1)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}

	msg := []byte("test message for ML-DSA-65")
	sig, err := cs.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !cs.Verify(msg, sig) {
		t.Error("Verify failed for valid ML-DSA-65 signature")
	}
}

func TestMLDSA87SignVerify(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa87.key")

	_, err := GenerateMLDSAKey(keyFile, AlgMLDSA87)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	cs, err := NewMLDSA(keyFile, AlgMLDSA87, "test87", "example.com/log", 2)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}

	msg := []byte("test message for ML-DSA-87")
	sig, err := cs.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !cs.Verify(msg, sig) {
		t.Error("Verify failed for valid ML-DSA-87 signature")
	}
}

func TestMLDSACheckpoint(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa65.key")

	_, err := GenerateMLDSAKey(keyFile, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	cs, err := NewMLDSA(keyFile, AlgMLDSA65, "pq-cosigner", "test.example.com/log", 1)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}

	rootHash := merkle.LeafHash([]byte("test root"))
	note, _, err := cs.SignCheckpoint(100, rootHash, fixedTime())
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}

	treeSize, parsedRoot, err := cs.VerifyCheckpoint(note)
	if err != nil {
		t.Fatalf("VerifyCheckpoint: %v", err)
	}
	if treeSize != 100 {
		t.Errorf("tree size = %d, want 100", treeSize)
	}
	if parsedRoot != rootHash {
		t.Error("root hash mismatch")
	}
}

func TestMLDSASubtreeLegacy(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa65.key")

	_, err := GenerateMLDSAKey(keyFile, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	cs, err := NewMLDSA(keyFile, AlgMLDSA65, "pq-cosigner", "example.com/log", 0)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}

	hash := merkle.LeafHash([]byte("subtree"))
	sig, err := cs.SignSubtree(0, 256, hash)
	if err != nil {
		t.Fatalf("SignSubtree: %v", err)
	}
	if !cs.VerifySubtree(0, 256, hash, sig) {
		t.Error("VerifySubtree failed")
	}
	if cs.VerifySubtree(1, 256, hash, sig) {
		t.Error("VerifySubtree should fail for wrong start")
	}
}

func TestSignSubtreeMTC(t *testing.T) {
	// Test with Ed25519.
	seed := make([]byte, ed25519.SeedSize)
	ed25519CS, err := NewFromSeed(seed, "ed-cosigner", "example.com/log")
	if err != nil {
		t.Fatalf("NewFromSeed: %v", err)
	}
	ed25519CS.SetCosignerID(0)

	logID := []byte("test-log-id-0123456789abcdef")
	hash := merkle.LeafHash([]byte("subtree data"))

	mtcSig, err := ed25519CS.SignSubtreeMTC(logID, 0, 100, hash)
	if err != nil {
		t.Fatalf("SignSubtreeMTC (ed25519): %v", err)
	}
	if mtcSig.CosignerID != 0 {
		t.Errorf("cosigner ID = %d, want 0", mtcSig.CosignerID)
	}
	if !ed25519CS.VerifySubtreeMTC(logID, 0, 100, hash, mtcSig) {
		t.Error("VerifySubtreeMTC (ed25519) failed")
	}

	// Tamper with range.
	if ed25519CS.VerifySubtreeMTC(logID, 1, 100, hash, mtcSig) {
		t.Error("VerifySubtreeMTC should fail for wrong start")
	}

	// Test with ML-DSA-65.
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa65.key")
	_, err = GenerateMLDSAKey(keyFile, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	mldsaCS, err := NewMLDSA(keyFile, AlgMLDSA65, "pq-cosigner", "example.com/log", 1)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}

	mtcSig2, err := mldsaCS.SignSubtreeMTC(logID, 0, 100, hash)
	if err != nil {
		t.Fatalf("SignSubtreeMTC (mldsa65): %v", err)
	}
	if mtcSig2.CosignerID != 1 {
		t.Errorf("cosigner ID = %d, want 1", mtcSig2.CosignerID)
	}
	if !mldsaCS.VerifySubtreeMTC(logID, 0, 100, hash, mtcSig2) {
		t.Error("VerifySubtreeMTC (mldsa65) failed")
	}

	// Tamper with hash.
	badHash := merkle.LeafHash([]byte("wrong"))
	if mldsaCS.VerifySubtreeMTC(logID, 0, 100, badHash, mtcSig2) {
		t.Error("VerifySubtreeMTC should fail for wrong hash")
	}
}

func TestSignSubtreeMTCSignatureFormat(t *testing.T) {
	// Verify the MTCSignature can be marshaled into a proof.
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa65.key")
	_, err := GenerateMLDSAKey(keyFile, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey: %v", err)
	}

	cs, err := NewMLDSA(keyFile, AlgMLDSA65, "pq-cosigner", "example.com/log", 42)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}

	logID := []byte("log-id")
	hash := merkle.LeafHash([]byte("data"))

	mtcSig, err := cs.SignSubtreeMTC(logID, 10, 20, hash)
	if err != nil {
		t.Fatalf("SignSubtreeMTC: %v", err)
	}

	// Build a full MTCProof containing this signature.
	proof := &mtcformat.MTCProof{
		Start:          10,
		End:            20,
		InclusionProof: [][]byte{hash[:]},
		Signatures:     []mtcformat.MTCSignature{mtcSig},
	}

	encoded, err := mtcformat.MarshalProof(proof)
	if err != nil {
		t.Fatalf("MarshalProof: %v", err)
	}

	decoded, err := mtcformat.UnmarshalProof(encoded)
	if err != nil {
		t.Fatalf("UnmarshalProof: %v", err)
	}

	if len(decoded.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(decoded.Signatures))
	}
	if decoded.Signatures[0].CosignerID != 42 {
		t.Errorf("cosigner ID = %d, want 42", decoded.Signatures[0].CosignerID)
	}

	// Verify the signature from the round-tripped proof.
	if !cs.VerifySubtreeMTC(logID, 10, 20, hash, decoded.Signatures[0]) {
		t.Error("VerifySubtreeMTC failed after proof round-trip")
	}
}

func TestGenerateMLDSAKeyBadAlgorithm(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "bad.key")
	_, err := GenerateMLDSAKey(keyFile, AlgEd25519)
	if err == nil {
		t.Error("expected error for non-ML-DSA algorithm")
	}
}

func TestNewMLDSABadAlgorithm(t *testing.T) {
	_, err := NewMLDSA("/dev/null", AlgEd25519, "key", "origin", 0)
	if err == nil {
		t.Error("expected error for non-ML-DSA algorithm")
	}
}

func TestPublicKeyBytes(t *testing.T) {
	// Ed25519.
	seed := make([]byte, ed25519.SeedSize)
	ed25519CS, _ := NewFromSeed(seed, "key", "origin")
	if len(ed25519CS.PublicKeyBytes()) != ed25519.PublicKeySize {
		t.Errorf("Ed25519 PublicKeyBytes length = %d, want %d", len(ed25519CS.PublicKeyBytes()), ed25519.PublicKeySize)
	}

	// ML-DSA-65.
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "mldsa65.key")
	_, _ = GenerateMLDSAKey(keyFile, AlgMLDSA65)
	mldsaCS, _ := NewMLDSA(keyFile, AlgMLDSA65, "key", "origin", 0)
	if len(mldsaCS.PublicKeyBytes()) == 0 {
		t.Error("ML-DSA-65 PublicKeyBytes is empty")
	}
	// ML-DSA-65 public key is 1952 bytes.
	if len(mldsaCS.PublicKeyBytes()) != 1952 {
		t.Errorf("ML-DSA-65 PublicKeyBytes length = %d, want 1952", len(mldsaCS.PublicKeyBytes()))
	}
}
