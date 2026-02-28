package cosigner

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
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
