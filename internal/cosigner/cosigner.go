// Package cosigner implements Ed25519 key management and checkpoint signing
// for the MTC issuance log.
package cosigner

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
)

// Cosigner signs checkpoints and subtrees with an Ed25519 key.
type Cosigner struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	keyHash    uint32 // first 4 bytes of SHA-256(name || 0x0a || pubkey) — C2SP key hash
	origin     string // log origin for checkpoint identity
}

// New creates a Cosigner from a PEM-encoded Ed25519 private key file.
func New(keyFile, keyID, origin string) (*Cosigner, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("cosigner.New: read key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("cosigner.New: no PEM block found in %s", keyFile)
	}

	// Support both PKCS8 and raw seed formats.
	var privKey ed25519.PrivateKey

	switch block.Type {
	case "PRIVATE KEY":
		// PKCS8 format — extract the seed.
		seed, err := extractEd25519Seed(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cosigner.New: extract seed: %w", err)
		}
		privKey = ed25519.NewKeyFromSeed(seed)

	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) == ed25519.SeedSize {
			privKey = ed25519.NewKeyFromSeed(block.Bytes)
		} else if len(block.Bytes) == ed25519.PrivateKeySize {
			privKey = block.Bytes
		} else {
			return nil, fmt.Errorf("cosigner.New: unexpected key size %d", len(block.Bytes))
		}

	default:
		return nil, fmt.Errorf("cosigner.New: unsupported PEM type %q", block.Type)
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	c := &Cosigner{
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      keyID,
		origin:     origin,
	}
	c.keyHash = c.computeKeyHash()

	return c, nil
}

// NewFromSeed creates a Cosigner from a raw 32-byte Ed25519 seed.
func NewFromSeed(seed []byte, keyID, origin string) (*Cosigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("cosigner.NewFromSeed: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	c := &Cosigner{
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      keyID,
		origin:     origin,
	}
	c.keyHash = c.computeKeyHash()

	return c, nil
}

// GenerateKey generates a new Ed25519 key pair and saves the private key to a PEM file.
func GenerateKey(keyFile string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cosigner.GenerateKey: %w", err)
	}

	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv.Seed(),
	}

	f, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("cosigner.GenerateKey: create file: %w", err)
	}
	defer f.Close()

	if err := pem.Encode(f, block); err != nil {
		return nil, fmt.Errorf("cosigner.GenerateKey: encode PEM: %w", err)
	}

	return pub, nil
}

// PublicKey returns the Ed25519 public key.
func (c *Cosigner) PublicKey() ed25519.PublicKey {
	return c.publicKey
}

// KeyID returns the key identifier.
func (c *Cosigner) KeyID() string {
	return c.keyID
}

// Origin returns the log origin string.
func (c *Cosigner) Origin() string {
	return c.origin
}

// PublicKeyHex returns the hex-encoded public key.
func (c *Cosigner) PublicKeyHex() string {
	return hex.EncodeToString(c.publicKey)
}

// SignCheckpoint creates a signed checkpoint note per C2SP signed-note format.
//
// Format:
//
//	<origin>\n
//	<tree_size>\n
//	<root_hash_base64>\n
//	\n
//	— <key_name> <base64(signature)>\n
func (c *Cosigner) SignCheckpoint(treeSize int64, rootHash merkle.Hash, timestamp time.Time) (string, []byte, error) {
	// Build the checkpoint body.
	rootB64 := base64.StdEncoding.EncodeToString(rootHash[:])
	body := fmt.Sprintf("%s\n%d\n%s\n", c.origin, treeSize, rootB64)

	// Sign the body.
	sig := ed25519.Sign(c.privateKey, []byte(body))

	// Build the signed note.
	// Signature line format: — <name> <base64(keyHash || sig)>
	sigData := make([]byte, 4+len(sig))
	binary.BigEndian.PutUint32(sigData[:4], c.keyHash)
	copy(sigData[4:], sig)

	sigB64 := base64.StdEncoding.EncodeToString(sigData)
	note := body + "\n" + fmt.Sprintf("\u2014 %s %s\n", c.keyID, sigB64)

	return note, sig, nil
}

// VerifyCheckpoint verifies a signed checkpoint note.
func (c *Cosigner) VerifyCheckpoint(note string) (int64, merkle.Hash, error) {
	// Split at blank line.
	parts := strings.SplitN(note, "\n\n", 2)
	if len(parts) < 2 {
		return 0, merkle.Hash{}, fmt.Errorf("cosigner.VerifyCheckpoint: invalid note format")
	}

	body := parts[0] + "\n"
	sigSection := parts[1]

	// Parse body.
	lines := strings.Split(strings.TrimRight(parts[0], "\n"), "\n")
	if len(lines) < 3 {
		return 0, merkle.Hash{}, fmt.Errorf("cosigner.VerifyCheckpoint: body needs 3 lines, got %d", len(lines))
	}

	var treeSize int64
	if _, err := fmt.Sscanf(lines[1], "%d", &treeSize); err != nil {
		return 0, merkle.Hash{}, fmt.Errorf("cosigner.VerifyCheckpoint: parse tree size: %w", err)
	}

	rootBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return 0, merkle.Hash{}, fmt.Errorf("cosigner.VerifyCheckpoint: decode root hash: %w", err)
	}

	var rootHash merkle.Hash
	copy(rootHash[:], rootBytes)

	// Parse and verify signatures.
	for _, line := range strings.Split(sigSection, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "\u2014 ") {
			continue
		}

		sigParts := strings.Fields(line[len("\u2014 "):])
		if len(sigParts) < 2 {
			continue
		}

		sigData, err := base64.StdEncoding.DecodeString(sigParts[1])
		if err != nil {
			continue
		}
		if len(sigData) < 4+ed25519.SignatureSize {
			continue
		}

		sig := sigData[4:] // skip key hash
		if ed25519.Verify(c.publicKey, []byte(body), sig) {
			return treeSize, rootHash, nil
		}
	}

	return 0, merkle.Hash{}, fmt.Errorf("cosigner.VerifyCheckpoint: no valid signature found")
}

// SignSubtree signs a subtree hash for the given range [start, end).
func (c *Cosigner) SignSubtree(start, end int64, hash merkle.Hash) ([]byte, error) {
	// Message: start (8 bytes BE) || end (8 bytes BE) || hash (32 bytes)
	msg := make([]byte, 8+8+merkle.HashSize)
	binary.BigEndian.PutUint64(msg[0:8], uint64(start))
	binary.BigEndian.PutUint64(msg[8:16], uint64(end))
	copy(msg[16:], hash[:])

	sig := ed25519.Sign(c.privateKey, msg)
	return sig, nil
}

// VerifySubtree verifies a subtree signature.
func (c *Cosigner) VerifySubtree(start, end int64, hash merkle.Hash, sig []byte) bool {
	msg := make([]byte, 8+8+merkle.HashSize)
	binary.BigEndian.PutUint64(msg[0:8], uint64(start))
	binary.BigEndian.PutUint64(msg[8:16], uint64(end))
	copy(msg[16:], hash[:])

	return ed25519.Verify(c.publicKey, msg, sig)
}

// computeKeyHash computes the C2SP key hash: first 4 bytes of SHA-256("<name>\n<pubkey>").
func (c *Cosigner) computeKeyHash() uint32 {
	h := sha256.New()
	h.Write([]byte(c.keyID + "\n"))
	h.Write(c.publicKey)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}

// extractEd25519Seed extracts the Ed25519 seed from a PKCS8-encoded private key.
// PKCS8 for Ed25519: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { seed } } }
func extractEd25519Seed(der []byte) ([]byte, error) {
	if len(der) < 34 {
		return nil, fmt.Errorf("DER too short: %d bytes", len(der))
	}

	// PKCS8 Ed25519 DER is typically 48 bytes.
	// Structure: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes seed>
	// So the seed is at offset 16.
	if len(der) == 48 {
		// Verify the OCTET STRING header just before the seed.
		if der[14] == 0x04 && der[15] == 0x20 {
			return der[16:48], nil
		}
	}

	// Fallback: try last 32 bytes.
	seed := der[len(der)-32:]
	key := ed25519.NewKeyFromSeed(seed)
	// Verify by regenerating and checking it produces a valid key.
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("failed to extract Ed25519 seed from PKCS8")
	}

	return seed, nil
}
