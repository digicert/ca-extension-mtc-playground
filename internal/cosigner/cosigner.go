// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package cosigner implements key management and checkpoint/subtree signing
// for the MTC issuance log. Supports Ed25519 and ML-DSA (post-quantum) algorithms.
package cosigner

import (
	"crypto"
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
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// SignatureAlgorithm identifies the cosigner's cryptographic algorithm.
type SignatureAlgorithm uint8

const (
	AlgEd25519 SignatureAlgorithm = iota
	AlgMLDSA44
	AlgMLDSA65
	AlgMLDSA87
)

// String returns the algorithm name.
func (a SignatureAlgorithm) String() string {
	switch a {
	case AlgEd25519:
		return "ed25519"
	case AlgMLDSA44:
		return "mldsa44"
	case AlgMLDSA65:
		return "mldsa65"
	case AlgMLDSA87:
		return "mldsa87"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

// ParseAlgorithm parses a string algorithm name.
func ParseAlgorithm(s string) (SignatureAlgorithm, error) {
	switch strings.ToLower(s) {
	case "ed25519", "":
		return AlgEd25519, nil
	case "mldsa44", "ml-dsa-44":
		return AlgMLDSA44, nil
	case "mldsa65", "ml-dsa-65":
		return AlgMLDSA65, nil
	case "mldsa87", "ml-dsa-87":
		return AlgMLDSA87, nil
	default:
		return 0, fmt.Errorf("cosigner: unknown algorithm %q", s)
	}
}

// Cosigner signs checkpoints and subtrees. Supports Ed25519 and ML-DSA algorithms.
type Cosigner struct {
	algorithm  SignatureAlgorithm
	privateKey ed25519.PrivateKey // used when algorithm == AlgEd25519
	publicKey  ed25519.PublicKey  // used when algorithm == AlgEd25519
	mldsaKey   crypto.Signer     // used when algorithm == AlgMLDSA*
	mldsaPub   []byte            // packed ML-DSA public key bytes
	keyID      string
	keyHash    uint32 // first 4 bytes of SHA-256(name || 0x0a || pubkey) — C2SP key hash
	origin     string // log origin for checkpoint identity
	cosignerID []byte // TrustAnchorID for MTCSignature (variable-length)
}

// New creates a Cosigner from a PEM-encoded Ed25519 private key file.
// This is the backward-compatible constructor. For ML-DSA keys, use NewMLDSA.
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
		algorithm:  AlgEd25519,
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
		algorithm:  AlgEd25519,
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      keyID,
		origin:     origin,
	}
	c.keyHash = c.computeKeyHash()

	return c, nil
}

// NewMLDSA creates a Cosigner from a PEM-encoded ML-DSA private key file.
func NewMLDSA(keyFile string, algorithm SignatureAlgorithm, keyID, origin string, cosignerID []byte) (*Cosigner, error) {
	if algorithm != AlgMLDSA44 && algorithm != AlgMLDSA65 && algorithm != AlgMLDSA87 {
		return nil, fmt.Errorf("cosigner.NewMLDSA: expected ML-DSA algorithm, got %s", algorithm)
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("cosigner.NewMLDSA: read key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("cosigner.NewMLDSA: no PEM block found in %s", keyFile)
	}

	c := &Cosigner{
		algorithm:  algorithm,
		keyID:      keyID,
		origin:     origin,
		cosignerID: cosignerID,
	}

	switch algorithm {
	case AlgMLDSA44:
		var sk mldsa44.PrivateKey
		if err := sk.UnmarshalBinary(block.Bytes); err != nil {
			return nil, fmt.Errorf("cosigner.NewMLDSA: unpack mldsa44 key: %w", err)
		}
		pk := sk.Public().(*mldsa44.PublicKey)
		c.mldsaKey = &sk
		c.mldsaPub, _ = pk.MarshalBinary()

	case AlgMLDSA65:
		var sk mldsa65.PrivateKey
		if err := sk.UnmarshalBinary(block.Bytes); err != nil {
			return nil, fmt.Errorf("cosigner.NewMLDSA: unpack mldsa65 key: %w", err)
		}
		pk := sk.Public().(*mldsa65.PublicKey)
		c.mldsaKey = &sk
		c.mldsaPub, _ = pk.MarshalBinary()

	case AlgMLDSA87:
		var sk mldsa87.PrivateKey
		if err := sk.UnmarshalBinary(block.Bytes); err != nil {
			return nil, fmt.Errorf("cosigner.NewMLDSA: unpack mldsa87 key: %w", err)
		}
		pk := sk.Public().(*mldsa87.PublicKey)
		c.mldsaKey = &sk
		c.mldsaPub, _ = pk.MarshalBinary()
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

// GenerateMLDSAKey generates a new ML-DSA key pair and saves the private key to a PEM file.
// Returns the packed public key bytes.
func GenerateMLDSAKey(keyFile string, algorithm SignatureAlgorithm) ([]byte, error) {
	var privBytes, pubBytes []byte
	var pemType string

	switch algorithm {
	case AlgMLDSA44:
		pk, sk, err := mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("cosigner.GenerateMLDSAKey: %w", err)
		}
		privBytes, _ = sk.MarshalBinary()
		pubBytes, _ = pk.MarshalBinary()
		pemType = "ML-DSA-44 PRIVATE KEY"

	case AlgMLDSA65:
		pk, sk, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("cosigner.GenerateMLDSAKey: %w", err)
		}
		privBytes, _ = sk.MarshalBinary()
		pubBytes, _ = pk.MarshalBinary()
		pemType = "ML-DSA-65 PRIVATE KEY"

	case AlgMLDSA87:
		pk, sk, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("cosigner.GenerateMLDSAKey: %w", err)
		}
		privBytes, _ = sk.MarshalBinary()
		pubBytes, _ = pk.MarshalBinary()
		pemType = "ML-DSA-87 PRIVATE KEY"

	default:
		return nil, fmt.Errorf("cosigner.GenerateMLDSAKey: not an ML-DSA algorithm: %s", algorithm)
	}

	block := &pem.Block{
		Type:  pemType,
		Bytes: privBytes,
	}

	f, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("cosigner.GenerateMLDSAKey: create file: %w", err)
	}
	defer f.Close()

	if err := pem.Encode(f, block); err != nil {
		return nil, fmt.Errorf("cosigner.GenerateMLDSAKey: encode PEM: %w", err)
	}

	return pubBytes, nil
}

// Algorithm returns the cosigner's signature algorithm.
func (c *Cosigner) Algorithm() SignatureAlgorithm {
	return c.algorithm
}

// CosignerID returns the cosigner's TrustAnchorID for MTCSignature.
func (c *Cosigner) CosignerID() []byte {
	return c.cosignerID
}

// SetCosignerID sets the cosigner's TrustAnchorID.
func (c *Cosigner) SetCosignerID(id []byte) {
	c.cosignerID = id
}

// PublicKey returns the Ed25519 public key. Panics if not an Ed25519 cosigner.
func (c *Cosigner) PublicKey() ed25519.PublicKey {
	return c.publicKey
}

// PublicKeyBytes returns the raw public key bytes regardless of algorithm.
func (c *Cosigner) PublicKeyBytes() []byte {
	if c.algorithm == AlgEd25519 {
		return []byte(c.publicKey)
	}
	return c.mldsaPub
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
	return hex.EncodeToString(c.PublicKeyBytes())
}

// Sign signs an arbitrary message using the cosigner's algorithm.
func (c *Cosigner) Sign(msg []byte) ([]byte, error) {
	switch c.algorithm {
	case AlgEd25519:
		return ed25519.Sign(c.privateKey, msg), nil
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		return c.mldsaKey.Sign(rand.Reader, msg, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("cosigner: unsupported algorithm %s", c.algorithm)
	}
}

// Verify verifies a signature over msg using the cosigner's public key.
func (c *Cosigner) Verify(msg, sig []byte) bool {
	switch c.algorithm {
	case AlgEd25519:
		return ed25519.Verify(c.publicKey, msg, sig)
	case AlgMLDSA44:
		pk := new(mldsa44.PublicKey)
		if err := pk.UnmarshalBinary(c.mldsaPub); err != nil {
			return false
		}
		return mldsa44.Verify(pk, msg, nil, sig)
	case AlgMLDSA65:
		pk := new(mldsa65.PublicKey)
		if err := pk.UnmarshalBinary(c.mldsaPub); err != nil {
			return false
		}
		return mldsa65.Verify(pk, msg, nil, sig)
	case AlgMLDSA87:
		pk := new(mldsa87.PublicKey)
		if err := pk.UnmarshalBinary(c.mldsaPub); err != nil {
			return false
		}
		return mldsa87.Verify(pk, msg, nil, sig)
	default:
		return false
	}
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
	sig, err := c.Sign([]byte(body))
	if err != nil {
		return "", nil, fmt.Errorf("cosigner.SignCheckpoint: %w", err)
	}

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
		if len(sigData) < 5 { // at least 4 bytes key hash + 1 byte sig
			continue
		}

		sig := sigData[4:] // skip key hash
		if c.Verify([]byte(body), sig) {
			return treeSize, rootHash, nil
		}
	}

	return 0, merkle.Hash{}, fmt.Errorf("cosigner.VerifyCheckpoint: no valid signature found")
}

// SignSubtree signs a subtree hash for the given range [start, end).
// This is the legacy format. For MTC-spec compliant signing, use SignSubtreeMTC.
func (c *Cosigner) SignSubtree(start, end int64, hash merkle.Hash) ([]byte, error) {
	// Message: start (8 bytes BE) || end (8 bytes BE) || hash (32 bytes)
	msg := make([]byte, 8+8+merkle.HashSize)
	binary.BigEndian.PutUint64(msg[0:8], uint64(start))
	binary.BigEndian.PutUint64(msg[8:16], uint64(end))
	copy(msg[16:], hash[:])

	return c.Sign(msg)
}

// VerifySubtree verifies a subtree signature (legacy format).
func (c *Cosigner) VerifySubtree(start, end int64, hash merkle.Hash, sig []byte) bool {
	msg := make([]byte, 8+8+merkle.HashSize)
	binary.BigEndian.PutUint64(msg[0:8], uint64(start))
	binary.BigEndian.PutUint64(msg[8:16], uint64(end))
	copy(msg[16:], hash[:])

	return c.Verify(msg, sig)
}

// SignSubtreeMTC signs a subtree per MTC spec §5.4.1 (MTCSubtreeSignatureInput).
// Returns an MTCSignature suitable for inclusion in an MTCProof.
func (c *Cosigner) SignSubtreeMTC(logID []byte, start, end int64, hash merkle.Hash) (mtcformat.MTCSignature, error) {
	input, err := mtcformat.BuildSubtreeSignatureInput(c.cosignerID, logID, uint64(start), uint64(end), hash[:])
	if err != nil {
		return mtcformat.MTCSignature{}, fmt.Errorf("cosigner.SignSubtreeMTC: build input: %w", err)
	}

	sig, err := c.Sign(input)
	if err != nil {
		return mtcformat.MTCSignature{}, fmt.Errorf("cosigner.SignSubtreeMTC: sign: %w", err)
	}

	return mtcformat.MTCSignature{
		CosignerID: c.cosignerID,
		Signature:  sig,
	}, nil
}

// VerifySubtreeMTC verifies a subtree signature per MTC spec §5.4.1.
func (c *Cosigner) VerifySubtreeMTC(logID []byte, start, end int64, hash merkle.Hash, sig mtcformat.MTCSignature) bool {
	input, err := mtcformat.BuildSubtreeSignatureInput(sig.CosignerID, logID, uint64(start), uint64(end), hash[:])
	if err != nil {
		return false
	}

	return c.Verify(input, sig.Signature)
}

// computeKeyHash computes the C2SP key hash: first 4 bytes of SHA-256("<name>\n<pubkey>").
func (c *Cosigner) computeKeyHash() uint32 {
	h := sha256.New()
	h.Write([]byte(c.keyID + "\n"))
	h.Write(c.PublicKeyBytes())
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
