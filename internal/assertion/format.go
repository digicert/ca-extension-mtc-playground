package assertion

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
)

// FormatJSON marshals the bundle to indented JSON.
func FormatJSON(bundle *Bundle) ([]byte, error) {
	return json.MarshalIndent(bundle, "", "  ")
}

// FormatPEM produces a PEM-like text format for the assertion bundle.
// This is a human-readable format suitable for file storage and CLI output.
//
// Format:
//
//	-----BEGIN MTC ASSERTION BUNDLE-----
//	Log-Origin: <origin>
//	Leaf-Index: <index>
//	Tree-Size: <size>
//	Root-Hash: <hex>
//	Leaf-Hash: <hex>
//	Serial: <hex>
//	Revoked: <true|false>
//
//	<base64-encoded checkpoint>
//
//	<base64-encoded proof hashes, one per line>
//
//	<base64-encoded DER certificate, if present>
//	-----END MTC ASSERTION BUNDLE-----
func FormatPEM(bundle *Bundle) ([]byte, error) {
	var b strings.Builder

	b.WriteString("-----BEGIN MTC ASSERTION BUNDLE-----\n")
	b.WriteString(fmt.Sprintf("Log-Origin: %s\n", bundle.LogOrigin))
	b.WriteString(fmt.Sprintf("Leaf-Index: %d\n", bundle.LeafIndex))
	b.WriteString(fmt.Sprintf("Tree-Size: %d\n", bundle.TreeSize))
	b.WriteString(fmt.Sprintf("Root-Hash: %s\n", bundle.RootHash))
	b.WriteString(fmt.Sprintf("Leaf-Hash: %s\n", bundle.LeafHash))
	if bundle.SerialHex != "" {
		b.WriteString(fmt.Sprintf("Serial: %s\n", bundle.SerialHex))
	}
	b.WriteString(fmt.Sprintf("Revoked: %t\n", bundle.Revoked))
	b.WriteString("\n")

	// Checkpoint section.
	b.WriteString(bundle.Checkpoint)
	if !strings.HasSuffix(bundle.Checkpoint, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Proof section: one base64-encoded hash per line.
	for _, ph := range bundle.Proof {
		hashBytes, err := hex.DecodeString(ph)
		if err != nil {
			return nil, fmt.Errorf("assertion.FormatPEM: invalid proof hash: %w", err)
		}
		b.WriteString(base64.StdEncoding.EncodeToString(hashBytes))
		b.WriteString("\n")
	}

	// Certificate DER (base64, 76-char lines).
	if len(bundle.CertDER) > 0 {
		b.WriteString("\n")
		encoded := base64.StdEncoding.EncodeToString(bundle.CertDER)
		for i := 0; i < len(encoded); i += 76 {
			end := i + 76
			if end > len(encoded) {
				end = len(encoded)
			}
			b.WriteString(encoded[i:end])
			b.WriteString("\n")
		}
	}

	b.WriteString("-----END MTC ASSERTION BUNDLE-----\n")
	return []byte(b.String()), nil
}

// Verify checks that the assertion bundle's inclusion proof is valid.
// It recomputes the root hash from the leaf hash and proof, then compares
// it against the bundle's stated root hash.
//
// This does NOT verify the checkpoint signature — that requires the
// cosigner's public key and is done separately by the caller.
func Verify(bundle *Bundle) (bool, error) {
	// Decode leaf hash.
	leafBytes, err := hex.DecodeString(bundle.LeafHash)
	if err != nil {
		return false, fmt.Errorf("assertion.Verify: invalid leaf hash: %w", err)
	}
	var leafHash merkle.Hash
	copy(leafHash[:], leafBytes)

	// Decode root hash.
	rootBytes, err := hex.DecodeString(bundle.RootHash)
	if err != nil {
		return false, fmt.Errorf("assertion.Verify: invalid root hash: %w", err)
	}
	var rootHash merkle.Hash
	copy(rootHash[:], rootBytes)

	// Decode proof hashes.
	proofHashes := make([]merkle.Hash, len(bundle.Proof))
	for i, ph := range bundle.Proof {
		b, err := hex.DecodeString(ph)
		if err != nil {
			return false, fmt.Errorf("assertion.Verify: invalid proof[%d]: %w", i, err)
		}
		copy(proofHashes[i][:], b)
	}

	// Verify using RFC 9162 inclusion verification.
	return merkle.VerifyInclusion(leafHash, bundle.LeafIndex, bundle.TreeSize, proofHashes, rootHash), nil
}
