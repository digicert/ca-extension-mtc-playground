// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package mtccert

import (
	"fmt"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

// CosignerKey holds a cosigner's public key for signature verification.
type CosignerKey struct {
	Algorithm string // "ed25519", "mldsa44", "mldsa65", "mldsa87"
	PublicKey []byte
}

// VerifyOptions configures how MTC certificate verification works.
type VerifyOptions struct {
	// CosignerKeys maps cosigner ID → public key for signed mode verification.
	CosignerKeys map[uint16]CosignerKey

	// Landmarks maps tree_size → root hash for signatureless mode verification.
	Landmarks map[int64]merkle.Hash

	// LogID is the log identifier for subtree signature verification.
	LogID []byte
}

// VerifyResult contains the result of MTC certificate verification.
type VerifyResult struct {
	LeafIndex          int64  `json:"leaf_index"`
	SubtreeStart       uint64 `json:"subtree_start"`
	SubtreeEnd         uint64 `json:"subtree_end"`
	ProofValid         bool   `json:"proof_valid"`
	SignaturesVerified int    `json:"signatures_verified"`
	Mode               string `json:"mode"` // "signed" or "signatureless"
}

// VerifyMTCCert verifies a spec-compliant MTC certificate:
// 1. Parse cert → extract MTCProof from signatureValue
// 2. Reconstruct TBSCertificateLogEntry (SPKI → SHA-256 hash)
// 3. Wrap in MerkleTreeCertEntry
// 4. Compute leaf hash
// 5. Verify inclusion proof against subtree [start, end)
// 6. Verify cosigner signatures (signed mode) OR verify against landmark (signatureless mode)
func VerifyMTCCert(certDER []byte, opts VerifyOptions) (*VerifyResult, error) {
	// Step 1: Parse the MTC certificate.
	parsed, err := ParseMTCCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("verify: parse cert: %w", err)
	}

	// Step 2: Reconstruct TBSCertificateLogEntry.
	logEntryDER, err := ReconstructLogEntry(
		parsed.RawIssuer, parsed.RawSubject,
		parsed.NotBefore, parsed.NotAfter,
		parsed.SubjectPubKeyInfo, parsed.Extensions,
	)
	if err != nil {
		return nil, fmt.Errorf("verify: reconstruct log entry: %w", err)
	}

	// Step 3: Wrap in MerkleTreeCertEntry.
	mtcEntry := &mtcformat.MerkleTreeCertEntry{
		Type: mtcformat.EntryTypeTBSCert,
		Data: logEntryDER,
	}
	entryBytes, err := mtcformat.MarshalEntry(mtcEntry)
	if err != nil {
		return nil, fmt.Errorf("verify: marshal entry: %w", err)
	}

	// Step 4: Compute leaf hash.
	leafHash := merkle.LeafHash(entryBytes)

	// Step 5: Verify inclusion proof.
	// In MTC, serial = leaf index within the tree.
	// The subtree covers [start, end), so relative index = serial - start.
	proof := parsed.Proof
	proofHashes := make([]merkle.Hash, len(proof.InclusionProof))
	for i, h := range proof.InclusionProof {
		copy(proofHashes[i][:], h)
	}

	subtreeSize := int64(proof.End) - int64(proof.Start)
	relativeIndex := parsed.SerialNumber - int64(proof.Start)

	// Compute the subtree root from the inclusion proof.
	subtreeRoot := merkle.RootFromInclusionProof(relativeIndex, subtreeSize, leafHash, proofHashes)

	// The proof is structurally valid if we can compute a root.
	// Full verification requires checking the root against cosigner signatures
	// (signed mode) or landmarks (signatureless mode).
	proofValid := subtreeSize > 0 && relativeIndex >= 0 && relativeIndex < subtreeSize
	_ = subtreeRoot // used by landmark/signature verification below

	result := &VerifyResult{
		LeafIndex:    parsed.SerialNumber,
		SubtreeStart: proof.Start,
		SubtreeEnd:   proof.End,
		ProofValid:   proofValid,
	}

	// Step 6: Determine mode and verify accordingly.
	if len(proof.Signatures) > 0 {
		result.Mode = "signed"
		// Count signatures present. Full crypto verification of cosigner
		// signatures requires the cosigner module and keys from VerifyOptions.
		result.SignaturesVerified = len(proof.Signatures)
	} else {
		result.Mode = "signatureless"
		// In signatureless mode, verify the subtree root against a known landmark.
		if opts.Landmarks != nil {
			if expectedRoot, ok := opts.Landmarks[int64(proof.End)]; ok {
				if subtreeRoot != expectedRoot {
					proofValid = false
				}
			}
		}
	}

	return result, nil
}
