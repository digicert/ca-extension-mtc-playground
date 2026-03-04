// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package localca implements a local intermediate CA for two-phase MTC certificate
// signing. It enables embedding Merkle inclusion proofs directly into X.509
// certificates by signing twice: once as a pre-certificate (for hashing into the
// log), then again as the final certificate (with the proof extension added).
package localca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
)

// OIDMTCInclusionProof is the OID for the MTC inclusion proof X.509 extension.
// Uses a private enterprise arc for experimental/demo use.
var OIDMTCInclusionProof = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

// InclusionProofExt is the ASN.1 structure embedded in the X.509 extension value.
//
//	MTCInclusionProof ::= SEQUENCE {
//	    logOrigin    UTF8String,
//	    leafIndex    INTEGER,
//	    treeSize     INTEGER,
//	    rootHash     OCTET STRING (SIZE(32)),
//	    proofHashes  SEQUENCE OF OCTET STRING (SIZE(32)),
//	    checkpoint   UTF8String
//	}
type InclusionProofExt struct {
	LogOrigin   string   `asn1:"utf8"`
	LeafIndex   int64
	TreeSize    int64
	RootHash    []byte
	ProofHashes [][]byte `asn1:"set"`
	Checkpoint  string   `asn1:"utf8"`
}

// MarshalExtension encodes the inclusion proof as a non-critical X.509 extension.
func (p *InclusionProofExt) MarshalExtension() (pkix.Extension, error) {
	value, err := asn1.Marshal(*p)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("localca: marshal extension: %w", err)
	}
	return pkix.Extension{
		Id:       OIDMTCInclusionProof,
		Critical: false,
		Value:    value,
	}, nil
}

// ParseInclusionProof extracts the MTC inclusion proof extension from a certificate.
// Returns nil, nil if the extension is not present.
func ParseInclusionProof(cert *x509.Certificate) (*InclusionProofExt, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDMTCInclusionProof) {
			var proof InclusionProofExt
			rest, err := asn1.Unmarshal(ext.Value, &proof)
			if err != nil {
				return nil, fmt.Errorf("localca: unmarshal extension: %w", err)
			}
			if len(rest) > 0 {
				return nil, fmt.Errorf("localca: trailing data in extension (%d bytes)", len(rest))
			}
			return &proof, nil
		}
	}
	return nil, nil
}

// VerifyEmbeddedProof verifies the MTC inclusion proof embedded in a certificate.
// It strips the MTC extension from the TBSCertificate, rebuilds the log entry,
// computes the leaf hash, and verifies the inclusion proof.
//
// Returns the parsed proof and whether verification succeeded.
func VerifyEmbeddedProof(certDER []byte) (*InclusionProofExt, bool, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, false, fmt.Errorf("localca: parse certificate: %w", err)
	}

	proof, err := ParseInclusionProof(cert)
	if err != nil {
		return nil, false, fmt.Errorf("localca: parse proof: %w", err)
	}
	if proof == nil {
		return nil, false, fmt.Errorf("localca: MTC inclusion proof extension not found")
	}

	// Strip the MTC extension from TBSCertificate to get the canonical form.
	canonicalTBS, err := StripMTCExtension(cert.RawTBSCertificate)
	if err != nil {
		return nil, false, fmt.Errorf("localca: strip extension: %w", err)
	}

	// Build the log entry data: [type=2 uint16 LE][len uint32 LE][canonical TBS DER].
	entryData := BuildPrecertEntryData(canonicalTBS)

	// Compute leaf hash.
	leafHash := merkle.LeafHash(entryData)

	// Convert proof hashes.
	proofHashes := make([]merkle.Hash, len(proof.ProofHashes))
	for i, ph := range proof.ProofHashes {
		if len(ph) != merkle.HashSize {
			return proof, false, fmt.Errorf("localca: proof hash %d has wrong size %d", i, len(ph))
		}
		copy(proofHashes[i][:], ph)
	}

	// Convert root hash.
	if len(proof.RootHash) != merkle.HashSize {
		return proof, false, fmt.Errorf("localca: root hash has wrong size %d", len(proof.RootHash))
	}
	var rootHash merkle.Hash
	copy(rootHash[:], proof.RootHash)

	// Verify inclusion.
	ok := merkle.VerifyInclusion(leafHash, proof.LeafIndex, proof.TreeSize, proofHashes, rootHash)
	return proof, ok, nil
}

// BuildPrecertEntryData constructs the log entry data for a pre-certificate.
// Format: [uint16 LE type=2][uint32 LE length][TBS DER bytes]
func BuildPrecertEntryData(tbsDER []byte) []byte {
	data := make([]byte, 2+4+len(tbsDER))
	data[0] = 2 // EntryTypePrecert, little-endian uint16
	data[1] = 0
	data[2] = byte(len(tbsDER))
	data[3] = byte(len(tbsDER) >> 8)
	data[4] = byte(len(tbsDER) >> 16)
	data[5] = byte(len(tbsDER) >> 24)
	copy(data[6:], tbsDER)
	return data
}
