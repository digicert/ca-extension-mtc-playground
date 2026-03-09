// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package mtcformat

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
)

// MerkleTreeCertEntry types per MTC spec §5.3.
// The enum is uint16 per TLS presentation language: enum { ..., (2^16-1) }.
const (
	EntryTypeNull    uint16 = 0 // null_entry: sentinel at index 0
	EntryTypeTBSCert uint16 = 1 // tbs_cert_entry: contents octets of TBSCertificateLogEntry DER
)

// MerkleTreeCertEntry is the leaf structure hashed into the Merkle tree.
//
// Wire format (TLS presentation language):
//
//	enum {
//	    null_entry(0), tbs_cert_entry(1), (2^16-1)
//	} MerkleTreeCertEntryType;
//
//	struct {
//	    MerkleTreeCertEntryType type;     // 2 bytes (uint16)
//	    select (type) {
//	        case null_entry: Empty;
//	        case tbs_cert_entry: opaque tbs_cert_entry_data<1..2^24-1>;
//	    }
//	} MerkleTreeCertEntry;
type MerkleTreeCertEntry struct {
	Type uint16
	Data []byte // empty for null_entry; contents octets of TBSCertificateLogEntry DER for tbs_cert_entry
}

// MarshalEntry encodes a MerkleTreeCertEntry to its wire format.
func MarshalEntry(e *MerkleTreeCertEntry) ([]byte, error) {
	switch e.Type {
	case EntryTypeNull:
		// 2-byte type field only (uint16 big-endian).
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, EntryTypeNull)
		return buf, nil

	case EntryTypeTBSCert:
		if len(e.Data) == 0 {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry data cannot be empty")
		}
		if len(e.Data) > 0xFFFFFF {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry data too large (%d bytes)", len(e.Data))
		}
		// 2 byte type + 3 byte length + data
		buf := make([]byte, 2+3+len(e.Data))
		binary.BigEndian.PutUint16(buf[0:2], EntryTypeTBSCert)
		buf[2] = byte(len(e.Data) >> 16)
		buf[3] = byte(len(e.Data) >> 8)
		buf[4] = byte(len(e.Data))
		copy(buf[5:], e.Data)
		return buf, nil

	default:
		return nil, fmt.Errorf("mtcformat: unknown entry type %d", e.Type)
	}
}

// UnmarshalEntry decodes a MerkleTreeCertEntry from wire format.
func UnmarshalEntry(data []byte) (*MerkleTreeCertEntry, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("mtcformat: entry data too short for type field (%d bytes)", len(data))
	}

	entryType := binary.BigEndian.Uint16(data[0:2])

	switch entryType {
	case EntryTypeNull:
		if len(data) != 2 {
			return nil, fmt.Errorf("mtcformat: null_entry has trailing data (%d bytes)", len(data)-2)
		}
		return &MerkleTreeCertEntry{Type: EntryTypeNull}, nil

	case EntryTypeTBSCert:
		if len(data) < 5 {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry too short for length prefix")
		}
		dataLen := int(data[2])<<16 | int(data[3])<<8 | int(data[4])
		if dataLen == 0 {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry has zero length")
		}
		if len(data) < 5+dataLen {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry truncated: need %d bytes, have %d", 5+dataLen, len(data))
		}
		if len(data) > 5+dataLen {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry has trailing data")
		}
		return &MerkleTreeCertEntry{
			Type: EntryTypeTBSCert,
			Data: data[5 : 5+dataLen],
		}, nil

	default:
		return nil, fmt.Errorf("mtcformat: unknown entry type %d", entryType)
	}
}

// MTCSignature pairs a cosigner's trust anchor ID with its signature bytes.
//
// Wire format (per draft-ietf-plants-merkle-tree-certs-02):
//
//	struct {
//	    TrustAnchorID cosigner_id<1..255>;
//	    opaque signature<0..2^16-1>;
//	} MTCSignature;
type MTCSignature struct {
	CosignerID []byte // variable-length TrustAnchorID (1..255 bytes)
	Signature  []byte
}

// MTCProof is the structure that goes into the X.509 signatureValue field
// when signatureAlgorithm = id-alg-mtcProof.
//
// Wire format (TLS presentation language):
//
//	struct {
//	    uint64 start;
//	    uint64 end;
//	    opaque inclusion_proof<0..2^16-1>;
//	    MTCSignature signatures<0..2^16-1>;
//	} MTCProof;
//
// In signatureless mode, Signatures is empty.
type MTCProof struct {
	Start          uint64
	End            uint64
	InclusionProof [][]byte       // each hash is 32 bytes (SHA-256)
	Signatures     []MTCSignature // empty for signatureless mode
}

// HashSize is the size of SHA-256 hashes used in inclusion proofs.
const HashSize = 32

// MarshalProof encodes an MTCProof to its binary wire format.
func MarshalProof(p *MTCProof) ([]byte, error) {
	if p.End <= p.Start {
		return nil, fmt.Errorf("mtcformat: invalid subtree range [%d, %d)", p.Start, p.End)
	}

	// Validate and compute inclusion proof size.
	proofLen := len(p.InclusionProof) * HashSize
	if proofLen > 0xFFFF {
		return nil, fmt.Errorf("mtcformat: inclusion proof too large (%d hashes)", len(p.InclusionProof))
	}
	for i, h := range p.InclusionProof {
		if len(h) != HashSize {
			return nil, fmt.Errorf("mtcformat: proof hash %d has wrong size %d (want %d)", i, len(h), HashSize)
		}
	}

	// Compute signatures section size.
	sigsBytes, err := marshalSignatures(p.Signatures)
	if err != nil {
		return nil, err
	}

	// Total: 8 (start) + 8 (end) + 2 (proof len) + proof + 2 (sigs len) + sigs
	total := 8 + 8 + 2 + proofLen + 2 + len(sigsBytes)
	buf := make([]byte, total)
	off := 0

	binary.BigEndian.PutUint64(buf[off:], p.Start)
	off += 8
	binary.BigEndian.PutUint64(buf[off:], p.End)
	off += 8

	// Inclusion proof: 2-byte length prefix + concatenated hashes.
	binary.BigEndian.PutUint16(buf[off:], uint16(proofLen))
	off += 2
	for _, h := range p.InclusionProof {
		copy(buf[off:], h)
		off += HashSize
	}

	// Signatures: 2-byte length prefix + encoded signatures.
	binary.BigEndian.PutUint16(buf[off:], uint16(len(sigsBytes)))
	off += 2
	copy(buf[off:], sigsBytes)

	return buf, nil
}

// UnmarshalProof decodes an MTCProof from its binary wire format.
func UnmarshalProof(data []byte) (*MTCProof, error) {
	if len(data) < 20 { // 8+8+2+2 minimum
		return nil, fmt.Errorf("mtcformat: proof data too short (%d bytes)", len(data))
	}

	off := 0
	p := &MTCProof{}

	p.Start = binary.BigEndian.Uint64(data[off:])
	off += 8
	p.End = binary.BigEndian.Uint64(data[off:])
	off += 8

	if p.End <= p.Start {
		return nil, fmt.Errorf("mtcformat: invalid subtree range [%d, %d)", p.Start, p.End)
	}

	// Inclusion proof.
	if off+2 > len(data) {
		return nil, fmt.Errorf("mtcformat: truncated at proof length")
	}
	proofLen := int(binary.BigEndian.Uint16(data[off:]))
	off += 2

	if proofLen%HashSize != 0 {
		return nil, fmt.Errorf("mtcformat: proof length %d not a multiple of %d", proofLen, HashSize)
	}
	if off+proofLen > len(data) {
		return nil, fmt.Errorf("mtcformat: truncated inclusion proof")
	}

	numHashes := proofLen / HashSize
	p.InclusionProof = make([][]byte, numHashes)
	for i := 0; i < numHashes; i++ {
		h := make([]byte, HashSize)
		copy(h, data[off:off+HashSize])
		p.InclusionProof[i] = h
		off += HashSize
	}

	// Signatures.
	if off+2 > len(data) {
		return nil, fmt.Errorf("mtcformat: truncated at signatures length")
	}
	sigsLen := int(binary.BigEndian.Uint16(data[off:]))
	off += 2

	if off+sigsLen > len(data) {
		return nil, fmt.Errorf("mtcformat: truncated signatures")
	}
	if off+sigsLen < len(data) {
		return nil, fmt.Errorf("mtcformat: trailing data after signatures")
	}

	sigs, err := unmarshalSignatures(data[off : off+sigsLen])
	if err != nil {
		return nil, err
	}
	p.Signatures = sigs

	return p, nil
}

// marshalSignatures encodes a slice of MTCSignature into their concatenated wire format.
// Each signature is: 1-byte cosigner_id length + cosigner_id + 2-byte sig length + sig.
func marshalSignatures(sigs []MTCSignature) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, nil
	}

	// Compute total size.
	total := 0
	for i, s := range sigs {
		if len(s.CosignerID) == 0 || len(s.CosignerID) > 255 {
			return nil, fmt.Errorf("mtcformat: cosigner_id %d has invalid length %d (must be 1..255)", i, len(s.CosignerID))
		}
		if len(s.Signature) > 0xFFFF {
			return nil, fmt.Errorf("mtcformat: signature %d too large (%d bytes)", i, len(s.Signature))
		}
		total += 1 + len(s.CosignerID) + 2 + len(s.Signature) // id_len + id + sig_len + sig
	}

	buf := make([]byte, total)
	off := 0
	for _, s := range sigs {
		buf[off] = byte(len(s.CosignerID))
		off++
		copy(buf[off:], s.CosignerID)
		off += len(s.CosignerID)
		binary.BigEndian.PutUint16(buf[off:], uint16(len(s.Signature)))
		off += 2
		copy(buf[off:], s.Signature)
		off += len(s.Signature)
	}

	return buf, nil
}

// unmarshalSignatures decodes a concatenated signature blob into MTCSignature slices.
func unmarshalSignatures(data []byte) ([]MTCSignature, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var sigs []MTCSignature
	off := 0
	for off < len(data) {
		// Read 1-byte cosigner_id length.
		if off+1 > len(data) {
			return nil, fmt.Errorf("mtcformat: truncated cosigner_id length at offset %d", off)
		}
		idLen := int(data[off])
		off++
		if idLen == 0 {
			return nil, fmt.Errorf("mtcformat: zero-length cosigner_id at offset %d", off)
		}
		if off+idLen > len(data) {
			return nil, fmt.Errorf("mtcformat: truncated cosigner_id at offset %d", off)
		}
		cosignerID := make([]byte, idLen)
		copy(cosignerID, data[off:off+idLen])
		off += idLen

		// Read 2-byte signature length.
		if off+2 > len(data) {
			return nil, fmt.Errorf("mtcformat: truncated signature length at offset %d", off)
		}
		sigLen := int(binary.BigEndian.Uint16(data[off:]))
		off += 2
		if off+sigLen > len(data) {
			return nil, fmt.Errorf("mtcformat: truncated signature data at offset %d", off)
		}
		sig := make([]byte, sigLen)
		copy(sig, data[off:off+sigLen])
		off += sigLen
		sigs = append(sigs, MTCSignature{
			CosignerID: cosignerID,
			Signature:  sig,
		})
	}

	return sigs, nil
}

// MTCSubtreeLabel is the fixed 16-byte label used in MTCSubtreeSignatureInput (§5.4.1).
var MTCSubtreeLabel = [16]byte{
	'm', 't', 'c', '-', 's', 'u', 'b', 't',
	'r', 'e', 'e', '/', 'v', '1', '\n', 0x00,
}

// BuildSubtreeSignatureInput constructs the message that cosigners sign (§5.4.1):
//
//	label("mtc-subtree/v1\n\0") || cosigner_id || log_id || start (8 bytes) || end (8 bytes) || hash (32 bytes)
func BuildSubtreeSignatureInput(cosignerID []byte, logID []byte, start, end uint64, hash []byte) ([]byte, error) {
	if len(hash) != HashSize {
		return nil, fmt.Errorf("mtcformat: hash must be %d bytes, got %d", HashSize, len(hash))
	}
	if len(cosignerID) == 0 {
		return nil, fmt.Errorf("mtcformat: empty cosigner_id")
	}

	// Total: 16 (label) + len(cosignerID) + len(logID) + 8 (start) + 8 (end) + 32 (hash)
	buf := make([]byte, 16+len(cosignerID)+len(logID)+8+8+HashSize)
	off := 0

	copy(buf[off:], MTCSubtreeLabel[:])
	off += 16

	copy(buf[off:], cosignerID)
	off += len(cosignerID)

	copy(buf[off:], logID)
	off += len(logID)

	binary.BigEndian.PutUint64(buf[off:], start)
	off += 8
	binary.BigEndian.PutUint64(buf[off:], end)
	off += 8

	copy(buf[off:], hash)

	return buf, nil
}

// DERContentsOctets strips the outer tag and length octets from a DER encoding,
// returning only the contents octets. Per MTC spec §5.3 (-02), tbs_cert_entry_data
// contains "the contents octets (i.e. excluding the initial identifier and length
// octets) of the DER encoding of TBSCertificateLogEntry."
func DERContentsOctets(der []byte) ([]byte, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("mtcformat: strip DER envelope: %w", err)
	}
	return raw.Bytes, nil
}

// WrapContentsOctets re-wraps contents octets into a full DER SEQUENCE encoding.
// This is the inverse of DERContentsOctets and is used during verification to
// reconstruct the full DER for ASN.1 parsing.
func WrapContentsOctets(contents []byte) ([]byte, error) {
	raw := asn1.RawValue{
		Tag:        asn1.TagSequence,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      contents,
	}
	return asn1.Marshal(raw)
}
