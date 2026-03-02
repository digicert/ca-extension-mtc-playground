package mtcformat

import (
	"encoding/binary"
	"fmt"
)

// MerkleTreeCertEntry types per MTC spec §5.3.
const (
	EntryTypeNull    uint8 = 0 // null_entry: sentinel at index 0
	EntryTypeTBSCert uint8 = 1 // tbs_cert_entry: DER of TBSCertificateLogEntry
)

// MerkleTreeCertEntry is the leaf structure hashed into the Merkle tree.
//
// Wire format (TLS presentation language):
//
//	struct {
//	    MerkleTreeCertEntryType type;     // 1 byte
//	    select (type) {
//	        case null_entry: Empty;
//	        case tbs_cert_entry: opaque tbs_cert_entry_data<1..2^24-1>;
//	    }
//	} MerkleTreeCertEntry;
type MerkleTreeCertEntry struct {
	Type uint8
	Data []byte // empty for null_entry; DER of TBSCertificateLogEntry for tbs_cert_entry
}

// MarshalEntry encodes a MerkleTreeCertEntry to its wire format.
func MarshalEntry(e *MerkleTreeCertEntry) ([]byte, error) {
	switch e.Type {
	case EntryTypeNull:
		return []byte{EntryTypeNull}, nil

	case EntryTypeTBSCert:
		if len(e.Data) == 0 {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry data cannot be empty")
		}
		if len(e.Data) > 0xFFFFFF {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry data too large (%d bytes)", len(e.Data))
		}
		// 1 byte type + 3 byte length + data
		buf := make([]byte, 1+3+len(e.Data))
		buf[0] = EntryTypeTBSCert
		buf[1] = byte(len(e.Data) >> 16)
		buf[2] = byte(len(e.Data) >> 8)
		buf[3] = byte(len(e.Data))
		copy(buf[4:], e.Data)
		return buf, nil

	default:
		return nil, fmt.Errorf("mtcformat: unknown entry type %d", e.Type)
	}
}

// UnmarshalEntry decodes a MerkleTreeCertEntry from wire format.
func UnmarshalEntry(data []byte) (*MerkleTreeCertEntry, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("mtcformat: empty entry data")
	}

	switch data[0] {
	case EntryTypeNull:
		if len(data) != 1 {
			return nil, fmt.Errorf("mtcformat: null_entry has trailing data (%d bytes)", len(data)-1)
		}
		return &MerkleTreeCertEntry{Type: EntryTypeNull}, nil

	case EntryTypeTBSCert:
		if len(data) < 4 {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry too short for length prefix")
		}
		dataLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if dataLen == 0 {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry has zero length")
		}
		if len(data) < 4+dataLen {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry truncated: need %d bytes, have %d", 4+dataLen, len(data))
		}
		if len(data) > 4+dataLen {
			return nil, fmt.Errorf("mtcformat: tbs_cert_entry has trailing data")
		}
		return &MerkleTreeCertEntry{
			Type: EntryTypeTBSCert,
			Data: data[4 : 4+dataLen],
		}, nil

	default:
		return nil, fmt.Errorf("mtcformat: unknown entry type %d", data[0])
	}
}

// MTCSignature pairs a cosigner ID with its signature bytes.
//
// Wire format:
//
//	struct {
//	    uint16 cosigner_id;
//	    opaque signature<0..2^16-1>;
//	} MTCSignature;
type MTCSignature struct {
	CosignerID uint16
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
func marshalSignatures(sigs []MTCSignature) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, nil
	}

	// Compute total size.
	total := 0
	for i, s := range sigs {
		if len(s.Signature) > 0xFFFF {
			return nil, fmt.Errorf("mtcformat: signature %d too large (%d bytes)", i, len(s.Signature))
		}
		total += 2 + 2 + len(s.Signature) // cosigner_id + sig_len + sig
	}

	buf := make([]byte, total)
	off := 0
	for _, s := range sigs {
		binary.BigEndian.PutUint16(buf[off:], s.CosignerID)
		off += 2
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
		if off+4 > len(data) {
			return nil, fmt.Errorf("mtcformat: truncated signature at offset %d", off)
		}
		cosignerID := binary.BigEndian.Uint16(data[off:])
		off += 2
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
//	label("mtc-subtree/v1\n\0") || cosigner_id (2 bytes) || log_id || start (8 bytes) || end (8 bytes) || hash (32 bytes)
func BuildSubtreeSignatureInput(cosignerID uint16, logID []byte, start, end uint64, hash []byte) ([]byte, error) {
	if len(hash) != HashSize {
		return nil, fmt.Errorf("mtcformat: hash must be %d bytes, got %d", HashSize, len(hash))
	}

	// Total: 16 (label) + 2 (cosigner_id) + len(logID) + 8 (start) + 8 (end) + 32 (hash)
	buf := make([]byte, 16+2+len(logID)+8+8+HashSize)
	off := 0

	copy(buf[off:], MTCSubtreeLabel[:])
	off += 16

	binary.BigEndian.PutUint16(buf[off:], cosignerID)
	off += 2

	copy(buf[off:], logID)
	off += len(logID)

	binary.BigEndian.PutUint64(buf[off:], start)
	off += 8
	binary.BigEndian.PutUint64(buf[off:], end)
	off += 8

	copy(buf[off:], hash)

	return buf, nil
}
