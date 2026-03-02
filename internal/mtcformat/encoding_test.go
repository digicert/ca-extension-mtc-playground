package mtcformat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestMarshalUnmarshalNullEntry(t *testing.T) {
	entry := &MerkleTreeCertEntry{Type: EntryTypeNull}
	data, err := MarshalEntry(entry)
	if err != nil {
		t.Fatalf("MarshalEntry(null): %v", err)
	}
	if !bytes.Equal(data, []byte{0x00}) {
		t.Fatalf("null entry should be single zero byte, got %x", data)
	}

	parsed, err := UnmarshalEntry(data)
	if err != nil {
		t.Fatalf("UnmarshalEntry(null): %v", err)
	}
	if parsed.Type != EntryTypeNull {
		t.Fatalf("expected null type, got %d", parsed.Type)
	}
	if len(parsed.Data) != 0 {
		t.Fatalf("null entry should have empty data, got %d bytes", len(parsed.Data))
	}
}

func TestMarshalUnmarshalTBSCertEntry(t *testing.T) {
	testData := []byte("test TBSCertificateLogEntry DER data")
	entry := &MerkleTreeCertEntry{
		Type: EntryTypeTBSCert,
		Data: testData,
	}

	data, err := MarshalEntry(entry)
	if err != nil {
		t.Fatalf("MarshalEntry(tbs): %v", err)
	}

	// Verify structure: 1 byte type + 3 byte length + data.
	if data[0] != EntryTypeTBSCert {
		t.Fatalf("expected type 1, got %d", data[0])
	}
	encodedLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if encodedLen != len(testData) {
		t.Fatalf("encoded length %d != data length %d", encodedLen, len(testData))
	}
	if !bytes.Equal(data[4:], testData) {
		t.Fatalf("data mismatch")
	}

	// Round-trip.
	parsed, err := UnmarshalEntry(data)
	if err != nil {
		t.Fatalf("UnmarshalEntry(tbs): %v", err)
	}
	if parsed.Type != EntryTypeTBSCert {
		t.Fatalf("expected tbs_cert type, got %d", parsed.Type)
	}
	if !bytes.Equal(parsed.Data, testData) {
		t.Fatalf("data round-trip mismatch")
	}
}

func TestMarshalEntryEmptyDataError(t *testing.T) {
	entry := &MerkleTreeCertEntry{Type: EntryTypeTBSCert, Data: nil}
	_, err := MarshalEntry(entry)
	if err == nil {
		t.Fatal("expected error for empty tbs_cert_entry data")
	}
}

func TestUnmarshalEntryTrailingDataError(t *testing.T) {
	// null_entry with extra bytes
	_, err := UnmarshalEntry([]byte{0x00, 0xFF})
	if err == nil {
		t.Fatal("expected error for null_entry with trailing data")
	}
}

func TestUnmarshalEntryUnknownType(t *testing.T) {
	_, err := UnmarshalEntry([]byte{0xFF})
	if err == nil {
		t.Fatal("expected error for unknown entry type")
	}
}

func TestMarshalUnmarshalProofSignedMode(t *testing.T) {
	// Build a proof with 2 inclusion hashes and 1 signature.
	hash1 := sha256.Sum256([]byte("hash1"))
	hash2 := sha256.Sum256([]byte("hash2"))
	sig := bytes.Repeat([]byte{0xAB}, 64) // Ed25519-like signature

	proof := &MTCProof{
		Start: 100,
		End:   200,
		InclusionProof: [][]byte{
			hash1[:],
			hash2[:],
		},
		Signatures: []MTCSignature{
			{CosignerID: 42, Signature: sig},
		},
	}

	data, err := MarshalProof(proof)
	if err != nil {
		t.Fatalf("MarshalProof: %v", err)
	}

	parsed, err := UnmarshalProof(data)
	if err != nil {
		t.Fatalf("UnmarshalProof: %v", err)
	}

	if parsed.Start != 100 {
		t.Errorf("Start: got %d, want 100", parsed.Start)
	}
	if parsed.End != 200 {
		t.Errorf("End: got %d, want 200", parsed.End)
	}
	if len(parsed.InclusionProof) != 2 {
		t.Fatalf("InclusionProof: got %d hashes, want 2", len(parsed.InclusionProof))
	}
	if !bytes.Equal(parsed.InclusionProof[0], hash1[:]) {
		t.Error("first inclusion hash mismatch")
	}
	if !bytes.Equal(parsed.InclusionProof[1], hash2[:]) {
		t.Error("second inclusion hash mismatch")
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("Signatures: got %d, want 1", len(parsed.Signatures))
	}
	if parsed.Signatures[0].CosignerID != 42 {
		t.Errorf("CosignerID: got %d, want 42", parsed.Signatures[0].CosignerID)
	}
	if !bytes.Equal(parsed.Signatures[0].Signature, sig) {
		t.Error("signature bytes mismatch")
	}
}

func TestMarshalUnmarshalProofSignatureless(t *testing.T) {
	// Signatureless mode: empty Signatures.
	hash1 := sha256.Sum256([]byte("proof-hash"))

	proof := &MTCProof{
		Start:          0,
		End:            1000,
		InclusionProof: [][]byte{hash1[:]},
		Signatures:     nil, // signatureless
	}

	data, err := MarshalProof(proof)
	if err != nil {
		t.Fatalf("MarshalProof(signatureless): %v", err)
	}

	parsed, err := UnmarshalProof(data)
	if err != nil {
		t.Fatalf("UnmarshalProof(signatureless): %v", err)
	}

	if len(parsed.Signatures) != 0 {
		t.Errorf("signatureless proof should have no signatures, got %d", len(parsed.Signatures))
	}
	if len(parsed.InclusionProof) != 1 {
		t.Fatalf("expected 1 proof hash, got %d", len(parsed.InclusionProof))
	}
	if !bytes.Equal(parsed.InclusionProof[0], hash1[:]) {
		t.Error("proof hash mismatch")
	}
}

func TestMarshalProofEmptyInclusionProof(t *testing.T) {
	proof := &MTCProof{
		Start:          0,
		End:            1,
		InclusionProof: nil, // single-entry tree, no proof hashes
	}

	data, err := MarshalProof(proof)
	if err != nil {
		t.Fatalf("MarshalProof(empty proof): %v", err)
	}

	parsed, err := UnmarshalProof(data)
	if err != nil {
		t.Fatalf("UnmarshalProof(empty proof): %v", err)
	}

	if len(parsed.InclusionProof) != 0 {
		t.Errorf("expected 0 proof hashes, got %d", len(parsed.InclusionProof))
	}
}

func TestMarshalProofInvalidRange(t *testing.T) {
	proof := &MTCProof{Start: 100, End: 50}
	_, err := MarshalProof(proof)
	if err == nil {
		t.Fatal("expected error for end <= start")
	}
}

func TestMarshalProofWrongHashSize(t *testing.T) {
	proof := &MTCProof{
		Start:          0,
		End:            10,
		InclusionProof: [][]byte{{0x01, 0x02, 0x03}}, // wrong size
	}
	_, err := MarshalProof(proof)
	if err == nil {
		t.Fatal("expected error for wrong hash size")
	}
}

func TestMarshalUnmarshalProofMultipleSignatures(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	sig1 := bytes.Repeat([]byte{0x11}, 64)  // Ed25519
	sig2 := bytes.Repeat([]byte{0x22}, 3309) // ML-DSA-65

	proof := &MTCProof{
		Start:          0,
		End:            500,
		InclusionProof: [][]byte{hash[:]},
		Signatures: []MTCSignature{
			{CosignerID: 0, Signature: sig1},
			{CosignerID: 1, Signature: sig2},
		},
	}

	data, err := MarshalProof(proof)
	if err != nil {
		t.Fatalf("MarshalProof(multi-sig): %v", err)
	}

	parsed, err := UnmarshalProof(data)
	if err != nil {
		t.Fatalf("UnmarshalProof(multi-sig): %v", err)
	}

	if len(parsed.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(parsed.Signatures))
	}

	if parsed.Signatures[0].CosignerID != 0 || !bytes.Equal(parsed.Signatures[0].Signature, sig1) {
		t.Error("signature 0 mismatch")
	}
	if parsed.Signatures[1].CosignerID != 1 || !bytes.Equal(parsed.Signatures[1].Signature, sig2) {
		t.Error("signature 1 mismatch")
	}
}

func TestProofWireFormatLayout(t *testing.T) {
	// Verify the exact wire format byte layout.
	hash := sha256.Sum256([]byte("x"))
	proof := &MTCProof{
		Start:          1,
		End:            2,
		InclusionProof: [][]byte{hash[:]},
		Signatures:     nil,
	}

	data, err := MarshalProof(proof)
	if err != nil {
		t.Fatalf("MarshalProof: %v", err)
	}

	// Expected: 8 (start=1) + 8 (end=2) + 2 (proof len=32) + 32 (hash) + 2 (sigs len=0) = 52 bytes
	if len(data) != 52 {
		t.Fatalf("expected 52 bytes, got %d", len(data))
	}

	// Check start.
	if binary.BigEndian.Uint64(data[0:8]) != 1 {
		t.Error("start field incorrect")
	}
	// Check end.
	if binary.BigEndian.Uint64(data[8:16]) != 2 {
		t.Error("end field incorrect")
	}
	// Check proof length.
	if binary.BigEndian.Uint16(data[16:18]) != 32 {
		t.Error("proof length field incorrect")
	}
	// Check proof hash.
	if !bytes.Equal(data[18:50], hash[:]) {
		t.Error("proof hash incorrect")
	}
	// Check signatures length.
	if binary.BigEndian.Uint16(data[50:52]) != 0 {
		t.Error("signatures length should be 0")
	}
}

func TestBuildSubtreeSignatureInput(t *testing.T) {
	hash := sha256.Sum256([]byte("subtree"))
	logID := []byte("test-log")

	input, err := BuildSubtreeSignatureInput(42, logID, 100, 200, hash[:])
	if err != nil {
		t.Fatalf("BuildSubtreeSignatureInput: %v", err)
	}

	// Verify label.
	if !bytes.Equal(input[:16], MTCSubtreeLabel[:]) {
		t.Error("label mismatch")
	}

	// Verify cosigner ID.
	if binary.BigEndian.Uint16(input[16:18]) != 42 {
		t.Error("cosigner ID mismatch")
	}

	// Verify log ID.
	off := 18
	if !bytes.Equal(input[off:off+len(logID)], logID) {
		t.Error("log ID mismatch")
	}
	off += len(logID)

	// Verify start.
	if binary.BigEndian.Uint64(input[off:off+8]) != 100 {
		t.Error("start mismatch")
	}
	off += 8

	// Verify end.
	if binary.BigEndian.Uint64(input[off:off+8]) != 200 {
		t.Error("end mismatch")
	}
	off += 8

	// Verify hash.
	if !bytes.Equal(input[off:off+32], hash[:]) {
		t.Error("hash mismatch")
	}
}

func TestBuildSubtreeSignatureInputWrongHashSize(t *testing.T) {
	_, err := BuildSubtreeSignatureInput(0, []byte("log"), 0, 1, []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for wrong hash size")
	}
}

func TestNullEntryBytes(t *testing.T) {
	b := NullEntryBytes()
	if !bytes.Equal(b, []byte{0x00}) {
		t.Fatalf("NullEntryBytes() = %x, want 00", b)
	}
}

func TestMTCSubtreeLabel(t *testing.T) {
	expected := "mtc-subtree/v1\n\x00"
	if string(MTCSubtreeLabel[:]) != expected {
		t.Fatalf("label = %q, want %q", string(MTCSubtreeLabel[:]), expected)
	}
}
