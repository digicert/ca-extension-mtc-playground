package mtcformat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestBuildLogEntry(t *testing.T) {
	// Generate a test key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}

	issuerName := pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
	}
	issuerDER, err := asn1.Marshal(issuerName.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshal issuer: %v", err)
	}

	subjectName := pkix.Name{
		CommonName:   "test.example.com",
		Organization: []string{"Test"},
		Country:      []string{"US"},
	}
	subjectDER, err := asn1.Marshal(subjectName.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshal subject: %v", err)
	}

	notBefore := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)

	extensions := []pkix.Extension{
		{
			Id:       oidBasicConstraints,
			Critical: true,
			Value:    []byte{0x30, 0x00}, // empty SEQUENCE
		},
	}

	issuerRaw := asn1.RawValue{FullBytes: issuerDER}
	subjectRaw := asn1.RawValue{FullBytes: subjectDER}

	logEntryDER, err := BuildLogEntry(issuerRaw, subjectRaw, notBefore, notAfter, spkiDER, extensions)
	if err != nil {
		t.Fatalf("BuildLogEntry: %v", err)
	}

	// Verify we can unmarshal the result.
	var entry TBSCertificateLogEntry
	rest, err := asn1.Unmarshal(logEntryDER, &entry)
	if err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	if len(rest) > 0 {
		t.Fatalf("trailing data: %d bytes", len(rest))
	}

	// Verify the SPKI hash.
	expectedHash := sha256.Sum256(spkiDER)
	if len(entry.SubjectPublicKeyInfoHash) != 32 {
		t.Fatalf("SPKI hash length: got %d, want 32", len(entry.SubjectPublicKeyInfoHash))
	}
	for i := range expectedHash {
		if entry.SubjectPublicKeyInfoHash[i] != expectedHash[i] {
			t.Fatalf("SPKI hash mismatch at byte %d", i)
		}
	}

	// Verify version is v3 (integer 2).
	if entry.Version != 2 {
		t.Errorf("version: got %d, want 2 (v3)", entry.Version)
	}

	// Verify validity dates.
	if !entry.Validity.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore: got %v, want %v", entry.Validity.NotBefore, notBefore)
	}
	if !entry.Validity.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter: got %v, want %v", entry.Validity.NotAfter, notAfter)
	}

	// Verify extensions are present.
	if len(entry.Extensions) != 1 {
		t.Errorf("extensions: got %d, want 1", len(entry.Extensions))
	}
}

func TestBuildLogEntryFromCSR(t *testing.T) {
	// Generate key and CSR.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "csr-test.example.com",
			Organization: []string{"CSR Test"},
			Country:      []string{"US"},
		},
		DNSNames: []string{"csr-test.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	issuerName := pkix.Name{
		CommonName:   "MTC Test CA",
		Organization: []string{"MTC Test"},
		Country:      []string{"US"},
	}

	notBefore := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)

	logEntryDER, err := BuildLogEntryFromCSR(issuerName, notBefore, notAfter, csr, []string{"csr-test.example.com"})
	if err != nil {
		t.Fatalf("BuildLogEntryFromCSR: %v", err)
	}

	// Verify we can unmarshal and the SPKI hash is correct.
	var entry TBSCertificateLogEntry
	rest, err := asn1.Unmarshal(logEntryDER, &entry)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rest) > 0 {
		t.Fatalf("trailing data: %d bytes", len(rest))
	}

	expectedHash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	if len(entry.SubjectPublicKeyInfoHash) != 32 {
		t.Fatalf("SPKI hash length: got %d, want 32", len(entry.SubjectPublicKeyInfoHash))
	}
	for i := range expectedHash {
		if entry.SubjectPublicKeyInfoHash[i] != expectedHash[i] {
			t.Fatalf("SPKI hash mismatch at byte %d", i)
		}
	}

	// Verify extensions are present (SAN, KeyUsage, ExtKeyUsage, BasicConstraints).
	if len(entry.Extensions) < 3 {
		t.Errorf("expected at least 3 extensions, got %d", len(entry.Extensions))
	}
}

func TestBuildLogEntryEmptySPKI(t *testing.T) {
	issuerRaw := asn1.RawValue{FullBytes: []byte{0x30, 0x00}}
	subjectRaw := asn1.RawValue{FullBytes: []byte{0x30, 0x00}}
	_, err := BuildLogEntry(issuerRaw, subjectRaw, time.Now(), time.Now().Add(time.Hour), nil, nil)
	if err == nil {
		t.Fatal("expected error for empty SPKI")
	}
}

func TestSPKIHash(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}

	hash := SPKIHash(spkiDER)
	expected := sha256.Sum256(spkiDER)
	if hash != expected {
		t.Fatalf("SPKIHash mismatch")
	}
}

func TestSerialFromLeafIndex(t *testing.T) {
	tests := []struct {
		index int64
		want  *big.Int
	}{
		{0, big.NewInt(0)},
		{1, big.NewInt(1)},
		{42, big.NewInt(42)},
		{1000000, big.NewInt(1000000)},
	}

	for _, tt := range tests {
		serial := SerialFromLeafIndex(tt.index)
		if serial.Cmp(tt.want) != 0 {
			t.Errorf("SerialFromLeafIndex(%d) = %v, want %v", tt.index, serial, tt.want)
		}
	}
}

func TestMerkleTreeCertEntryRoundTrip(t *testing.T) {
	// Build a TBSCertificateLogEntry, wrap it, marshal, unmarshal, verify.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "roundtrip.example.com",
			Country:    []string{"US"},
		},
		DNSNames: []string{"roundtrip.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	issuer := pkix.Name{CommonName: "Test CA", Country: []string{"US"}}
	now := time.Now().UTC().Truncate(time.Second)

	logEntryDER, err := BuildLogEntryFromCSR(issuer, now, now.Add(365*24*time.Hour), csr, []string{"roundtrip.example.com"})
	if err != nil {
		t.Fatalf("BuildLogEntryFromCSR: %v", err)
	}

	// Wrap in MerkleTreeCertEntry.
	entry := &MerkleTreeCertEntry{
		Type: EntryTypeTBSCert,
		Data: logEntryDER,
	}

	entryBytes, err := MarshalEntry(entry)
	if err != nil {
		t.Fatalf("MarshalEntry: %v", err)
	}

	// Unmarshal and verify.
	parsed, err := UnmarshalEntry(entryBytes)
	if err != nil {
		t.Fatalf("UnmarshalEntry: %v", err)
	}

	if parsed.Type != EntryTypeTBSCert {
		t.Fatalf("type: got %d, want %d", parsed.Type, EntryTypeTBSCert)
	}

	// Verify the inner DER can be parsed as TBSCertificateLogEntry.
	var logEntry TBSCertificateLogEntry
	rest, err := asn1.Unmarshal(parsed.Data, &logEntry)
	if err != nil {
		t.Fatalf("unmarshal inner TBSCertificateLogEntry: %v", err)
	}
	if len(rest) > 0 {
		t.Fatalf("trailing data in inner entry: %d bytes", len(rest))
	}

	// Verify SPKI hash.
	expectedHash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	for i := range expectedHash {
		if logEntry.SubjectPublicKeyInfoHash[i] != expectedHash[i] {
			t.Fatalf("SPKI hash mismatch at byte %d", i)
		}
	}
}

func TestBuildLogEntryFromCert(t *testing.T) {
	// Generate CA key and cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA", Country: []string{"US"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// Generate leaf key and cert.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaf.example.com", Country: []string{"US"}},
		DNSNames:     []string{"leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// Build log entry from the leaf cert.
	logEntryDER, err := BuildLogEntryFromCert(leafCert)
	if err != nil {
		t.Fatalf("BuildLogEntryFromCert: %v", err)
	}

	// Verify it can be parsed.
	var entry TBSCertificateLogEntry
	rest, err := asn1.Unmarshal(logEntryDER, &entry)
	if err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	if len(rest) > 0 {
		t.Fatalf("trailing data: %d bytes", len(rest))
	}

	// Verify SPKI hash matches the leaf cert's public key.
	expectedHash := sha256.Sum256(leafCert.RawSubjectPublicKeyInfo)
	for i := range expectedHash {
		if entry.SubjectPublicKeyInfoHash[i] != expectedHash[i] {
			t.Fatalf("SPKI hash mismatch at byte %d", i)
		}
	}
}
