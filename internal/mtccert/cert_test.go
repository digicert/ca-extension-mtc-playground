// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package mtccert

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

	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

func testCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
			Country:      []string{"US"},
		},
		DNSNames: []string{"test.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

func testProof() *mtcformat.MTCProof {
	h := sha256.Sum256([]byte("sibling hash"))
	return &mtcformat.MTCProof{
		Start:          0,
		End:            256,
		InclusionProof: [][]byte{h[:]},
		Signatures:     nil, // signatureless mode
	}
}

func TestBuildAndParseMTCCertificate(t *testing.T) {
	csr := testCSR(t)
	proof := testProof()
	issuer := pkix.Name{CommonName: "Test CA", Country: []string{"US"}}
	notBefore := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)

	certDER, err := BuildMTCCertFromCSR(csr, issuer, notBefore, notAfter, []string{"test.example.com"}, 42, proof)
	if err != nil {
		t.Fatalf("BuildMTCCertFromCSR: %v", err)
	}

	// Parse it back.
	parsed, err := ParseMTCCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseMTCCertificate: %v", err)
	}

	// Verify serial = leaf index.
	if parsed.SerialNumber != 42 {
		t.Errorf("serial = %d, want 42", parsed.SerialNumber)
	}

	// Verify validity.
	if !parsed.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %v, want %v", parsed.NotBefore, notBefore)
	}
	if !parsed.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v, want %v", parsed.NotAfter, notAfter)
	}

	// Verify proof fields.
	if parsed.Proof == nil {
		t.Fatal("proof is nil")
	}
	if parsed.Proof.Start != 0 {
		t.Errorf("proof.Start = %d, want 0", parsed.Proof.Start)
	}
	if parsed.Proof.End != 256 {
		t.Errorf("proof.End = %d, want 256", parsed.Proof.End)
	}
	if len(parsed.Proof.InclusionProof) != 1 {
		t.Errorf("proof hashes = %d, want 1", len(parsed.Proof.InclusionProof))
	}
	if len(parsed.Proof.Signatures) != 0 {
		t.Errorf("signatures = %d, want 0 (signatureless)", len(parsed.Proof.Signatures))
	}

	// Verify SPKI is preserved.
	if len(parsed.SubjectPubKeyInfo) == 0 {
		t.Error("SubjectPubKeyInfo is empty")
	}

	// Verify extensions are present (SAN, KeyUsage, ExtKeyUsage, BasicConstraints).
	if len(parsed.Extensions) < 3 {
		t.Errorf("extensions = %d, want >= 3", len(parsed.Extensions))
	}
}

func TestBuildMTCCertificateWithSignatures(t *testing.T) {
	csr := testCSR(t)
	issuer := pkix.Name{CommonName: "Test CA", Country: []string{"US"}}
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}

	proof := &mtcformat.MTCProof{
		Start: 100,
		End:   200,
		InclusionProof: [][]byte{
			sha256.New().Sum(nil), // dummy hash
		},
		Signatures: []mtcformat.MTCSignature{
			{CosignerID: 0, Signature: sig},
			{CosignerID: 1, Signature: sig},
		},
	}

	certDER, err := BuildMTCCertFromCSR(csr, issuer, notBefore, notAfter, []string{"test.example.com"}, 150, proof)
	if err != nil {
		t.Fatalf("BuildMTCCertFromCSR: %v", err)
	}

	parsed, err := ParseMTCCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseMTCCertificate: %v", err)
	}

	if parsed.SerialNumber != 150 {
		t.Errorf("serial = %d, want 150", parsed.SerialNumber)
	}
	if len(parsed.Proof.Signatures) != 2 {
		t.Fatalf("signatures = %d, want 2", len(parsed.Proof.Signatures))
	}
	if parsed.Proof.Signatures[0].CosignerID != 0 {
		t.Errorf("sig[0].CosignerID = %d, want 0", parsed.Proof.Signatures[0].CosignerID)
	}
	if parsed.Proof.Signatures[1].CosignerID != 1 {
		t.Errorf("sig[1].CosignerID = %d, want 1", parsed.Proof.Signatures[1].CosignerID)
	}
}

func TestIsMTCCertificate(t *testing.T) {
	csr := testCSR(t)
	proof := testProof()
	issuer := pkix.Name{CommonName: "Test CA"}
	now := time.Now().UTC().Truncate(time.Second)

	certDER, err := BuildMTCCertFromCSR(csr, issuer, now, now.Add(time.Hour), []string{"test.example.com"}, 1, proof)
	if err != nil {
		t.Fatalf("BuildMTCCertFromCSR: %v", err)
	}

	if !IsMTCCertificate(certDER) {
		t.Error("IsMTCCertificate returned false for MTC cert")
	}

	// Generate a regular X.509 cert — IsMTCCertificate should return false.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "regular"},
	}
	regularDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create regular cert: %v", err)
	}

	if IsMTCCertificate(regularDER) {
		t.Error("IsMTCCertificate returned true for regular cert")
	}

	// Garbage input.
	if IsMTCCertificate([]byte("garbage")) {
		t.Error("IsMTCCertificate returned true for garbage")
	}
}

func TestReconstructLogEntry(t *testing.T) {
	csr := testCSR(t)
	proof := testProof()
	issuer := pkix.Name{CommonName: "Test CA", Country: []string{"US"}}
	notBefore := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)

	certDER, err := BuildMTCCertFromCSR(csr, issuer, notBefore, notAfter, []string{"test.example.com"}, 42, proof)
	if err != nil {
		t.Fatalf("BuildMTCCertFromCSR: %v", err)
	}

	parsed, err := ParseMTCCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseMTCCertificate: %v", err)
	}

	// Reconstruct the log entry.
	logEntryDER, err := ReconstructLogEntry(
		parsed.RawIssuer, parsed.RawSubject,
		parsed.NotBefore, parsed.NotAfter,
		parsed.SubjectPubKeyInfo, parsed.Extensions,
	)
	if err != nil {
		t.Fatalf("ReconstructLogEntry: %v", err)
	}

	// Also build the log entry directly from CSR (the way it would be built at issuance time).
	directLogEntry, err := mtcformat.BuildLogEntryFromCSR(issuer, notBefore, notAfter, csr, []string{"test.example.com"})
	if err != nil {
		t.Fatalf("BuildLogEntryFromCSR: %v", err)
	}

	// Both should parse and have the same SPKI hash.
	var reconstructed, direct mtcformat.TBSCertificateLogEntry
	if _, err := asn1.Unmarshal(logEntryDER, &reconstructed); err != nil {
		t.Fatalf("unmarshal reconstructed: %v", err)
	}
	if _, err := asn1.Unmarshal(directLogEntry, &direct); err != nil {
		t.Fatalf("unmarshal direct: %v", err)
	}

	expectedHash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	for i := range expectedHash {
		if reconstructed.SubjectPublicKeyInfoHash[i] != expectedHash[i] {
			t.Fatalf("reconstructed SPKI hash mismatch at byte %d", i)
		}
		if direct.SubjectPublicKeyInfoHash[i] != expectedHash[i] {
			t.Fatalf("direct SPKI hash mismatch at byte %d", i)
		}
	}
}

func TestBuildMTCCertNilProof(t *testing.T) {
	issuerDER, _ := asn1.Marshal(pkix.Name{CommonName: "CA"}.ToRDNSequence())
	subjectDER, _ := asn1.Marshal(pkix.Name{CommonName: "S"}.ToRDNSequence())

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)

	fields := TBSFields{
		Issuer:            asn1.RawValue{FullBytes: issuerDER},
		NotBefore:         time.Now(),
		NotAfter:          time.Now().Add(time.Hour),
		Subject:           asn1.RawValue{FullBytes: subjectDER},
		SubjectPubKeyInfo: spki,
	}

	_, err := BuildMTCCertificate(fields, 0, nil)
	if err == nil {
		t.Error("expected error for nil proof")
	}
}

func TestBuildMTCCertEmptySPKI(t *testing.T) {
	proof := testProof()
	issuerDER, _ := asn1.Marshal(pkix.Name{CommonName: "CA"}.ToRDNSequence())
	subjectDER, _ := asn1.Marshal(pkix.Name{CommonName: "S"}.ToRDNSequence())

	fields := TBSFields{
		Issuer:  asn1.RawValue{FullBytes: issuerDER},
		Subject: asn1.RawValue{FullBytes: subjectDER},
	}

	_, err := BuildMTCCertificate(fields, 0, proof)
	if err == nil {
		t.Error("expected error for empty SPKI")
	}
}

func TestParseMTCCertificateGarbage(t *testing.T) {
	_, err := ParseMTCCertificate([]byte("garbage"))
	if err == nil {
		t.Error("expected error for garbage input")
	}
}
