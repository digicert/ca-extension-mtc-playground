package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestParseDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames:    []string{"test.example.com", "*.example.com"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	meta, err := ParseDER(der)
	if err != nil {
		t.Fatal(err)
	}

	if meta.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", meta.CommonName, "test.example.com")
	}
	if len(meta.Organization) != 1 || meta.Organization[0] != "Test Org" {
		t.Errorf("Organization = %v, want [Test Org]", meta.Organization)
	}
	if len(meta.SANs) != 2 {
		t.Errorf("SANs = %v, want 2 entries", meta.SANs)
	}
	if meta.KeyAlgorithm != "ECDSA" {
		t.Errorf("KeyAlgorithm = %q, want ECDSA", meta.KeyAlgorithm)
	}
	if meta.IsCA {
		t.Error("IsCA = true, want false")
	}
	if len(meta.ExtKeyUsage) != 1 || meta.ExtKeyUsage[0] != "Server Authentication" {
		t.Errorf("ExtKeyUsage = %v, want [Server Authentication]", meta.ExtKeyUsage)
	}
	if meta.SerialNumber != "2A" {
		t.Errorf("SerialNumber = %q, want 2A", meta.SerialNumber)
	}
}

func TestParseLogEntry(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "entry.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	// Wrap in log entry format: [uint16 LE type=1][uint32 LE length][DER]
	entry := make([]byte, 6+len(der))
	entry[0] = 1 // type = 1 (cert), little-endian
	entry[1] = 0
	l := uint32(len(der))
	entry[2] = byte(l)
	entry[3] = byte(l >> 8)
	entry[4] = byte(l >> 16)
	entry[5] = byte(l >> 24)
	copy(entry[6:], der)

	meta, gotDER, err := ParseLogEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if meta.CommonName != "entry.example.com" {
		t.Errorf("CommonName = %q, want entry.example.com", meta.CommonName)
	}
	if len(gotDER) != len(der) {
		t.Errorf("DER length = %d, want %d", len(gotDER), len(der))
	}
}

func TestParseLogEntry_NullEntry(t *testing.T) {
	entry := []byte{0, 0, 0, 0, 0, 0}
	_, _, err := ParseLogEntry(entry)
	if err == nil {
		t.Fatal("expected error for null entry")
	}
}

func TestParseLogEntry_TooShort(t *testing.T) {
	_, _, err := ParseLogEntry([]byte{1, 0})
	if err == nil {
		t.Fatal("expected error for short entry")
	}
}

func TestFormatKeyUsage(t *testing.T) {
	ku := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	got := formatKeyUsage(ku)
	if got != "Digital Signature, Certificate Sign" {
		t.Errorf("formatKeyUsage = %q", got)
	}
}

func TestFormatSerial_Empty(t *testing.T) {
	got := formatSerial(nil)
	if got != "0" {
		t.Errorf("formatSerial(nil) = %q, want 0", got)
	}
}
