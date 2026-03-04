// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/mtccert"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

const defaultValidity = 90 * 24 * time.Hour // 90 days

// Config holds local CA configuration.
type Config struct {
	KeyFile      string        // Path to ECDSA P-256 private key (PEM)
	CertFile     string        // Path to CA certificate (PEM)
	Validity     time.Duration // Default cert validity (default: 90 days)
	Organization string
	Country      string
}

// LocalCA is a locally-controlled intermediate CA for two-phase MTC signing.
type LocalCA struct {
	key       *ecdsa.PrivateKey
	cert      *x509.Certificate
	certDER   []byte
	validity  time.Duration
}

// New loads a LocalCA from existing key and certificate files.
func New(cfg Config) (*LocalCA, error) {
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("localca: read key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("localca: no PEM block in key file")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("localca: parse key: %w", err)
	}

	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("localca: read cert: %w", err)
	}
	block, _ = pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("localca: no PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("localca: parse cert: %w", err)
	}

	validity := cfg.Validity
	if validity == 0 {
		validity = defaultValidity
	}

	return &LocalCA{
		key:      key,
		cert:     cert,
		certDER:  block.Bytes,
		validity: validity,
	}, nil
}

// CACertDER returns the CA certificate in DER format (for chain building).
func (ca *LocalCA) CACertDER() []byte {
	return ca.certDER
}

// CACert returns the parsed CA certificate.
func (ca *LocalCA) CACert() *x509.Certificate {
	return ca.cert
}

// PrecertResult holds the output of IssuePrecert.
type PrecertResult struct {
	PrecertDER   []byte           // Full signed pre-certificate DER
	CanonicalTBS []byte           // TBSCertificate DER (canonical form for hashing)
	Serial       *big.Int         // Certificate serial number
	NotBefore    time.Time        // Validity start (needed for IssueWithProof)
	NotAfter     time.Time        // Validity end
	Template     *x509.Certificate // The template used (for reference)
}

// IssuePrecert creates a pre-certificate from a CSR. The pre-certificate is a
// valid X.509 certificate with no MTC extension. Its TBSCertificate (canonical
// form) will be hashed into the Merkle tree.
func (ca *LocalCA) IssuePrecert(csr *x509.CertificateRequest, dnsNames []string, validity time.Duration) (*PrecertResult, error) {
	if validity == 0 {
		validity = ca.validity
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, fmt.Errorf("localca: generate serial: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonNameFromCSR(csr, dnsNames),
			Organization: csr.Subject.Organization,
			Country:      csr.Subject.Country,
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
	}

	precertDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("localca: sign precert: %w", err)
	}

	// Parse back to get the exact RawTBSCertificate.
	parsed, err := x509.ParseCertificate(precertDER)
	if err != nil {
		return nil, fmt.Errorf("localca: parse precert: %w", err)
	}

	return &PrecertResult{
		PrecertDER:   precertDER,
		CanonicalTBS: parsed.RawTBSCertificate,
		Serial:       serial,
		NotBefore:    now,
		NotAfter:     now.Add(validity),
		Template:     template,
	}, nil
}

// IssueWithProof re-signs the same certificate template with the MTC inclusion
// proof extension added. The resulting certificate has an identical TBSCertificate
// to the pre-certificate except for the added MTC extension.
func (ca *LocalCA) IssueWithProof(csr *x509.CertificateRequest, precert *PrecertResult, proof *InclusionProofExt) ([]byte, error) {
	ext, err := proof.MarshalExtension()
	if err != nil {
		return nil, fmt.Errorf("localca: marshal proof extension: %w", err)
	}

	// Rebuild the same template with identical fields.
	template := &x509.Certificate{
		SerialNumber: precert.Serial,
		Subject: pkix.Name{
			CommonName:   precert.Template.Subject.CommonName,
			Organization: precert.Template.Subject.Organization,
			Country:      precert.Template.Subject.Country,
		},
		NotBefore:             precert.NotBefore,
		NotAfter:              precert.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              precert.Template.DNSNames,
		ExtraExtensions:       []pkix.Extension{ext},
	}

	finalDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("localca: sign final cert: %w", err)
	}

	return finalDER, nil
}

// GenerateCA creates a new self-signed CA key pair and certificate, writing
// them to the specified files. This is used for initial setup / demo.
func GenerateCA(keyFile, certFile string, org, country string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("localca: generate key: %w", err)
	}

	serial, err := generateSerial()
	if err != nil {
		return fmt.Errorf("localca: generate serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "MTC Bridge Local CA",
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("localca: sign CA cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("localca: marshal key: %w", err)
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: keyDER,
	}), 0600); err != nil {
		return fmt.Errorf("localca: write key: %w", err)
	}

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certDER,
	}), 0644); err != nil {
		return fmt.Errorf("localca: write cert: %w", err)
	}

	return nil
}

// IssueMTCCert constructs a spec-compliant MTC certificate where:
//   - serialNumber = leafIndex (the Merkle tree position)
//   - signatureAlgorithm = id-alg-mtcProof
//   - signatureValue = binary-encoded MTCProof
//
// Unlike IssueWithProof, this does NOT use the CA's signing key for a per-cert
// signature. The certificate's authenticity comes from the Merkle tree proof
// and cosigner signatures on the tree head.
func (ca *LocalCA) IssueMTCCert(
	csr *x509.CertificateRequest,
	dnsNames []string,
	validity time.Duration,
	leafIndex int64,
	proof *mtcformat.MTCProof,
) ([]byte, error) {
	if validity == 0 {
		validity = ca.validity
	}

	now := time.Now().UTC().Truncate(time.Second)

	issuerDER, err := asn1.Marshal(ca.cert.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("localca: marshal issuer: %w", err)
	}

	subjectDER, err := asn1.Marshal(pkix.Name{
		CommonName:   commonNameFromCSR(csr, dnsNames),
		Organization: csr.Subject.Organization,
		Country:      csr.Subject.Country,
	}.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("localca: marshal subject: %w", err)
	}

	extensions, err := mtccert.BuildCertExtensions(dnsNames)
	if err != nil {
		return nil, fmt.Errorf("localca: build extensions: %w", err)
	}

	fields := mtccert.TBSFields{
		Issuer:            asn1.RawValue{FullBytes: issuerDER},
		NotBefore:         now,
		NotAfter:          now.Add(validity),
		Subject:           asn1.RawValue{FullBytes: subjectDER},
		SubjectPubKeyInfo: csr.RawSubjectPublicKeyInfo,
		Extensions:        extensions,
	}

	return mtccert.BuildMTCCertificate(fields, leafIndex, proof)
}

// IssuerName returns the CA's subject as a pkix.Name (for log entry construction).
func (ca *LocalCA) IssuerName() pkix.Name {
	return ca.cert.Subject
}

func generateSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func commonNameFromCSR(csr *x509.CertificateRequest, dnsNames []string) string {
	if csr.Subject.CommonName != "" {
		return csr.Subject.CommonName
	}
	if len(dnsNames) > 0 {
		return dnsNames[0]
	}
	return ""
}
