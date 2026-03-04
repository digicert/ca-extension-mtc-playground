// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package mtccert builds and parses MTC-spec-compliant certificates where
// signatureAlgorithm = id-alg-mtcProof and signatureValue = binary MTCProof.
//
// Go's crypto/x509 rejects unknown signature algorithms, so this package
// constructs and parses certificates using raw ASN.1 encoding.
package mtccert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

// TBSFields contains the certificate fields needed to build an MTC certificate.
type TBSFields struct {
	Issuer            asn1.RawValue    // DER-encoded issuer Name
	NotBefore         time.Time
	NotAfter          time.Time
	Subject           asn1.RawValue    // DER-encoded subject Name
	SubjectPubKeyInfo []byte           // full DER of SubjectPublicKeyInfo
	Extensions        []pkix.Extension // X.509 v3 extensions
}

// algorithmIdentifier is the ASN.1 AlgorithmIdentifier for id-alg-mtcProof.
type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

// validity is the ASN.1 Validity structure.
type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// tbsCertificate is the raw ASN.1 TBSCertificate for MTC certificates.
type tbsCertificate struct {
	Version            int                  `asn1:"optional,explicit,tag:0,default:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm algorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	SubjectPubKeyInfo  asn1.RawValue
	Extensions         []pkix.Extension     `asn1:"optional,explicit,tag:3"`
}

// certificate is the outer ASN.1 Certificate structure.
type certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}

// BuildMTCCertificate constructs a DER-encoded X.509 Certificate with:
//   - serialNumber = leafIndex
//   - signatureAlgorithm = id-alg-mtcProof (in both TBS and outer)
//   - signatureValue = marshaled MTCProof as BIT STRING
func BuildMTCCertificate(fields TBSFields, leafIndex int64, proof *mtcformat.MTCProof) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("mtccert: nil proof")
	}
	if len(fields.SubjectPubKeyInfo) == 0 {
		return nil, fmt.Errorf("mtccert: empty SubjectPublicKeyInfo")
	}

	algID := algorithmIdentifier{Algorithm: mtcformat.OIDMTCProof}

	// Parse the SPKI as a RawValue so we can embed it directly.
	var spkiRaw asn1.RawValue
	if _, err := asn1.Unmarshal(fields.SubjectPubKeyInfo, &spkiRaw); err != nil {
		return nil, fmt.Errorf("mtccert: parse SPKI: %w", err)
	}

	// Build TBSCertificate.
	tbs := tbsCertificate{
		Version:            2, // v3
		SerialNumber:       big.NewInt(leafIndex),
		SignatureAlgorithm: algID,
		Issuer:             fields.Issuer,
		Validity:           validity{NotBefore: fields.NotBefore, NotAfter: fields.NotAfter},
		Subject:            fields.Subject,
		SubjectPubKeyInfo:  spkiRaw,
		Extensions:         fields.Extensions,
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("mtccert: marshal TBS: %w", err)
	}

	// Marshal the MTCProof to binary.
	proofBytes, err := mtcformat.MarshalProof(proof)
	if err != nil {
		return nil, fmt.Errorf("mtccert: marshal proof: %w", err)
	}

	// Build outer Certificate: TBS || AlgorithmIdentifier || BIT STRING(proof).
	cert := certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algID,
		SignatureValue:     asn1.BitString{Bytes: proofBytes, BitLength: len(proofBytes) * 8},
	}

	certDER, err := asn1.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("mtccert: marshal certificate: %w", err)
	}

	return certDER, nil
}

// BuildMTCCertFromCSR constructs an MTC certificate from a CSR, CA name, and proof.
// This is the primary entry point for the local CA MTC flow.
func BuildMTCCertFromCSR(
	csr *x509.CertificateRequest,
	issuerName pkix.Name,
	notBefore, notAfter time.Time,
	dnsNames []string,
	leafIndex int64,
	proof *mtcformat.MTCProof,
) ([]byte, error) {
	// Marshal issuer Name to DER.
	issuerDER, err := asn1.Marshal(issuerName.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("mtccert: marshal issuer: %w", err)
	}

	// Marshal subject Name to DER.
	subjectDER, err := asn1.Marshal(csr.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("mtccert: marshal subject: %w", err)
	}

	// Build standard extensions.
	extensions, err := BuildCertExtensions(dnsNames)
	if err != nil {
		return nil, fmt.Errorf("mtccert: build extensions: %w", err)
	}

	fields := TBSFields{
		Issuer:            asn1.RawValue{FullBytes: issuerDER},
		NotBefore:         notBefore,
		NotAfter:          notAfter,
		Subject:           asn1.RawValue{FullBytes: subjectDER},
		SubjectPubKeyInfo: csr.RawSubjectPublicKeyInfo,
		Extensions:        extensions,
	}

	return BuildMTCCertificate(fields, leafIndex, proof)
}

// ReconstructLogEntry rebuilds a TBSCertificateLogEntry from parsed MTC cert fields.
// This replaces the full SPKI with its SHA-256 hash for tree verification.
func ReconstructLogEntry(
	issuer, subject asn1.RawValue,
	notBefore, notAfter time.Time,
	spkiDER []byte,
	extensions []pkix.Extension,
) ([]byte, error) {
	return mtcformat.BuildLogEntry(issuer, subject, notBefore, notAfter, spkiDER, extensions)
}

// --- Extension helpers ---

var (
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

// BuildCertExtensions builds standard X.509 extensions for an end-entity certificate:
// SAN, KeyUsage, ExtKeyUsage, BasicConstraints.
func BuildCertExtensions(dnsNames []string) ([]pkix.Extension, error) {
	var extensions []pkix.Extension

	// Subject Alternative Name.
	if len(dnsNames) > 0 {
		sanExt, err := buildSANExtension(dnsNames)
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, sanExt)
	}

	// Key Usage: digitalSignature, keyEncipherment.
	kuExt, err := buildKeyUsageExtension(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment)
	if err != nil {
		return nil, err
	}
	extensions = append(extensions, kuExt)

	// Extended Key Usage: serverAuth, clientAuth.
	ekuExt, err := buildExtKeyUsageExtension([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1}, // serverAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // clientAuth
	})
	if err != nil {
		return nil, err
	}
	extensions = append(extensions, ekuExt)

	// Basic Constraints: CA=false.
	bcExt, err := buildBasicConstraintsExtension(false)
	if err != nil {
		return nil, err
	}
	extensions = append(extensions, bcExt)

	return extensions, nil
}

func buildSANExtension(dnsNames []string) (pkix.Extension, error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   2, // dNSName
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(name),
		})
	}
	value, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oidSubjectAltName, Value: value}, nil
}

func buildKeyUsageExtension(usage x509.KeyUsage) (pkix.Extension, error) {
	var a [2]byte
	a[0] = reverseBitsInByte(byte(usage))
	a[1] = reverseBitsInByte(byte(usage >> 8))

	padding := 0
	if a[1] == 0 {
		padding = countTrailingZeros(a[0])
		value, err := asn1.Marshal(asn1.BitString{Bytes: a[:1], BitLength: 8 - padding})
		if err != nil {
			return pkix.Extension{}, err
		}
		return pkix.Extension{Id: oidKeyUsage, Critical: true, Value: value}, nil
	}

	padding = countTrailingZeros(a[1])
	value, err := asn1.Marshal(asn1.BitString{Bytes: a[:], BitLength: 16 - padding})
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oidKeyUsage, Critical: true, Value: value}, nil
}

func buildExtKeyUsageExtension(oids []asn1.ObjectIdentifier) (pkix.Extension, error) {
	value, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oidExtKeyUsage, Value: value}, nil
}

func buildBasicConstraintsExtension(isCA bool) (pkix.Extension, error) {
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	bc := basicConstraints{IsCA: isCA, MaxPathLen: -1}
	value, err := asn1.Marshal(bc)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oidBasicConstraints, Critical: true, Value: value}, nil
}

func reverseBitsInByte(b byte) byte {
	b = (b&0xF0)>>4 | (b&0x0F)<<4
	b = (b&0xCC)>>2 | (b&0x33)<<2
	b = (b&0xAA)>>1 | (b&0x55)<<1
	return b
}

func countTrailingZeros(b byte) int {
	if b == 0 {
		return 8
	}
	n := 0
	for b&1 == 0 {
		n++
		b >>= 1
	}
	return n
}
