// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package mtccert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

// ParsedMTCCert contains the fields extracted from an MTC-format certificate.
type ParsedMTCCert struct {
	RawTBS            []byte              // raw TBSCertificate DER
	SerialNumber      int64               // = leaf index
	Issuer            pkix.RDNSequence
	NotBefore         time.Time
	NotAfter          time.Time
	Subject           pkix.RDNSequence
	SubjectPubKeyInfo []byte              // full DER of SubjectPublicKeyInfo
	Extensions        []pkix.Extension
	Proof             *mtcformat.MTCProof

	// Raw ASN.1 values for log entry reconstruction.
	RawIssuer  asn1.RawValue
	RawSubject asn1.RawValue
}

// ParseMTCCertificate extracts an MTCProof from the signatureValue of a
// certificate with signatureAlgorithm = id-alg-mtcProof.
//
// Go's x509.ParseCertificate rejects unknown signature algorithms, so this
// function uses raw ASN.1 parsing.
func ParseMTCCertificate(certDER []byte) (*ParsedMTCCert, error) {
	// Parse the outer Certificate SEQUENCE.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(certDER, &outer)
	if err != nil {
		return nil, fmt.Errorf("mtccert: unmarshal outer: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("mtccert: trailing data after certificate")
	}

	// The Certificate SEQUENCE contains: TBSCertificate, AlgorithmIdentifier, BIT STRING.
	inner := outer.Bytes
	fields, err := parseSequenceFields(inner)
	if err != nil {
		return nil, fmt.Errorf("mtccert: parse certificate fields: %w", err)
	}
	if len(fields) < 3 {
		return nil, fmt.Errorf("mtccert: certificate has %d fields, want 3", len(fields))
	}

	// Field 0: TBSCertificate (SEQUENCE).
	tbsRaw := fields[0]
	tbsDER := tbsRaw.FullBytes

	// Field 1: AlgorithmIdentifier — verify it's id-alg-mtcProof.
	var algID algorithmIdentifier
	if _, err := asn1.Unmarshal(fields[1].FullBytes, &algID); err != nil {
		return nil, fmt.Errorf("mtccert: unmarshal algorithm: %w", err)
	}
	if !algID.Algorithm.Equal(mtcformat.OIDMTCProof) {
		return nil, fmt.Errorf("mtccert: signatureAlgorithm is %v, not id-alg-mtcProof", algID.Algorithm)
	}

	// Field 2: signatureValue (BIT STRING) = marshaled MTCProof.
	var sigBits asn1.BitString
	if _, err := asn1.Unmarshal(fields[2].FullBytes, &sigBits); err != nil {
		return nil, fmt.Errorf("mtccert: unmarshal signatureValue: %w", err)
	}

	proof, err := mtcformat.UnmarshalProof(sigBits.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtccert: unmarshal proof: %w", err)
	}

	// Parse TBSCertificate fields.
	parsed, err := parseTBS(tbsDER)
	if err != nil {
		return nil, fmt.Errorf("mtccert: parse TBS: %w", err)
	}
	parsed.RawTBS = tbsDER
	parsed.Proof = proof

	return parsed, nil
}

// IsMTCCertificate checks if a DER-encoded certificate uses id-alg-mtcProof
// as its signature algorithm, without fully parsing it.
func IsMTCCertificate(certDER []byte) bool {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(certDER, &outer)
	if err != nil || len(rest) > 0 {
		return false
	}

	fields, err := parseSequenceFields(outer.Bytes)
	if err != nil || len(fields) < 2 {
		return false
	}

	var algID algorithmIdentifier
	if _, err := asn1.Unmarshal(fields[1].FullBytes, &algID); err != nil {
		return false
	}

	return algID.Algorithm.Equal(mtcformat.OIDMTCProof)
}

// parseTBS extracts fields from a raw TBSCertificate DER.
func parseTBS(tbsDER []byte) (*ParsedMTCCert, error) {
	var tbsOuter asn1.RawValue
	if _, err := asn1.Unmarshal(tbsDER, &tbsOuter); err != nil {
		return nil, fmt.Errorf("unmarshal TBS outer: %w", err)
	}

	fields, err := parseSequenceFields(tbsOuter.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse TBS fields: %w", err)
	}

	// TBSCertificate fields (indices relative to offset):
	//   offset+0: serialNumber
	//   offset+1: signature (AlgorithmIdentifier)
	//   offset+2: issuer (Name)
	//   offset+3: validity (Validity)
	//   offset+4: subject (Name)
	//   offset+5: subjectPublicKeyInfo
	// If version [0] is present, offset=1; otherwise offset=0.
	offset := 0
	if len(fields) > 0 && fields[0].Tag == 0 && fields[0].Class == asn1.ClassContextSpecific {
		offset = 1
	}

	if len(fields) < offset+6 {
		return nil, fmt.Errorf("TBS has too few fields (%d)", len(fields))
	}

	result := &ParsedMTCCert{}

	// Serial number (offset+0).
	var serial *big.Int
	if _, err := asn1.Unmarshal(fields[offset+0].FullBytes, &serial); err != nil {
		return nil, fmt.Errorf("unmarshal serial: %w", err)
	}
	result.SerialNumber = serial.Int64()

	// Issuer (offset+2).
	result.RawIssuer = fields[offset+2]
	result.RawIssuer.FullBytes = reencodeField(fields[offset+2])
	var issuerRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(result.RawIssuer.FullBytes, &issuerRDN); err != nil {
		// Non-fatal: keep raw bytes even if RDN parsing fails.
		issuerRDN = nil
	}
	result.Issuer = issuerRDN

	// Validity (offset+3).
	var val validity
	if _, err := asn1.Unmarshal(fields[offset+3].FullBytes, &val); err != nil {
		return nil, fmt.Errorf("unmarshal validity: %w", err)
	}
	result.NotBefore = val.NotBefore
	result.NotAfter = val.NotAfter

	// Subject (offset+4).
	result.RawSubject = fields[offset+4]
	result.RawSubject.FullBytes = reencodeField(fields[offset+4])
	var subjectRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(result.RawSubject.FullBytes, &subjectRDN); err != nil {
		subjectRDN = nil
	}
	result.Subject = subjectRDN

	// SubjectPublicKeyInfo (offset+5).
	result.SubjectPubKeyInfo = reencodeField(fields[offset+5])

	// Extensions (tag 3, context-specific) — after SPKI.
	for i := offset + 6; i < len(fields); i++ {
		if fields[i].Tag == 3 && fields[i].Class == asn1.ClassContextSpecific {
			var exts []pkix.Extension
			if _, err := asn1.Unmarshal(fields[i].Bytes, &exts); err != nil {
				return nil, fmt.Errorf("unmarshal extensions: %w", err)
			}
			result.Extensions = exts
			break
		}
	}

	return result, nil
}

// parseSequenceFields splits an ASN.1 SEQUENCE's inner bytes into individual fields.
func parseSequenceFields(data []byte) ([]asn1.RawValue, error) {
	var fields []asn1.RawValue
	rest := data
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	return fields, nil
}

// reencodeField re-encodes a RawValue with its tag and length.
func reencodeField(f asn1.RawValue) []byte {
	if len(f.FullBytes) > 0 {
		return f.FullBytes
	}
	encoded, err := asn1.Marshal(f)
	if err != nil {
		return f.Bytes
	}
	return encoded
}
