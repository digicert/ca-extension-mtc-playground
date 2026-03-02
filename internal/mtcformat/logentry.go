package mtcformat

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// TBSCertificateLogEntry is the ASN.1 structure that gets hashed into the
// Merkle tree as part of a MerkleTreeCertEntry (§5.3).
//
// It differs from a standard X.509 TBSCertificate in two ways:
//   - Uses subjectPublicKeyInfoHash (SHA-256 of SPKI DER) instead of the full SPKI
//   - Does not include serialNumber (the leaf index serves as the serial)
//
//	TBSCertificateLogEntry ::= SEQUENCE {
//	    version                  [0] EXPLICIT Version DEFAULT v1,
//	    issuer                   Name,
//	    validity                 Validity,
//	    subject                  Name,
//	    subjectPublicKeyInfoHash OCTET STRING,
//	    issuerUniqueID           [1] IMPLICIT UniqueIdentifier OPTIONAL,
//	    subjectUniqueID          [2] IMPLICIT UniqueIdentifier OPTIONAL,
//	    extensions               [3] EXPLICIT Extensions OPTIONAL
//	}
type TBSCertificateLogEntry struct {
	Version                  int             `asn1:"optional,explicit,tag:0,default:0"`
	Issuer                   asn1.RawValue   `asn1:""`
	Validity                 validity        `asn1:""`
	Subject                  asn1.RawValue   `asn1:""`
	SubjectPublicKeyInfoHash []byte          `asn1:""`
	Extensions               []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// validity mirrors the X.509 Validity ASN.1 structure.
type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// BuildLogEntry constructs a DER-encoded TBSCertificateLogEntry from certificate fields.
//
// Parameters:
//   - issuerRaw: DER-encoded issuer Name (from the CA certificate)
//   - subjectRaw: DER-encoded subject Name (from the CSR/certificate)
//   - notBefore, notAfter: validity period
//   - spkiDER: DER-encoded SubjectPublicKeyInfo (the full public key)
//   - extensions: X.509 extensions to include (excluding the MTC proof extension)
func BuildLogEntry(issuerRaw, subjectRaw asn1.RawValue, notBefore, notAfter time.Time, spkiDER []byte, extensions []pkix.Extension) ([]byte, error) {
	if len(spkiDER) == 0 {
		return nil, fmt.Errorf("mtcformat: empty SubjectPublicKeyInfo")
	}

	spkiHash := sha256.Sum256(spkiDER)

	entry := TBSCertificateLogEntry{
		Version:                  2, // v3 = integer value 2
		Issuer:                   issuerRaw,
		Validity:                 validity{NotBefore: notBefore, NotAfter: notAfter},
		Subject:                  subjectRaw,
		SubjectPublicKeyInfoHash: spkiHash[:],
		Extensions:               extensions,
	}

	der, err := asn1.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("mtcformat: marshal log entry: %w", err)
	}

	return der, nil
}

// BuildLogEntryFromCSR constructs a TBSCertificateLogEntry from a CSR and CA info.
// This is the primary entry point for the local CA flow during pre-certificate creation.
func BuildLogEntryFromCSR(issuerName pkix.Name, notBefore, notAfter time.Time, csr *x509.CertificateRequest, dnsNames []string) ([]byte, error) {
	// Marshal the issuer Name to DER.
	issuerDER, err := asn1.Marshal(issuerName.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("mtcformat: marshal issuer: %w", err)
	}

	// Marshal the subject Name to DER.
	subjectDER, err := asn1.Marshal(csr.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("mtcformat: marshal subject: %w", err)
	}

	// Build extensions: SAN, key usage, etc.
	var extensions []pkix.Extension

	// Subject Alternative Name extension.
	if len(dnsNames) > 0 {
		sanExt, err := buildSANExtension(dnsNames)
		if err != nil {
			return nil, fmt.Errorf("mtcformat: build SAN extension: %w", err)
		}
		extensions = append(extensions, sanExt)
	}

	// Key Usage: digitalSignature, keyEncipherment
	kuExt, err := buildKeyUsageExtension(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment)
	if err != nil {
		return nil, fmt.Errorf("mtcformat: build key usage extension: %w", err)
	}
	extensions = append(extensions, kuExt)

	// Extended Key Usage: serverAuth, clientAuth
	ekuExt, err := buildExtKeyUsageExtension([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1}, // serverAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // clientAuth
	})
	if err != nil {
		return nil, fmt.Errorf("mtcformat: build ext key usage extension: %w", err)
	}
	extensions = append(extensions, ekuExt)

	// Basic Constraints: CA=false
	bcExt, err := buildBasicConstraintsExtension(false)
	if err != nil {
		return nil, fmt.Errorf("mtcformat: build basic constraints extension: %w", err)
	}
	extensions = append(extensions, bcExt)

	issuerRaw := asn1.RawValue{FullBytes: issuerDER}
	subjectRaw := asn1.RawValue{FullBytes: subjectDER}

	return BuildLogEntry(issuerRaw, subjectRaw, notBefore, notAfter, csr.RawSubjectPublicKeyInfo, extensions)
}

// BuildLogEntryFromCert constructs a TBSCertificateLogEntry from an existing
// parsed certificate. Used for post-issuance logging of externally-issued certificates.
func BuildLogEntryFromCert(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("mtcformat: nil certificate")
	}

	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	// Extract extensions, excluding any existing MTC proof extension.
	var extensions []pkix.Extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDMTCProof) {
			continue
		}
		extensions = append(extensions, ext)
	}

	// Re-parse issuer and subject from the raw TBS.
	issuerRaw, subjectRaw, err := extractIssuerSubject(cert.RawTBSCertificate)
	if err != nil {
		return nil, fmt.Errorf("mtcformat: extract issuer/subject: %w", err)
	}

	entry := TBSCertificateLogEntry{
		Version:                  2,
		Issuer:                   issuerRaw,
		Validity:                 validity{NotBefore: cert.NotBefore, NotAfter: cert.NotAfter},
		Subject:                  subjectRaw,
		SubjectPublicKeyInfoHash: spkiHash[:],
		Extensions:               extensions,
	}

	der, err := asn1.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("mtcformat: marshal log entry: %w", err)
	}

	return der, nil
}

// SPKIHash computes the SHA-256 hash of a DER-encoded SubjectPublicKeyInfo.
func SPKIHash(spkiDER []byte) [32]byte {
	return sha256.Sum256(spkiDER)
}

// --- Extension helpers ---

// OID constants for X.509 extensions.
var (
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

func buildSANExtension(dnsNames []string) (pkix.Extension, error) {
	// Build GeneralNames SEQUENCE.
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
	return pkix.Extension{
		Id:    oidSubjectAltName,
		Value: value,
	}, nil
}

func buildKeyUsageExtension(usage x509.KeyUsage) (pkix.Extension, error) {
	var a [2]byte
	a[0] = reverseBitsInByte(byte(usage))
	a[1] = reverseBitsInByte(byte(usage >> 8))

	// Count unused bits in the last byte.
	padding := 0
	if a[1] == 0 {
		// Only one byte needed; count trailing zeros in a[0].
		padding = countTrailingZeros(a[0])
		value, err := asn1.Marshal(asn1.BitString{Bytes: a[:1], BitLength: 8 - padding})
		if err != nil {
			return pkix.Extension{}, err
		}
		return pkix.Extension{
			Id:       oidKeyUsage,
			Critical: true,
			Value:    value,
		}, nil
	}

	padding = countTrailingZeros(a[1])
	value, err := asn1.Marshal(asn1.BitString{Bytes: a[:], BitLength: 16 - padding})
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       oidKeyUsage,
		Critical: true,
		Value:    value,
	}, nil
}

func buildExtKeyUsageExtension(oids []asn1.ObjectIdentifier) (pkix.Extension, error) {
	value, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    oidExtKeyUsage,
		Value: value,
	}, nil
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
	return pkix.Extension{
		Id:       oidBasicConstraints,
		Critical: true,
		Value:    value,
	}, nil
}

// extractIssuerSubject extracts raw issuer and subject Name fields from a TBSCertificate DER.
// TBSCertificate SEQUENCE: version, serialNumber, signature, issuer, validity, subject, ...
func extractIssuerSubject(tbsDER []byte) (issuer, subject asn1.RawValue, err error) {
	var tbs asn1.RawValue
	rest, err := asn1.Unmarshal(tbsDER, &tbs)
	if err != nil {
		return issuer, subject, fmt.Errorf("unmarshal TBS outer: %w", err)
	}
	if len(rest) > 0 {
		return issuer, subject, fmt.Errorf("trailing data after TBS")
	}

	// Parse the inner SEQUENCE fields.
	inner := tbs.Bytes
	fields := make([]asn1.RawValue, 0, 8)
	for len(inner) > 0 {
		var field asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &field)
		if err != nil {
			return issuer, subject, fmt.Errorf("unmarshal TBS field: %w", err)
		}
		fields = append(fields, field)
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
		return issuer, subject, fmt.Errorf("TBS has too few fields (%d)", len(fields))
	}

	// issuer is at offset+2, subject at offset+4
	issuer = fields[offset+2]
	issuer.FullBytes = tbsFieldFullBytes(tbsDER, fields, offset+2)

	subject = fields[offset+4]
	subject.FullBytes = tbsFieldFullBytes(tbsDER, fields, offset+4)

	return issuer, subject, nil
}

// tbsFieldFullBytes re-encodes a field with its tag and length for use as FullBytes.
func tbsFieldFullBytes(tbsDER []byte, fields []asn1.RawValue, idx int) []byte {
	f := fields[idx]
	encoded, err := asn1.Marshal(f)
	if err != nil {
		// Fallback: reconstruct from Bytes.
		return f.Bytes
	}
	return encoded
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

// NullEntryBytes returns the wire-format bytes for a null_entry (index 0).
func NullEntryBytes() []byte {
	return []byte{EntryTypeNull}
}

// SerialFromLeafIndex converts a leaf index to an X.509 serial number.
// Per MTC spec §6.1, the serial number is the zero-based leaf index.
func SerialFromLeafIndex(leafIndex int64) *big.Int {
	return big.NewInt(leafIndex)
}
