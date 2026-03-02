package localca

import (
	"encoding/asn1"
	"fmt"
)

// StripMTCExtension removes the MTC inclusion proof extension from a raw
// TBSCertificate DER encoding, producing the canonical form used for hashing.
//
// TBSCertificate (RFC 5280 §4.1):
//
//	SEQUENCE {
//	    [0] EXPLICIT version
//	    serialNumber
//	    signature (AlgorithmIdentifier)
//	    issuer (Name)
//	    validity
//	    subject (Name)
//	    subjectPublicKeyInfo
//	    [1] IMPLICIT issuerUniqueID (optional)
//	    [2] IMPLICIT subjectUniqueID (optional)
//	    [3] EXPLICIT extensions (optional)
//	}
//
// We parse the outer SEQUENCE into raw fields, locate the [3] tagged extensions,
// filter out OIDMTCInclusionProof, and reassemble the TBSCertificate.
func StripMTCExtension(tbsDER []byte) ([]byte, error) {
	// Parse the TBSCertificate as a SEQUENCE of raw values.
	var tbsSeq asn1.RawValue
	rest, err := asn1.Unmarshal(tbsDER, &tbsSeq)
	if err != nil {
		return nil, fmt.Errorf("unmarshal TBSCertificate outer: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after TBSCertificate (%d bytes)", len(rest))
	}
	if tbsSeq.Tag != asn1.TagSequence || tbsSeq.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("expected SEQUENCE, got tag %d class %d", tbsSeq.Tag, tbsSeq.Class)
	}

	// Walk through the fields of TBSCertificate, collecting them as raw bytes.
	// When we find [3] (extensions), we filter it.
	inner := tbsSeq.Bytes
	var fields []asn1.RawValue
	for len(inner) > 0 {
		var field asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &field)
		if err != nil {
			return nil, fmt.Errorf("unmarshal TBS field: %w", err)
		}
		fields = append(fields, field)
	}

	// Find the extensions field: context-specific, tag 3, constructed.
	var rebuilt []byte
	for _, field := range fields {
		if field.Class == asn1.ClassContextSpecific && field.Tag == 3 {
			// This is [3] EXPLICIT Extensions.
			// The content is a SEQUENCE OF Extension.
			filtered, err := filterExtensions(field.Bytes)
			if err != nil {
				return nil, fmt.Errorf("filter extensions: %w", err)
			}
			// Re-wrap as [3] EXPLICIT.
			wrapped := asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        3,
				IsCompound: true,
				Bytes:      filtered,
			}
			enc, err := asn1.Marshal(wrapped)
			if err != nil {
				return nil, fmt.Errorf("marshal [3] wrapper: %w", err)
			}
			rebuilt = append(rebuilt, enc...)
		} else {
			// Preserve the field exactly as-is.
			rebuilt = append(rebuilt, field.FullBytes...)
		}
	}

	// Re-wrap as SEQUENCE.
	result, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rebuilt,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal TBSCertificate: %w", err)
	}
	return result, nil
}

// filterExtensions takes the content bytes of a [3] EXPLICIT extensions field
// (which is a SEQUENCE OF Extension) and removes any extension with OID
// matching OIDMTCInclusionProof.
func filterExtensions(extFieldBytes []byte) ([]byte, error) {
	// The content of [3] is a single SEQUENCE (Extensions).
	var extSeq asn1.RawValue
	rest, err := asn1.Unmarshal(extFieldBytes, &extSeq)
	if err != nil {
		return nil, fmt.Errorf("unmarshal Extensions SEQUENCE: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in extensions field (%d bytes)", len(rest))
	}

	// Parse each Extension in the SEQUENCE.
	inner := extSeq.Bytes
	var filteredExts []byte
	for len(inner) > 0 {
		var ext asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &ext)
		if err != nil {
			return nil, fmt.Errorf("unmarshal extension: %w", err)
		}

		// Parse just the OID from the extension to check if we should skip it.
		if shouldSkipExtension(ext.Bytes) {
			continue
		}
		filteredExts = append(filteredExts, ext.FullBytes...)
	}

	// Re-wrap as SEQUENCE.
	newExtSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      filteredExts,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal filtered Extensions: %w", err)
	}
	return newExtSeq, nil
}

// shouldSkipExtension checks if an extension's OID matches OIDMTCInclusionProof.
// The input is the inner bytes of an Extension SEQUENCE.
func shouldSkipExtension(extInnerBytes []byte) bool {
	// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
	// The first element is the OID.
	var oid asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(extInnerBytes, &oid)
	if err != nil {
		return false
	}
	return oid.Equal(OIDMTCInclusionProof)
}

// ExtractTBSCertificate extracts the raw TBSCertificate DER from a full
// certificate DER encoding.
//
// Certificate ::= SEQUENCE {
//
//	tbsCertificate      TBSCertificate,
//	signatureAlgorithm  AlgorithmIdentifier,
//	signatureValue      BIT STRING
//
// }
func ExtractTBSCertificate(certDER []byte) ([]byte, error) {
	var certSeq asn1.RawValue
	rest, err := asn1.Unmarshal(certDER, &certSeq)
	if err != nil {
		return nil, fmt.Errorf("unmarshal certificate: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after certificate (%d bytes)", len(rest))
	}

	// The first element of the Certificate SEQUENCE is the TBSCertificate.
	var tbsRaw asn1.RawValue
	_, err = asn1.Unmarshal(certSeq.Bytes, &tbsRaw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal TBSCertificate: %w", err)
	}
	return tbsRaw.FullBytes, nil
}
