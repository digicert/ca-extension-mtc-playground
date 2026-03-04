// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package certutil extracts X.509 metadata from DER-encoded certificates.
//
// It is a leaf package with no internal dependencies - it relies only on
// the Go standard library crypto/x509 parser.
package certutil

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// CertMeta holds human-readable metadata extracted from an X.509 certificate.
type CertMeta struct {
	CommonName         string   `json:"common_name,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	SerialNumber       string   `json:"serial_number"`
	SANs               []string `json:"sans,omitempty"`
	IssuerCN           string   `json:"issuer_cn,omitempty"`
	IssuerOrganization []string `json:"issuer_organization,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string `json:"key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	KeyUsage           string `json:"key_usage,omitempty"`
	IsCA               bool     `json:"is_ca"`
	ExtKeyUsage        []string `json:"ext_key_usage,omitempty"`
	CRLEndpoints       []string `json:"crl_endpoints,omitempty"`
	OCSPServers        []string `json:"ocsp_servers,omitempty"`
	IssuingCertURL     []string `json:"issuing_cert_url,omitempty"`
}

// ParseDER parses a DER-encoded X.509 certificate and extracts metadata.
func ParseDER(der []byte) (*CertMeta, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certutil.ParseDER: %w", err)
	}
	return fromCert(cert), nil
}

// ParseLogEntry extracts the DER certificate from an MTC log entry and parses it.
// Log entry format: [uint16 LE type][uint32 LE length][DER blob]
func ParseLogEntry(entryData []byte) (*CertMeta, []byte, error) {
	if len(entryData) < 6 {
		return nil, nil, fmt.Errorf("certutil.ParseLogEntry: entry too short (%d bytes)", len(entryData))
	}
	entryType := uint16(entryData[0]) | uint16(entryData[1])<<8
	if entryType == 0 {
		return nil, nil, fmt.Errorf("certutil.ParseLogEntry: null entry (type 0)")
	}
	if entryType != 1 {
		return nil, nil, fmt.Errorf("certutil.ParseLogEntry: unsupported entry type %d", entryType)
	}
	derLen := uint32(entryData[2]) | uint32(entryData[3])<<8 | uint32(entryData[4])<<16 | uint32(entryData[5])<<24
	if int(derLen)+6 > len(entryData) {
		return nil, nil, fmt.Errorf("certutil.ParseLogEntry: DER length %d exceeds entry size %d", derLen, len(entryData)-6)
	}
	der := entryData[6 : 6+derLen]
	meta, err := ParseDER(der)
	if err != nil {
		return nil, der, err
	}
	return meta, der, nil
}

func fromCert(cert *x509.Certificate) *CertMeta {
	m := &CertMeta{
		CommonName:         cert.Subject.CommonName,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Country:            cert.Subject.Country,
		Province:           cert.Subject.Province,
		Locality:           cert.Subject.Locality,
		SerialNumber:       formatSerial(cert.SerialNumber.Bytes()),
		IssuerCN:           cert.Issuer.CommonName,
		IssuerOrganization: cert.Issuer.Organization,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		KeyAlgorithm:       cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		CRLEndpoints:       cert.CRLDistributionPoints,
		OCSPServers:        cert.OCSPServer,
		IssuingCertURL:     cert.IssuingCertificateURL,
	}
	for _, dns := range cert.DNSNames {
		m.SANs = append(m.SANs, dns)
	}
	for _, ip := range cert.IPAddresses {
		m.SANs = append(m.SANs, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		m.SANs = append(m.SANs, email)
	}
	for _, uri := range cert.URIs {
		m.SANs = append(m.SANs, uri.String())
	}
	m.KeyUsage = formatKeyUsage(cert.KeyUsage)
	m.ExtKeyUsage = formatExtKeyUsage(cert.ExtKeyUsage)
	return m
}

func formatSerial(b []byte) string {
	if len(b) == 0 {
		return "0"
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	var usages []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", eku))
		}
	}
	return usages
}
