// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command demo-embedded-cert demonstrates the full two-phase MTC signing flow
// end-to-end, producing a certificate with an embedded Merkle inclusion proof.
//
// It runs entirely locally with no database or network dependencies:
//  1. Generates a temporary CA key + certificate
//  2. Generates a client key + CSR
//  3. Phase 1: Issues a pre-certificate (no MTC extension)
//  4. Builds a small Merkle tree containing the canonical TBSCertificate
//  5. Computes the inclusion proof
//  6. Phase 2: Re-signs with the MTC proof extension embedded
//  7. Writes the final certificate PEM to stdout or a file
//  8. Verifies the embedded proof
//
// Usage:
//
//	demo-embedded-cert [-domain example.com] [-output cert.pem]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/localca"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtccert"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
)

func main() {
	domain := flag.String("domain", "demo.example.com", "domain name for the certificate")
	output := flag.String("output", "", "output PEM file path (default: stdout)")
	mtcMode := flag.Bool("mtc-mode", false, "generate MTC-spec cert (id-alg-mtcProof) instead of legacy X.509 extension")
	flag.Parse()

	if *mtcMode {
		runMTCMode(*domain, *output)
		return
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "MTC Embedded Proof — Certificate Generation Demo")
	fmt.Fprintln(os.Stderr, "=================================================")
	fmt.Fprintln(os.Stderr, "")

	// Step 1: Generate temporary CA.
	fmt.Fprintln(os.Stderr, "Step 1: Generating temporary CA (ECDSA P-256)...")
	tmpDir, err := os.MkdirTemp("", "mtc-demo-*")
	if err != nil {
		fatal("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caKeyFile := filepath.Join(tmpDir, "ca.key")
	caCertFile := filepath.Join(tmpDir, "ca.pem")
	if err := localca.GenerateCA(caKeyFile, caCertFile, "MTC Demo CA", "US"); err != nil {
		fatal("generate CA: %v", err)
	}

	ca, err := localca.New(localca.Config{
		KeyFile:  caKeyFile,
		CertFile: caCertFile,
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		fatal("load CA: %v", err)
	}
	fmt.Fprintf(os.Stderr, "        Issuer: %s\n", ca.CACert().Subject.CommonName)
	fmt.Fprintln(os.Stderr, "")

	// Step 2: Generate client key + CSR.
	fmt.Fprintf(os.Stderr, "Step 2: Generating client CSR for %s...\n", *domain)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("generate client key: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   *domain,
			Organization: []string{"MTC Demo"},
			Country:      []string{"US"},
		},
		DNSNames: []string{*domain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	if err != nil {
		fatal("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		fatal("parse CSR: %v", err)
	}
	fmt.Fprintln(os.Stderr, "")

	// Step 3: Phase 1 — Issue pre-certificate.
	fmt.Fprintln(os.Stderr, "Step 3: Phase 1 — Issuing pre-certificate (no MTC extension)...")
	precert, err := ca.IssuePrecert(csr, []string{*domain}, 0)
	if err != nil {
		fatal("issue precert: %v", err)
	}
	serialHex := strings.ToUpper(hex.EncodeToString(precert.Serial.Bytes()))
	fmt.Fprintf(os.Stderr, "        Serial:    %s\n", serialHex)
	fmt.Fprintf(os.Stderr, "        Not Before: %s\n", precert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(os.Stderr, "        Not After:  %s\n", precert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(os.Stderr, "        TBS size:   %d bytes (canonical form for Merkle hashing)\n", len(precert.CanonicalTBS))
	fmt.Fprintln(os.Stderr, "")

	// Step 4: Build Merkle tree.
	fmt.Fprintln(os.Stderr, "Step 4: Building Merkle tree with pre-cert entry...")
	entryData := localca.BuildPrecertEntryData(precert.CanonicalTBS)
	leafHash := merkle.LeafHash(entryData)

	// Create a tree with 4 leaves: null entry, our cert, two dummy entries.
	nullEntry := []byte{0x00, 0x00}
	dummyEntry1 := []byte{0x01, 0x00, 5, 0, 0, 0, 'h', 'e', 'l', 'l', 'o'}
	dummyEntry2 := []byte{0x01, 0x00, 5, 0, 0, 0, 'w', 'o', 'r', 'l', 'd'}

	leaves := [][]byte{nullEntry, entryData, dummyEntry1, dummyEntry2}
	rootHash := merkle.MTH(leaves)
	treeSize := int64(len(leaves))

	fmt.Fprintf(os.Stderr, "        Leaf index: 1 (our cert)\n")
	fmt.Fprintf(os.Stderr, "        Tree size:  %d entries\n", treeSize)
	fmt.Fprintf(os.Stderr, "        Leaf hash:  %s\n", hex.EncodeToString(leafHash[:]))
	fmt.Fprintf(os.Stderr, "        Root hash:  %s\n", hex.EncodeToString(rootHash[:]))
	fmt.Fprintln(os.Stderr, "")

	// Step 5: Compute inclusion proof.
	fmt.Fprintln(os.Stderr, "Step 5: Computing Merkle inclusion proof...")
	hashAt := func(idx int64) merkle.Hash { return merkle.LeafHash(leaves[idx]) }
	proofHashes, err := merkle.InclusionProof(1, treeSize, hashAt)
	if err != nil {
		fatal("inclusion proof: %v", err)
	}
	fmt.Fprintf(os.Stderr, "        Proof depth: %d sibling hashes\n", len(proofHashes))
	for i, h := range proofHashes {
		fmt.Fprintf(os.Stderr, "        Sibling[%d]: %s\n", i, hex.EncodeToString(h[:]))
	}
	fmt.Fprintln(os.Stderr, "")

	// Build the checkpoint text.
	checkpointText := fmt.Sprintf("demo-log\n%d\n%s\n",
		treeSize,
		hex.EncodeToString(rootHash[:]),
	)

	// Convert proof hashes for the extension.
	proofBytes := make([][]byte, len(proofHashes))
	for i, h := range proofHashes {
		ph := make([]byte, merkle.HashSize)
		copy(ph, h[:])
		proofBytes[i] = ph
	}
	proofExt := &localca.InclusionProofExt{
		LogOrigin:   "demo-log",
		LeafIndex:   1,
		TreeSize:    treeSize,
		RootHash:    rootHash[:],
		ProofHashes: proofBytes,
		Checkpoint:  checkpointText,
	}

	// Step 6: Phase 2 — Re-sign with embedded proof.
	fmt.Fprintln(os.Stderr, "Step 6: Phase 2 — Re-signing with MTC inclusion proof extension...")
	finalDER, err := ca.IssueWithProof(csr, precert, proofExt)
	if err != nil {
		fatal("issue final cert: %v", err)
	}
	fmt.Fprintf(os.Stderr, "        Final cert: %d bytes DER\n", len(finalDER))
	fmt.Fprintln(os.Stderr, "")

	// Step 7: Verify the embedded proof.
	fmt.Fprintln(os.Stderr, "Step 7: Verifying embedded proof...")
	parsedProof, ok, err := localca.VerifyEmbeddedProof(finalDER)
	if err != nil {
		fatal("verify embedded proof: %v", err)
	}
	if !ok {
		fatal("embedded proof verification FAILED")
	}
	fmt.Fprintf(os.Stderr, "        [PASS] MTC extension found (OID %s)\n", localca.OIDMTCInclusionProof)
	fmt.Fprintf(os.Stderr, "        [PASS] Log Origin:  %s\n", parsedProof.LogOrigin)
	fmt.Fprintf(os.Stderr, "        [PASS] Leaf Index:  %d\n", parsedProof.LeafIndex)
	fmt.Fprintf(os.Stderr, "        [PASS] Tree Size:   %d\n", parsedProof.TreeSize)
	fmt.Fprintf(os.Stderr, "        [PASS] Root Hash:   %s\n", hex.EncodeToString(parsedProof.RootHash))
	fmt.Fprintf(os.Stderr, "        [PASS] Proof Depth: %d sibling hashes\n", len(parsedProof.ProofHashes))
	fmt.Fprintf(os.Stderr, "        [PASS] Merkle inclusion proof is VALID\n")
	fmt.Fprintln(os.Stderr, "")

	// Output the certificate PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: finalDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CACertDER()})

	if *output != "" {
		chainPEM := append(certPEM, caPEM...)
		if err := os.WriteFile(*output, chainPEM, 0644); err != nil {
			fatal("write output: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Certificate written to: %s\n", *output)
		fmt.Fprintf(os.Stderr, "Inspect with: openssl x509 -in %s -text -noout\n", *output)
	} else {
		fmt.Fprintln(os.Stderr, "--- BEGIN CERTIFICATE PEM ---")
		fmt.Fprintln(os.Stderr, "")
		os.Stdout.Write(certPEM)
		os.Stdout.Write(caPEM)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "--- END CERTIFICATE PEM ---")
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Done. The certificate above contains the MTC inclusion proof")
	fmt.Fprintln(os.Stderr, "embedded as a non-critical X.509 extension at OID 1.3.6.1.4.1.99999.1.1")
}

func runMTCMode(domain, output string) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "MTC-Spec Certificate Generation Demo")
	fmt.Fprintln(os.Stderr, "=====================================")
	fmt.Fprintln(os.Stderr, "  Format: signatureAlgorithm = id-alg-mtcProof")
	fmt.Fprintln(os.Stderr, "  Proof embedded in signatureValue field")
	fmt.Fprintln(os.Stderr, "")

	// Step 1: Generate client key + CSR.
	fmt.Fprintf(os.Stderr, "Step 1: Generating client CSR for %s...\n", domain)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("generate client key: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"MTC Demo"},
			Country:      []string{"US"},
		},
		DNSNames: []string{domain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	if err != nil {
		fatal("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		fatal("parse CSR: %v", err)
	}
	fmt.Fprintln(os.Stderr, "")

	// Step 2: Build MerkleTreeCertEntry (spec log entry format).
	fmt.Fprintln(os.Stderr, "Step 2: Building TBSCertificateLogEntry (SPKI hashed)...")
	issuer := pkix.Name{CommonName: "MTC Demo CA", Country: []string{"US"}}
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	logEntryDER, err := mtcformat.BuildLogEntryFromCSR(issuer, notBefore, notAfter, csr, []string{domain})
	if err != nil {
		fatal("build log entry: %v", err)
	}

	spkiHash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	fmt.Fprintf(os.Stderr, "        SPKI hash: %s\n", hex.EncodeToString(spkiHash[:]))
	fmt.Fprintf(os.Stderr, "        Log entry: %d bytes DER\n", len(logEntryDER))

	mtcEntry := &mtcformat.MerkleTreeCertEntry{
		Type: mtcformat.EntryTypeTBSCert,
		Data: logEntryDER,
	}
	wireData, err := mtcformat.MarshalEntry(mtcEntry)
	if err != nil {
		fatal("marshal entry: %v", err)
	}
	fmt.Fprintf(os.Stderr, "        Wire data: %d bytes (1B type + 3B len + DER)\n", len(wireData))
	fmt.Fprintln(os.Stderr, "")

	// Step 3: Build Merkle tree.
	fmt.Fprintln(os.Stderr, "Step 3: Building Merkle tree...")
	leafHash := merkle.LeafHash(wireData)

	nullEntry, _ := mtcformat.MarshalEntry(&mtcformat.MerkleTreeCertEntry{Type: mtcformat.EntryTypeNull})
	dummyEntry1, _ := mtcformat.MarshalEntry(&mtcformat.MerkleTreeCertEntry{Type: mtcformat.EntryTypeNull})
	dummyEntry2, _ := mtcformat.MarshalEntry(&mtcformat.MerkleTreeCertEntry{Type: mtcformat.EntryTypeNull})

	leaves := [][]byte{nullEntry, wireData, dummyEntry1, dummyEntry2}
	rootHash := merkle.MTH(leaves)
	treeSize := int64(len(leaves))
	leafIndex := int64(1)

	fmt.Fprintf(os.Stderr, "        Leaf index: %d\n", leafIndex)
	fmt.Fprintf(os.Stderr, "        Tree size:  %d entries\n", treeSize)
	fmt.Fprintf(os.Stderr, "        Leaf hash:  %s\n", hex.EncodeToString(leafHash[:]))
	fmt.Fprintf(os.Stderr, "        Root hash:  %s\n", hex.EncodeToString(rootHash[:]))
	fmt.Fprintln(os.Stderr, "")

	// Step 4: Compute inclusion proof + build MTCProof.
	fmt.Fprintln(os.Stderr, "Step 4: Computing inclusion proof and building MTCProof...")
	hashAt := func(idx int64) merkle.Hash { return merkle.LeafHash(leaves[idx]) }
	proofHashes, err := merkle.InclusionProof(leafIndex, treeSize, hashAt)
	if err != nil {
		fatal("inclusion proof: %v", err)
	}
	proofBytes := make([][]byte, len(proofHashes))
	for i, h := range proofHashes {
		ph := make([]byte, merkle.HashSize)
		copy(ph, h[:])
		proofBytes[i] = ph
	}

	mtcProof := &mtcformat.MTCProof{
		Start:          0,
		End:            uint64(treeSize),
		InclusionProof: proofBytes,
		Signatures:     nil, // signatureless mode
	}

	fmt.Fprintf(os.Stderr, "        Subtree:     [%d, %d)\n", mtcProof.Start, mtcProof.End)
	fmt.Fprintf(os.Stderr, "        Proof depth: %d sibling hashes\n", len(proofHashes))
	fmt.Fprintf(os.Stderr, "        Mode:        signatureless\n")
	fmt.Fprintln(os.Stderr, "")

	// Step 5: Build MTC certificate.
	fmt.Fprintln(os.Stderr, "Step 5: Building MTC certificate (id-alg-mtcProof)...")
	certDER, err := mtccert.BuildMTCCertFromCSR(csr, issuer, notBefore, notAfter, []string{domain}, leafIndex, mtcProof)
	if err != nil {
		fatal("build MTC cert: %v", err)
	}
	fmt.Fprintf(os.Stderr, "        Cert size: %d bytes DER\n", len(certDER))
	fmt.Fprintf(os.Stderr, "        Serial:    %d (= leaf index)\n", leafIndex)
	fmt.Fprintln(os.Stderr, "")

	// Step 6: Verify the MTC certificate.
	fmt.Fprintln(os.Stderr, "Step 6: Verifying MTC certificate...")
	if !mtccert.IsMTCCertificate(certDER) {
		fatal("IsMTCCertificate returned false")
	}
	fmt.Fprintln(os.Stderr, "        [PASS] Detected as MTC-spec format")

	parsed, err := mtccert.ParseMTCCertificate(certDER)
	if err != nil {
		fatal("parse MTC cert: %v", err)
	}
	fmt.Fprintf(os.Stderr, "        [PASS] Parsed: serial=%d, subtree=[%d,%d)\n",
		parsed.SerialNumber, parsed.Proof.Start, parsed.Proof.End)

	result, err := mtccert.VerifyMTCCert(certDER, mtccert.VerifyOptions{})
	if err != nil {
		fatal("verify MTC cert: %v", err)
	}
	if result.ProofValid {
		fmt.Fprintf(os.Stderr, "        [PASS] Inclusion proof valid\n")
	} else {
		fatal("inclusion proof invalid")
	}
	fmt.Fprintf(os.Stderr, "        [PASS] Mode: %s\n", result.Mode)
	fmt.Fprintln(os.Stderr, "")

	// Output the certificate PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		fatal("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if output != "" {
		if err := os.WriteFile(output, certPEM, 0644); err != nil {
			fatal("write cert: %v", err)
		}
		keyOutput := strings.TrimSuffix(output, filepath.Ext(output)) + ".key"
		if err := os.WriteFile(keyOutput, keyPEM, 0600); err != nil {
			fatal("write key: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Certificate written to: %s\n", output)
		fmt.Fprintf(os.Stderr, "Private key written to: %s\n", keyOutput)
		fmt.Fprintf(os.Stderr, "Verify with: go run ./cmd/mtc-verify-cert -cert %s\n", output)
	} else {
		fmt.Fprintln(os.Stderr, "--- BEGIN CERTIFICATE PEM ---")
		fmt.Fprintln(os.Stderr, "")
		os.Stdout.Write(certPEM)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "--- END CERTIFICATE PEM ---")
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Done. The certificate uses signatureAlgorithm = id-alg-mtcProof")
	fmt.Fprintln(os.Stderr, "with the MTC inclusion proof in the signatureValue field.")
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
