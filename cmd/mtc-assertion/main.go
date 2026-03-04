// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command mtc-assertion is a CLI tool for fetching, verifying, and inspecting
// MTC assertion bundles from a running mtc-bridge server.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	command := os.Args[1]
	switch command {
	case "fetch":
		cmdFetch(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "inspect":
		cmdInspect(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`mtc-assertion - MTC Assertion Bundle CLI

Usage:
  mtc-assertion <command> [options]

Commands:
  fetch      Fetch an assertion bundle from a running mtc-bridge server
  verify     Verify an assertion bundle's inclusion proof
  inspect    Display human-readable details of an assertion bundle

Fetch options:
  -url       Base URL of mtc-bridge server (default: http://localhost:8080)
  -serial    Certificate serial number (hex)
  -index     Log entry index
  -format    Output format: json or pem (default: json)
  -output    Output file (default: stdout)

Verify options:
  -input     Path to assertion bundle JSON file

Inspect options:
  -input     Path to assertion bundle JSON file`)
}

func cmdFetch(args []string) {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	baseURL := fs.String("url", "http://localhost:8080", "base URL of mtc-bridge server")
	serial := fs.String("serial", "", "certificate serial number (hex)")
	index := fs.Int64("index", -1, "log entry index")
	format := fs.String("format", "json", "output format: json or pem")
	output := fs.String("output", "", "output file (default: stdout)")
	fs.Parse(args)

	if *serial == "" && *index < 0 {
		fmt.Fprintln(os.Stderr, "error: specify -serial or -index")
		os.Exit(1)
	}

	var query string
	if *serial != "" {
		query = *serial
	} else {
		query = fmt.Sprintf("%d", *index)
	}

	url := strings.TrimRight(*baseURL, "/") + "/assertion/" + query
	if *format == "pem" {
		url += "/pem"
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading response: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "error: server returned %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}

	var w io.Writer = os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	w.Write(body)
	if *output != "" {
		fmt.Fprintf(os.Stderr, "Assertion bundle saved to %s\n", *output)
	}
}

type bundleForVerify struct {
	LeafIndex int64    `json:"leaf_index"`
	LeafHash  string   `json:"leaf_hash"`
	Proof     []string `json:"proof"`
	TreeSize  int64    `json:"tree_size"`
	RootHash  string   `json:"root_hash"`
	SerialHex string   `json:"serial_hex"`
	Revoked   bool     `json:"revoked"`
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	input := fs.String("input", "", "path to assertion bundle JSON file")
	fs.Parse(args)

	if *input == "" {
		fmt.Fprintln(os.Stderr, "error: specify -input")
		os.Exit(1)
	}

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}

	var bundle bundleForVerify
	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	leafBytes, err := hex.DecodeString(bundle.LeafHash)
	if err != nil || len(leafBytes) != 32 {
		fmt.Fprintln(os.Stderr, "error: invalid leaf hash")
		os.Exit(1)
	}
	rootBytes, err := hex.DecodeString(bundle.RootHash)
	if err != nil || len(rootBytes) != 32 {
		fmt.Fprintln(os.Stderr, "error: invalid root hash")
		os.Exit(1)
	}

	proofHashes := make([][]byte, len(bundle.Proof))
	for i, ph := range bundle.Proof {
		b, err := hex.DecodeString(ph)
		if err != nil || len(b) != 32 {
			fmt.Fprintf(os.Stderr, "error: invalid proof hash at index %d\n", i)
			os.Exit(1)
		}
		proofHashes[i] = b
	}

	h := sha256.New()
	current := make([]byte, 32)
	copy(current, leafBytes)
	idx := bundle.LeafIndex
	for _, sibling := range proofHashes {
		h.Reset()
		h.Write([]byte{0x01})
		if idx%2 == 0 {
			h.Write(current)
			h.Write(sibling)
		} else {
			h.Write(sibling)
			h.Write(current)
		}
		current = h.Sum(nil)
		idx /= 2
	}

	match := true
	for i := 0; i < 32; i++ {
		if current[i] != rootBytes[i] {
			match = false
			break
		}
	}

	if match {
		fmt.Println("Inclusion proof is VALID")
		fmt.Printf("  Leaf index: %d\n", bundle.LeafIndex)
		fmt.Printf("  Tree size:  %d\n", bundle.TreeSize)
		fmt.Printf("  Root hash:  %s\n", bundle.RootHash)
		if bundle.Revoked {
			fmt.Println("  Certificate is REVOKED")
		}
	} else {
		fmt.Println("Inclusion proof is INVALID")
		fmt.Printf("  Expected root: %s\n", bundle.RootHash)
		fmt.Printf("  Got root:      %s\n", hex.EncodeToString(current))
		os.Exit(1)
	}
}

func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	input := fs.String("input", "", "path to assertion bundle JSON file")
	fs.Parse(args)

	if *input == "" {
		fmt.Fprintln(os.Stderr, "error: specify -input")
		os.Exit(1)
	}

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}

	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== MTC Assertion Bundle ===")
	fmt.Println()

	printField("Log Origin", bundle["log_origin"])
	printField("Leaf Index", bundle["leaf_index"])
	printField("Tree Size", bundle["tree_size"])
	printField("Serial", bundle["serial_hex"])
	printField("Revoked", bundle["revoked"])
	printField("Leaf Hash", bundle["leaf_hash"])
	printField("Root Hash", bundle["root_hash"])

	if proof, ok := bundle["proof"].([]interface{}); ok {
		fmt.Printf("  %-20s %d hashes\n", "Proof Length:", len(proof))
		for i, ph := range proof {
			fmt.Printf("    [%d] %v\n", i, ph)
		}
	}

	if meta, ok := bundle["cert_meta"].(map[string]interface{}); ok {
		fmt.Println()
		fmt.Println("--- Certificate Details ---")
		printField("Common Name", meta["common_name"])
		printField("Organization", meta["organization"])
		printField("Serial", meta["serial_number"])
		printField("Not Before", meta["not_before"])
		printField("Not After", meta["not_after"])
		printField("Key Algorithm", meta["key_algorithm"])
		printField("Sig Algorithm", meta["signature_algorithm"])
		printField("Issuer CN", meta["issuer_cn"])
		printField("SANs", meta["sans"])
		printField("Key Usage", meta["key_usage"])
		printField("Ext Key Usage", meta["ext_key_usage"])
		printField("Is CA", meta["is_ca"])
	}

	if cp, ok := bundle["checkpoint"].(string); ok {
		fmt.Println()
		fmt.Println("--- Checkpoint ---")
		fmt.Println(cp)
	}
}

func printField(label string, value interface{}) {
	if value == nil {
		return
	}
	switch v := value.(type) {
	case string:
		if v == "" {
			return
		}
		fmt.Printf("  %-20s %s\n", label+":", v)
	case float64:
		fmt.Printf("  %-20s %.0f\n", label+":", v)
	case bool:
		fmt.Printf("  %-20s %t\n", label+":", v)
	case []interface{}:
		if len(v) == 0 {
			return
		}
		for i, item := range v {
			if i == 0 {
				fmt.Printf("  %-20s %v\n", label+":", item)
			} else {
				fmt.Printf("  %-20s %v\n", "", item)
			}
		}
	default:
		fmt.Printf("  %-20s %v\n", label+":", v)
	}
}
