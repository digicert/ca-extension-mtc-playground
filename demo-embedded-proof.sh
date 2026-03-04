#!/bin/bash
# Copyright (C) 2026 DigiCert, Inc.
#
# Licensed under the dual-license model:
#   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
#   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
#
# For commercial licensing, contact sales@digicert.com.

# Demo: Embedded MTC inclusion proofs in X.509 certificates
#
# This script demonstrates the two-phase signing flow where the local CA
# embeds a Merkle inclusion proof directly into the X.509 certificate.
# The verifier (mtc-verify-cert) extracts the proof and verifies it offline.
#
# Prerequisites:
#   - mtc-bridge running with local_ca enabled
#   - Local CA key + cert generated (make generate-local-ca)
#   - ACME server running on :8443
set -euo pipefail

ACME_URL="${ACME_URL:-https://localhost:8443}"
BRIDGE_URL="${BRIDGE_URL:-http://localhost:8080}"
DOMAIN="embedded-proof-demo.example.com"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "=== MTC Embedded Proof Demo ==="
echo "  ACME:    $ACME_URL"
echo "  Bridge:  $BRIDGE_URL"
echo "  Domain:  $DOMAIN"
echo ""

# Step 1: Build binaries.
echo "Building binaries..."
make build 2>&1 | tail -1
echo ""

# Step 2: Check bridge is running.
echo -n "Checking bridge... "
if ! curl -sf "$BRIDGE_URL/healthz" > /dev/null 2>&1; then
  echo "FAIL"
  echo "ERROR: mtc-bridge not reachable at $BRIDGE_URL"
  echo "Start it with: docker compose up -d"
  exit 1
fi
echo "OK"

# Step 3: Check ACME directory.
echo -n "Checking ACME server... "
if ! curl -sfk "$ACME_URL/acme/directory" > /dev/null 2>&1; then
  echo "FAIL"
  echo "ERROR: ACME server not reachable at $ACME_URL"
  exit 1
fi
echo "OK"
echo ""

# Step 4: Run the full ACME conformance test which exercises the local CA
# embedded proof flow end-to-end.
echo "Running ACME conformance tests (includes embedded proof flow)..."
echo ""
./bin/mtc-conformance -url "$BRIDGE_URL" -acme-url "$ACME_URL" -verbose 2>&1 | grep -E "(acme_|PASS|FAIL|Results)"
echo ""

# Step 5: If a certificate was issued, demonstrate mtc-verify-cert.
# The conformance test creates a cert via ACME. We can verify any cert
# that was issued with the local CA by downloading it from the ACME endpoint.
echo "--- Standalone Verification ---"
echo ""
echo "To verify a certificate with an embedded proof, use:"
echo ""
echo "  ./bin/mtc-verify-cert -cert <cert.pem> [-bridge-url $BRIDGE_URL]"
echo ""
echo "The verifier will:"
echo "  1. Parse the X.509 certificate"
echo "  2. Extract the MTC inclusion proof extension (OID 1.3.6.1.4.1.99999.1.1)"
echo "  3. Strip the extension to reconstruct the canonical TBSCertificate"
echo "  4. Compute the leaf hash and verify the Merkle inclusion proof"
echo "  5. Optionally compare the root hash against the live checkpoint"
echo ""
echo "=== Demo Complete ==="
