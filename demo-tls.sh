#!/bin/bash
# Copyright (C) 2026 DigiCert, Inc.
#
# Licensed under the dual-license model:
#   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
#   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
#
# For commercial licensing, contact sales@digicert.com.

# Demo: MTC assertion stapling in TLS handshakes
#
# This script issues a fresh certificate via the DigiCert CA, waits for
# the mtc-bridge to generate an assertion bundle, then starts the MTC TLS
# server and runs the verification client to prove end-to-end assertion
# stapling through a TLS handshake.
#
# Prerequisites:
#   - mtc-bridge running at BRIDGE_URL (default http://localhost:8080)
#   - DigiCert CA accessible at CA_URL with valid CA_API_KEY, CA_ID, CA_TEMPLATE_ID
#   - .env file with the above variables (or export them)
set -euo pipefail

# Load environment variables.
if [ -f .env ]; then
  set -a; source .env; set +a
else
  echo "Missing .env file. Copy .env.example and fill in your values."
  exit 1
fi

BRIDGE_URL="${BRIDGE_URL:-http://localhost:8080}"
CA_URL="${CA_URL:-http://localhost}"
TLS_ADDR="${TLS_ADDR:-:4443}"
DEMO_CN="tls-demo.meridianfs.com"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR; [ -n '${SERVER_PID:-}' ] && kill $SERVER_PID 2>/dev/null || true" EXIT

echo "=== MTC TLS Assertion Stapling Demo ==="
echo "  Bridge:  $BRIDGE_URL"
echo "  CA:      $CA_URL"
echo "  Domain:  $DEMO_CN"
echo ""

# Step 1: Build binaries.
echo "Building binaries..."
make build 2>&1 | tail -1
echo ""

# Step 2: Check bridge is running.
echo -n "Checking bridge... "
if ! curl -sf "$BRIDGE_URL/checkpoint" > /dev/null 2>&1; then
  echo "FAIL"
  echo "ERROR: mtc-bridge not reachable at $BRIDGE_URL"
  echo "Start it first: make run"
  exit 1
fi
echo "OK"

# Step 3: Generate RSA key and CSR.
echo -n "Generating key and CSR... "
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$TMPDIR/key.pem" \
  -subj "/CN=$DEMO_CN/O=MTC TLS Demo/C=US" \
  -addext "subjectAltName=DNS:$DEMO_CN" \
  -out "$TMPDIR/csr.pem" 2>/dev/null
CSR=$(cat "$TMPDIR/csr.pem")
echo "OK"

# Step 4: Issue certificate via DigiCert CA.
echo -n "Issuing certificate via CA... "
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EXPIRY=$(date -u -v+365d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "+365 days" +"%Y-%m-%dT%H:%M:%SZ")

PAYLOAD=$(cat <<ENDJSON
{
  "issuer": {"id": "$CA_ID"},
  "template_id": "$CA_TEMPLATE_ID",
  "cert_type": "private_ssl",
  "csr": $(echo "$CSR" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))'),
  "subject": {
    "common_name": "$DEMO_CN",
    "organization_name": "MTC TLS Demo",
    "country": "US"
  },
  "validity": {
    "valid_from": "$NOW",
    "valid_to": "$EXPIRY"
  },
  "extensions": {
    "san": {
      "dns_names": ["$DEMO_CN"]
    }
  }
}
ENDJSON
)

RESP=$(curl -sf -X POST "$CA_URL/certificate-authority/api/v1/certificate" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $CA_API_KEY" \
  -d "$PAYLOAD")

SERIAL=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('serial_number',''))" 2>/dev/null || true)
if [ -z "$SERIAL" ]; then
  echo "FAIL"
  echo "ERROR: Failed to issue certificate. Response: $RESP"
  exit 1
fi
echo "OK (serial: ${SERIAL:0:16}...)"

# Step 5: Download certificate PEM from CA.
echo -n "Downloading certificate... "
CERT_RESP=$(curl -sf "$CA_URL/certificate-authority/api/v1/certificate/$SERIAL" \
  -H "Accept: application/x-pem-file" \
  -H "x-api-key: $CA_API_KEY" || true)

if echo "$CERT_RESP" | grep -q "BEGIN CERTIFICATE"; then
  echo "$CERT_RESP" > "$TMPDIR/cert.pem"
  echo "OK"
else
  # Try alternate endpoint format.
  CERT_RESP=$(curl -sf "$CA_URL/certificate-authority/api/v1/certificate/$SERIAL/download" \
    -H "Accept: application/x-pem-file" \
    -H "x-api-key: $CA_API_KEY" || true)
  if echo "$CERT_RESP" | grep -q "BEGIN CERTIFICATE"; then
    echo "$CERT_RESP" > "$TMPDIR/cert.pem"
    echo "OK"
  else
    echo "FAIL (could not download PEM)"
    echo "You may need to export the cert manually and run:"
    echo "  ./bin/mtc-tls-server -cert cert.pem -key key.pem"
    exit 1
  fi
fi

# Step 6: Wait for assertion bundle.
echo -n "Waiting for assertion bundle"
SERIAL_UPPER=$(echo "$SERIAL" | tr '[:lower:]' '[:upper:]')
for i in $(seq 1 30); do
  if curl -sf "$BRIDGE_URL/assertion/$SERIAL_UPPER" > /dev/null 2>&1; then
    echo " OK"
    break
  fi
  echo -n "."
  sleep 5
done

if ! curl -sf "$BRIDGE_URL/assertion/$SERIAL_UPPER" > /dev/null 2>&1; then
  echo " TIMEOUT"
  echo "WARNING: Assertion not yet available after 150s."
  echo "The server will start without a stapled assertion."
fi

# Step 7: Start TLS server.
echo ""
echo "Starting MTC TLS server on $TLS_ADDR..."
./bin/mtc-tls-server \
  -cert "$TMPDIR/cert.pem" \
  -key "$TMPDIR/key.pem" \
  -bridge-url "$BRIDGE_URL" \
  -addr "$TLS_ADDR" \
  -refresh 30 &
SERVER_PID=$!
sleep 2

# Step 8: Run verification.
echo ""
echo "--- Verification ---"
echo ""
./bin/mtc-tls-verify \
  -url "https://localhost${TLS_ADDR}" \
  -bridge-url "$BRIDGE_URL" \
  -insecure

echo ""
echo "=== Demo Complete ==="
echo ""
echo "The TLS server is still running at https://localhost${TLS_ADDR}"
echo "  Status page:  https://localhost${TLS_ADDR}/"
echo "  JSON status:  https://localhost${TLS_ADDR}/mtc-status"
echo ""
echo "Press Ctrl+C to stop."
wait $SERVER_PID
