#!/bin/bash
# Copyright (C) 2026 DigiCert, Inc.
#
# Licensed under the dual-license model:
#   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
#   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
#
# For commercial licensing, contact sales@digicert.com.

# Demo script: Automated ACME order flow
set -euo pipefail

ACME_URL="http://localhost:8443"
DOMAIN="mtc-demo.example.com"
CSR_PATH="/tmp/mtc-demo.csr"
KEY_PATH="/tmp/mtc-demo.key"

# Step 1: Generate key and CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$KEY_PATH" \
  -subj "/CN=$DOMAIN/O=MTC Demo Corp/C=US" \
  -addext "subjectAltName=DNS:$DOMAIN" \
  -out "$CSR_PATH" 2>/dev/null

CSR=$(awk '{printf "%s\\n", $0}' "$CSR_PATH")

# Step 2: Get ACME directory
curl -s "$ACME_URL/acme/directory" | python3 -m json.tool

# Step 3: Get a replay nonce
NONCE=$(curl -sI "$ACME_URL/acme/new-nonce" | grep -i replay-nonce | awk '{print $2}')
echo "Replay Nonce: $NONCE"

# Step 4: Create account (JWS POST)
# NOTE: This step requires JWS construction. For demo, use conformance tool or Postman collection for full flow.

echo "Run ./bin/mtc-conformance -url http://localhost:8080 -acme-url $ACME_URL -verbose for full automated test."
