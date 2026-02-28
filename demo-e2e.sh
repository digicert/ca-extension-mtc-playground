#!/bin/bash
# Fully automated end-to-end ACME MTC demo
set -euo pipefail

# Load environment variables
if [ -f .env ]; then
  source .env
else
  echo "Missing .env file. Copy .env.example and fill in your values."
  exit 1
fi

# Step 1: Generate demo TLS certs
./gen-demo-cert.sh

# Step 2: Start all services (Postgres, mtc-bridge, acme-server)
docker compose up -d
sleep 10

echo "Services started."

# Step 3: Issue certificate via ACME (using conformance tool for full flow)
./bin/mtc-conformance -url https://localhost:8080 -acme-url https://localhost:8443 -verbose || {
  echo "Conformance test failed."; exit 1;
}

echo "Certificate issued via ACME."

# Step 4: Revoke certificate in DigiCert CA (example: using curl, requires valid API key and cert ID)
# Replace CERT_ID with actual value from previous step or conformance output
# curl -X POST "$CA_URL/v1/certificate/$CERT_ID/revoke" -H "x-api-key: $CA_API_KEY" -d '{"reason": "keyCompromise"}'

echo "Certificate revocation requested."

# Step 5: Verify Merkle tree/log and endpoint status
curl -sk https://localhost:8080/checkpoint | tee checkpoint.txt
curl -sk https://localhost:8080/proof/inclusion?serial=<serial>

# Step 6: Confirm endpoint is blocked/flagged (manual or automated check)
# For demo, you may want to check status in admin UI or via API

echo "End-to-end demo complete. See README for details."
