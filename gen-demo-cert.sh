#!/bin/bash
# Generate self-signed cert for ACME demo endpoint
set -euo pipefail
CERT_PATH="acme-cert.pem"
KEY_PATH="acme-key.pem"
DOMAIN="localhost"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY_PATH" -out "$CERT_PATH" -days 365 \
  -subj "/CN=$DOMAIN/O=MTC Demo/C=US" -addext "subjectAltName=DNS:$DOMAIN"
echo "Self-signed cert and key generated: $CERT_PATH, $KEY_PATH"
