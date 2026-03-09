# Copyright (C) 2026 DigiCert, Inc.
#
# Licensed under the dual-license model:
#   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
#   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
#
# For commercial licensing, contact sales@digicert.com.

.PHONY: build test vet lint clean run generate-key generate-local-ca conformance interop demo-tls demo-embedded demo-mtc docker docker-up docker-down help

# Default target
help:
	@echo "MTC Bridge — Makefile targets"
	@echo ""
	@echo "  build            Build both binaries"
	@echo "  test             Run all tests"
	@echo "  vet              Run go vet"
	@echo "  clean            Remove build artifacts"
	@echo "  run              Run mtc-bridge locally"
	@echo "  generate-key     Generate a new Ed25519 signing key"
	@echo "  generate-local-ca Generate a self-signed local CA key + cert for embedded proofs"
	@echo "  conformance      Run conformance test suite against a running server"
	@echo "  interop          Cross-validate against bwesterb/mtc reference implementation"
	@echo "  demo-tls         Run TLS assertion stapling demo (requires running bridge + CA)"
	@echo "  demo-embedded    Run embedded MTC proof demo (standalone, no server needed)"
	@echo "  demo-mtc         Run MTC-spec cert demo (id-alg-mtcProof, standalone)"
	@echo "  docker           Build Docker image"
	@echo "  docker-up        Start all services via docker compose"
	@echo "  docker-down      Stop all services"
	@echo ""

# Build
build:
	@mkdir -p bin
	go build -o bin/mtc-bridge ./cmd/mtc-bridge/
	go build -o bin/mtc-conformance ./cmd/mtc-conformance/
	go build -o bin/mtc-assertion ./cmd/mtc-assertion/
	go build -o bin/mtc-tls-server ./cmd/mtc-tls-server/
	go build -o bin/mtc-tls-verify ./cmd/mtc-tls-verify/
	go build -o bin/mtc-verify-cert ./cmd/mtc-verify-cert/
	go build -o bin/demo-embedded-cert ./cmd/demo-embedded-cert/
	go build -o bin/mtc-interop ./cmd/mtc-interop/
	@echo "Built: bin/mtc-bridge, bin/mtc-conformance, bin/mtc-assertion, bin/mtc-tls-server, bin/mtc-tls-verify, bin/mtc-verify-cert, bin/demo-embedded-cert, bin/mtc-interop"

# Test
test:
	go test ./... -v -count=1

# Vet
vet:
	go vet ./...

# Clean
clean:
	rm -rf bin/
	go clean -cache

# Run locally
run: build
	./bin/mtc-bridge -config config.yaml

# Generate signing key
generate-key: build
	@mkdir -p keys
	./bin/mtc-bridge -generate-key keys/cosigner.key

# Generate local CA key + cert for embedded proof mode
generate-local-ca: build
	./bin/mtc-bridge -generate-local-ca

# Conformance test
conformance: build
	./bin/mtc-conformance -url http://localhost:8080 -acme-url https://localhost:8443 -verbose

# Interop validation against bwesterb/mtc reference implementation
interop: build
	./bin/mtc-interop -verbose

# TLS assertion stapling demo
demo-tls: build
	./demo-tls.sh

# Embedded proof demo (standalone, no server needed)
demo-embedded: build
	@echo ""
	./bin/demo-embedded-cert -domain demo.example.com -output /tmp/mtc-demo-cert.pem
	@echo ""
	@echo "=== X.509 Certificate with Embedded MTC Proof ==="
	@echo ""
	openssl x509 -in /tmp/mtc-demo-cert.pem -text -noout
	@echo ""
	@echo "=== Verifying Embedded Proof ==="
	@echo ""
	./bin/mtc-verify-cert -cert /tmp/mtc-demo-cert.pem
	@rm -f /tmp/mtc-demo-cert.pem

# MTC-spec demo (standalone, no server needed)
demo-mtc: build
	@echo ""
	./bin/demo-embedded-cert -mtc-mode -domain demo.example.com -output /tmp/mtc-spec-cert.pem
	@echo ""
	@echo "=== Verifying MTC-Spec Certificate ==="
	@echo ""
	./bin/mtc-verify-cert -cert /tmp/mtc-spec-cert.pem
	@rm -f /tmp/mtc-spec-cert.pem /tmp/mtc-spec-cert.key

# Docker
docker:
	docker build -t mtc-bridge:latest .

docker-up:
	docker compose up -d

docker-down:
	docker compose down
