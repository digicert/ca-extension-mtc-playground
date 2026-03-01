.PHONY: build test vet lint clean run generate-key conformance demo-tls docker docker-up docker-down help

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
	@echo "  conformance      Run conformance test suite against a running server"
	@echo "  demo-tls         Run TLS assertion stapling demo (requires running bridge + CA)"
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
	@echo "Built: bin/mtc-bridge, bin/mtc-conformance, bin/mtc-assertion, bin/mtc-tls-server, bin/mtc-tls-verify"

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

# Conformance test
conformance: build
	./bin/mtc-conformance -url http://localhost:8080 -acme-url http://localhost:8443 -verbose

# TLS assertion stapling demo
demo-tls: build
	./demo-tls.sh

# Docker
docker:
	docker build -t mtc-bridge:latest .

docker-up:
	docker compose up -d

docker-down:
	docker compose down
