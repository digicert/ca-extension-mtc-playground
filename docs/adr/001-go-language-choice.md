# ADR-001: Go Language Choice

**Status**: Accepted

**Date**: 2026-02-27

### Context

We need a language for the mtc-bridge service that will handle cryptographic operations (Merkle tree hashing, Ed25519 signing), database connectivity (MariaDB read, PostgreSQL write), and HTTP serving (tlog-tiles API + admin dashboard). The service must be easily containerized and have a single binary deployment model.

### Decision

Use Go (1.26+) as the implementation language.

### Consequences

- **Positive**: Single static binary, excellent stdlib (crypto, net/http, database/sql), strong concurrency model (goroutines for watcher + HTTP server), mature ecosystem for database drivers, easy Docker builds.
- **Positive**: The Go transparency ecosystem (Trillian, sunlight, etc.) provides reference implementations.
- **Negative**: No generics for trees (available since 1.18, but Merkle tree code is simpler without).
- **Negative**: Verbose error handling, but aligns with explicit error propagation style.

### Alternatives Considered

- **Rust**: Better performance for crypto, but slower development speed and team unfamiliarity.
- **TypeScript/Node**: Faster prototyping, but crypto and binary handling are less ergonomic.
- **Python**: Good for prototyping, bad for concurrent HTTP serving and crypto performance.
