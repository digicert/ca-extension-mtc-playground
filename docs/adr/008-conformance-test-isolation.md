# ADR-008: Conformance Test Client Isolation

**Status**: Accepted

**Date**: 2026-02-27

### Context

We need a test client to verify that mtc-bridge serves content in the standard-expected format. This client should validate compliance with the tlog-tiles spec and MTC draft, acting as an independent auditor.

### Decision

Build `cmd/mtc-conformance` as a standalone binary that shares ZERO internal code with `cmd/mtc-bridge`. It imports only Go stdlib and its own local packages (under `cmd/mtc-conformance/internal/`). This ensures it validates the **wire protocol**, not the implementation.

### Consequences

- **Positive**: True black-box testing — catches serialization bugs that unit tests might miss.
- **Positive**: Reusable by third parties who want to validate any tlog-tiles server.
- **Positive**: No risk of shared-bug masking (where both producer and consumer share a buggy encoder).
- **Negative**: Duplicates some code (checkpoint parsing, tile fetching, hash computation).
- **Negative**: Must be kept in sync with spec changes independently.

### Alternatives Considered

- **Shared internal library**: Faster to build, but defeats the purpose of independent validation.
- **External test suite (e.g., Python)**: Language boundary adds complexity; Go is consistent with project.
- **curl + jq scripts**: Insufficient for cryptographic verification.
