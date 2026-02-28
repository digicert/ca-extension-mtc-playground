# ADR-002: Simplified MTC Scope

**Status**: Accepted

**Date**: 2026-02-27

### Context

The full MTC specification (draft-ietf-plants-merkle-tree-certs-01) includes many features beyond simple issuance logging: cosigner protocol with multiple external cosigners, TLS 1.3 Certificate message integration, signatureless certificate handshakes, ACME extensions, and browser relying-party logic. Implementing the full spec would require months of effort and TLS library modifications.

### Decision

Implement a simplified subset:
- ✅ Issuance log (append-only Merkle tree of certificate entries)
- ✅ HTTP tile API (C2SP tlog-tiles)
- ✅ Revocation-by-index tracking
- ✅ Ed25519 signing (single local cosigner)
- ✅ Checkpoints + landmarks
- ❌ External cosigner protocol
- ❌ TLS 1.3 integration / signatureless certificates
- ❌ ACME MTC extensions
- ❌ Multi-cosigner coordination
- ❌ Browser relying-party verification

### Consequences

- **Positive**: Deliverable in weeks, not months. Focuses on the transparency/auditability value.
- **Positive**: Conformance test client validates the tile serving is spec-compliant, enabling future expansion.
- **Negative**: Cannot demonstrate the full MTC TLS flow end-to-end.
- **Negative**: External verifiers must implement their own client logic.

### Alternatives Considered

- **Full spec**: Too ambitious for initial deployment.
- **CT v2 only**: Doesn't explore MTC-specific concepts (subtrees, entry bundles, landmarks).
