# ADR-005: Ed25519 Cosigner Keys

**Status**: Accepted

**Date**: 2026-02-27

### Context

MTC §5.4.2 specifies that cosigners sign subtrees using a digital signature algorithm. The spec lists Ed25519, Ed448, ECDSA, and ML-DSA. We need to choose a signature algorithm for the single local cosigner.

### Decision

Use Ed25519 (RFC 8032) for all signing operations.

### Consequences

- **Positive**: Smallest signatures (64 bytes) and public keys (32 bytes), reducing checkpoint/subtree sizes.
- **Positive**: Deterministic signatures — no nonce management needed.
- **Positive**: Go stdlib `crypto/ed25519` is well-tested and performant.
- **Positive**: Widely supported by transparency ecosystem tooling.
- **Negative**: Not post-quantum (but neither are the TLS certificates being logged).

### Alternatives Considered

- **ECDSA P-256**: Larger signatures, non-deterministic without RFC 6979.
- **ML-DSA-65**: Post-quantum, but very large signatures (~3.3KB) and Go stdlib support is experimental.
- **Ed448**: Larger (114-byte sigs), minimal security gain for this use case.
