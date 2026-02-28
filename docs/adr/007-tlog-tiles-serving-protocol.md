# ADR-007: tlog-tiles Serving Protocol

**Status**: Accepted

**Date**: 2026-02-27

### Context

We need an HTTP API to serve the Merkle tree to clients. Options include custom API, CT v2 API (RFC 9162 §4), or C2SP tlog-tiles.

### Decision

Use the C2SP tlog-tiles HTTP API as the serving protocol.

### Consequences

- **Positive**: Standard protocol with existing client libraries (Go sumdb, sigsum, etc.).
- **Positive**: Tile-based serving is cache-friendly — full tiles are immutable and can be served from CDN.
- **Positive**: Simple URL scheme: `/checkpoint`, `/tile/<L>/<N>`, `/tile/entries/<N>`.
- **Positive**: Aligns with Go module proxy transparency (sumdb) ecosystem.
- **Negative**: Not the CT v2 API — CT monitors/auditors need adaptation.
- **Negative**: Entry bundle format (length-prefixed entries in tiles) is specific to tlog-tiles.

### Alternatives Considered

- **CT v2 API**: Standard for Certificate Transparency, but designed for different tree structure.
- **Custom REST API**: Flexible, but no ecosystem compatibility.
- **gRPC**: Good for service-to-service, bad for browser/curl access.
