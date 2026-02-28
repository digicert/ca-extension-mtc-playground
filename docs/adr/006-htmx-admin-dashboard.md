# ADR-006: HTMX Admin Dashboard

**Status**: Accepted

**Date**: 2026-02-27

### Context

Operators need a web UI to monitor mtc-bridge health: tree size, latest checkpoint, recent events, watcher status, error rates. This should be part of the single Go binary, not a separate SPA build step.

### Decision

Use Go `html/template` with HTMX for interactivity and Tailwind CSS (CDN) for styling. Server-Sent Events (SSE) for real-time event streaming.

### Consequences

- **Positive**: Zero JavaScript build toolchain. Templates are embedded in the Go binary via `embed`.
- **Positive**: HTMX provides SPA-like UX (partial page updates, SSE) with HTML-over-the-wire.
- **Positive**: Single binary contains all UI assets — nothing to serve from disk.
- **Negative**: Limited client-side interactivity compared to React/Vue.
- **Negative**: Tailwind CDN is larger than a purged build (acceptable for internal tooling).

### Alternatives Considered

- **React SPA**: Requires Node.js build toolchain, separate deployment.
- **Grafana dashboard**: External dependency, limited custom UI.
- **CLI-only**: No persistent monitoring view.
