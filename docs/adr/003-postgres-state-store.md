# ADR-003: PostgreSQL State Store

**Status**: Accepted

**Date**: 2026-02-27

### Context

mtc-bridge needs a persistent state store for: log entries, tree node hashes, checkpoints, subtree signatures, landmark references, revocation index mappings, watcher cursor positions, and admin events. The store must support concurrent reads (HTTP tile serving) while writes are serialized (watcher appends).

### Decision

Use PostgreSQL 16 as the state store, deployed as a Docker container alongside mtc-bridge.

### Consequences

- **Positive**: Company-standard database, strong ACID guarantees, excellent Go driver support (pgx).
- **Positive**: JSONB columns for flexible event data, advisory locks for watcher coordination.
- **Positive**: Well-understood backup/restore and monitoring story.
- **Negative**: Heavier than SQLite for a single-writer workload.
- **Negative**: Requires a separate container and network configuration.

### Alternatives Considered

- **SQLite**: Simpler deployment (embedded), but company prefers PostgreSQL for production services.
- **bbolt/BadgerDB**: Embedded KV stores, but lack SQL query flexibility for admin dashboard.
