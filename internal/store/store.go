// Package store implements the PostgreSQL state store for mtc-bridge.
//
// It manages log entries, tree node hashes, checkpoints, revocation indices,
// watcher cursors, and admin events. All writes are serialized through the
// watcher; reads from HTTP handlers are concurrent and lock-free.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/config"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Store is the PostgreSQL state store for mtc-bridge.
type Store struct {
	db     *sql.DB
	logger *slog.Logger
}

// New creates a new Store connected to PostgreSQL.
func New(ctx context.Context, cfg config.PostgresConfig, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("pgx", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("store.New: open: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store.New: ping: %w", err)
	}

	return &Store{db: db, logger: logger}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Migrate runs database migrations to create/update the schema.
func (s *Store) Migrate(ctx context.Context) error {
	for i, m := range migrations {
		if _, err := s.db.ExecContext(ctx, m); err != nil {
			return fmt.Errorf("store.Migrate: migration %d: %w", i, err)
		}
	}
	s.logger.Info("database migrations complete", "count", len(migrations))
	return nil
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS log_entries (
		idx         BIGINT PRIMARY KEY,
		entry_type  SMALLINT NOT NULL,
		entry_data  BYTEA NOT NULL,
		cert_sha256 BYTEA,
		serial_hex  TEXT,
		ca_cert_id  TEXT,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS tree_nodes (
		level   INTEGER NOT NULL,
		idx     BIGINT NOT NULL,
		hash    BYTEA NOT NULL,
		PRIMARY KEY (level, idx)
	)`,
	`CREATE TABLE IF NOT EXISTS checkpoints (
		id          BIGSERIAL PRIMARY KEY,
		tree_size   BIGINT NOT NULL,
		root_hash   BYTEA NOT NULL,
		timestamp   TIMESTAMPTZ NOT NULL,
		signature   BYTEA NOT NULL,
		body        TEXT NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS revoked_indices (
		entry_idx   BIGINT PRIMARY KEY REFERENCES log_entries(idx),
		serial_hex  TEXT NOT NULL,
		revoked_at  TIMESTAMPTZ NOT NULL,
		reason      SMALLINT NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS watcher_cursors (
		id              TEXT PRIMARY KEY DEFAULT 'default',
		last_created_at TIMESTAMPTZ NOT NULL,
		last_cert_id    TEXT NOT NULL,
		updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS events (
		id          BIGSERIAL PRIMARY KEY,
		event_type  TEXT NOT NULL,
		payload     JSONB NOT NULL DEFAULT '{}',
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)`,
	`CREATE INDEX IF NOT EXISTS idx_log_entries_serial ON log_entries(serial_hex)`,
	`CREATE INDEX IF NOT EXISTS idx_checkpoints_tree_size ON checkpoints(tree_size)`,
}

// --- Log Entries ---

// LogEntry represents a single entry in the issuance log.
type LogEntry struct {
	Index      int64     `json:"index"`
	EntryType  int16     `json:"entry_type"`
	EntryData  []byte    `json:"entry_data"`
	CertSHA256 []byte    `json:"cert_sha256,omitempty"`
	SerialHex  string    `json:"serial_hex,omitempty"`
	CACertID   string    `json:"ca_cert_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// AppendEntry inserts a new log entry. The caller must ensure idx is correct.
func (s *Store) AppendEntry(ctx context.Context, entry *LogEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO log_entries (idx, entry_type, entry_data, cert_sha256, serial_hex, ca_cert_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		entry.Index, entry.EntryType, entry.EntryData, entry.CertSHA256, entry.SerialHex, entry.CACertID,
	)
	if err != nil {
		return fmt.Errorf("store.AppendEntry: %w", err)
	}
	return nil
}

// AppendEntries inserts multiple log entries in a single transaction.
func (s *Store) AppendEntries(ctx context.Context, entries []*LogEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.AppendEntries: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO log_entries (idx, entry_type, entry_data, cert_sha256, serial_hex, ca_cert_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
	)
	if err != nil {
		return fmt.Errorf("store.AppendEntries: prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.Index, e.EntryType, e.EntryData, e.CertSHA256, e.SerialHex, e.CACertID); err != nil {
			return fmt.Errorf("store.AppendEntries: insert idx=%d: %w", e.Index, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.AppendEntries: commit: %w", err)
	}
	return nil
}

// GetEntry retrieves a single log entry by index.
func (s *Store) GetEntry(ctx context.Context, idx int64) (*LogEntry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT idx, entry_type, entry_data, cert_sha256, serial_hex, ca_cert_id, created_at
		 FROM log_entries WHERE idx = $1`, idx)

	var e LogEntry
	var certSHA256 []byte
	var serialHex, caCertID sql.NullString
	err := row.Scan(&e.Index, &e.EntryType, &e.EntryData, &certSHA256, &serialHex, &caCertID, &e.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetEntry: %w", err)
	}
	e.CertSHA256 = certSHA256
	e.SerialHex = serialHex.String
	e.CACertID = caCertID.String
	return &e, nil
}

// GetEntries retrieves log entries for indices [start, end).
func (s *Store) GetEntries(ctx context.Context, start, end int64) ([]*LogEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT idx, entry_type, entry_data, cert_sha256, serial_hex, ca_cert_id, created_at
		 FROM log_entries WHERE idx >= $1 AND idx < $2 ORDER BY idx`, start, end)
	if err != nil {
		return nil, fmt.Errorf("store.GetEntries: %w", err)
	}
	defer rows.Close()

	var entries []*LogEntry
	for rows.Next() {
		var e LogEntry
		var certSHA256 []byte
		var serialHex, caCertID sql.NullString
		if err := rows.Scan(&e.Index, &e.EntryType, &e.EntryData, &certSHA256, &serialHex, &caCertID, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("store.GetEntries: scan: %w", err)
		}
		e.CertSHA256 = certSHA256
		e.SerialHex = serialHex.String
		e.CACertID = caCertID.String
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// TreeSize returns the current number of entries in the log.
func (s *Store) TreeSize(ctx context.Context) (int64, error) {
	var size int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(idx) + 1, 0) FROM log_entries`).Scan(&size)
	if err != nil {
		return 0, fmt.Errorf("store.TreeSize: %w", err)
	}
	return size, nil
}

// --- Tree Nodes ---

// TreeNode is a precomputed tree hash.
type TreeNode struct {
	Level int
	Index int64
	Hash  merkle.Hash
}

// SetTreeNode stores a precomputed tree node hash.
func (s *Store) SetTreeNode(ctx context.Context, level int, index int64, hash merkle.Hash) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tree_nodes (level, idx, hash) VALUES ($1, $2, $3)
		 ON CONFLICT (level, idx) DO UPDATE SET hash = EXCLUDED.hash`,
		level, index, hash[:],
	)
	if err != nil {
		return fmt.Errorf("store.SetTreeNode: %w", err)
	}
	return nil
}

// SetTreeNodes stores multiple tree node hashes in a transaction.
func (s *Store) SetTreeNodes(ctx context.Context, nodes []TreeNode) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.SetTreeNodes: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO tree_nodes (level, idx, hash) VALUES ($1, $2, $3)
		 ON CONFLICT (level, idx) DO UPDATE SET hash = EXCLUDED.hash`)
	if err != nil {
		return fmt.Errorf("store.SetTreeNodes: prepare: %w", err)
	}
	defer stmt.Close()

	for _, n := range nodes {
		if _, err := stmt.ExecContext(ctx, n.Level, n.Index, n.Hash[:]); err != nil {
			return fmt.Errorf("store.SetTreeNodes: insert level=%d index=%d: %w", n.Level, n.Index, err)
		}
	}
	return tx.Commit()
}

// GetTreeNode retrieves a tree node hash.
func (s *Store) GetTreeNode(ctx context.Context, level int, index int64) (merkle.Hash, error) {
	var hashBytes []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT hash FROM tree_nodes WHERE level = $1 AND idx = $2`, level, index).Scan(&hashBytes)
	if err != nil {
		return merkle.Hash{}, fmt.Errorf("store.GetTreeNode: %w", err)
	}
	var h merkle.Hash
	copy(h[:], hashBytes)
	return h, nil
}

// GetTileHashes retrieves all node hashes for a tile at the given level,
// starting at nodeStart, up to 256 nodes.
func (s *Store) GetTileHashes(ctx context.Context, level int, nodeStart int64, count int) ([]merkle.Hash, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT idx, hash FROM tree_nodes
		 WHERE level = $1 AND idx >= $2 AND idx < $3
		 ORDER BY idx`,
		level, nodeStart, nodeStart+int64(count))
	if err != nil {
		return nil, fmt.Errorf("store.GetTileHashes: %w", err)
	}
	defer rows.Close()

	hashes := make([]merkle.Hash, count)
	found := 0
	for rows.Next() {
		var idx int64
		var hashBytes []byte
		if err := rows.Scan(&idx, &hashBytes); err != nil {
			return nil, fmt.Errorf("store.GetTileHashes: scan: %w", err)
		}
		offset := idx - nodeStart
		if offset >= 0 && offset < int64(count) {
			copy(hashes[offset][:], hashBytes)
			found++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.GetTileHashes: rows: %w", err)
	}
	return hashes[:found], nil
}

// --- Checkpoints ---

// Checkpoint is a signed checkpoint record.
type Checkpoint struct {
	ID        int64     `json:"id"`
	TreeSize  int64     `json:"tree_size"`
	RootHash  []byte    `json:"root_hash"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// SaveCheckpoint inserts a new checkpoint.
func (s *Store) SaveCheckpoint(ctx context.Context, cp *Checkpoint) error {
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO checkpoints (tree_size, root_hash, timestamp, signature, body)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, created_at`,
		cp.TreeSize, cp.RootHash, cp.Timestamp, cp.Signature, cp.Body,
	).Scan(&cp.ID, &cp.CreatedAt)
	if err != nil {
		return fmt.Errorf("store.SaveCheckpoint: %w", err)
	}
	return nil
}

// LatestCheckpoint returns the most recent checkpoint.
func (s *Store) LatestCheckpoint(ctx context.Context) (*Checkpoint, error) {
	var cp Checkpoint
	err := s.db.QueryRowContext(ctx,
		`SELECT id, tree_size, root_hash, timestamp, signature, body, created_at
		 FROM checkpoints ORDER BY id DESC LIMIT 1`).
		Scan(&cp.ID, &cp.TreeSize, &cp.RootHash, &cp.Timestamp, &cp.Signature, &cp.Body, &cp.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.LatestCheckpoint: %w", err)
	}
	return &cp, nil
}

// GetCheckpoint retrieves a checkpoint by tree size.
func (s *Store) GetCheckpoint(ctx context.Context, treeSize int64) (*Checkpoint, error) {
	var cp Checkpoint
	err := s.db.QueryRowContext(ctx,
		`SELECT id, tree_size, root_hash, timestamp, signature, body, created_at
		 FROM checkpoints WHERE tree_size = $1 ORDER BY id DESC LIMIT 1`, treeSize).
		Scan(&cp.ID, &cp.TreeSize, &cp.RootHash, &cp.Timestamp, &cp.Signature, &cp.Body, &cp.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetCheckpoint: %w", err)
	}
	return &cp, nil
}

// RecentCheckpoints returns the most recent n checkpoints.
func (s *Store) RecentCheckpoints(ctx context.Context, limit int) ([]*Checkpoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tree_size, root_hash, timestamp, signature, body, created_at
		 FROM checkpoints ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.RecentCheckpoints: %w", err)
	}
	defer rows.Close()

	var cps []*Checkpoint
	for rows.Next() {
		var cp Checkpoint
		if err := rows.Scan(&cp.ID, &cp.TreeSize, &cp.RootHash, &cp.Timestamp, &cp.Signature, &cp.Body, &cp.CreatedAt); err != nil {
			return nil, fmt.Errorf("store.RecentCheckpoints: scan: %w", err)
		}
		cps = append(cps, &cp)
	}
	return cps, rows.Err()
}

// --- Revocation ---

// RevokedIndex is a revocation record.
type RevokedIndex struct {
	EntryIdx  int64     `json:"entry_idx"`
	SerialHex string    `json:"serial_hex"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    int16     `json:"reason"`
}

// AddRevocation records a revocation.
func (s *Store) AddRevocation(ctx context.Context, rev *RevokedIndex) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO revoked_indices (entry_idx, serial_hex, revoked_at, reason)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (entry_idx) DO NOTHING`,
		rev.EntryIdx, rev.SerialHex, rev.RevokedAt, rev.Reason,
	)
	if err != nil {
		return fmt.Errorf("store.AddRevocation: %w", err)
	}
	return nil
}

// GetRevokedIndices returns all revoked entry indices.
func (s *Store) GetRevokedIndices(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT entry_idx FROM revoked_indices ORDER BY entry_idx`)
	if err != nil {
		return nil, fmt.Errorf("store.GetRevokedIndices: %w", err)
	}
	defer rows.Close()

	var indices []int64
	for rows.Next() {
		var idx int64
		if err := rows.Scan(&idx); err != nil {
			return nil, fmt.Errorf("store.GetRevokedIndices: scan: %w", err)
		}
		indices = append(indices, idx)
	}
	return indices, rows.Err()
}

// RevocationCount returns the number of revoked entries.
func (s *Store) RevocationCount(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM revoked_indices`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store.RevocationCount: %w", err)
	}
	return count, nil
}

// FindEntryBySerial returns the log entry index for a given certificate serial number.
func (s *Store) FindEntryBySerial(ctx context.Context, serialHex string) (int64, error) {
	var idx int64
	err := s.db.QueryRowContext(ctx,
		`SELECT idx FROM log_entries WHERE serial_hex = $1`, serialHex).Scan(&idx)
	if err != nil {
		return 0, fmt.Errorf("store.FindEntryBySerial: %w", err)
	}
	return idx, nil
}

// --- Watcher Cursor ---

// WatcherCursor represents the last-seen position in the CA database.
type WatcherCursor struct {
	ID            string    `json:"id"`
	LastCreatedAt time.Time `json:"last_created_at"`
	LastCertID    string    `json:"last_cert_id"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// GetWatcherCursor retrieves the current watcher cursor.
func (s *Store) GetWatcherCursor(ctx context.Context) (*WatcherCursor, error) {
	var c WatcherCursor
	err := s.db.QueryRowContext(ctx,
		`SELECT id, last_created_at, last_cert_id, updated_at
		 FROM watcher_cursors WHERE id = 'default'`).
		Scan(&c.ID, &c.LastCreatedAt, &c.LastCertID, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetWatcherCursor: %w", err)
	}
	return &c, nil
}

// UpdateWatcherCursor upserts the watcher cursor position.
func (s *Store) UpdateWatcherCursor(ctx context.Context, lastCreatedAt time.Time, lastCertID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO watcher_cursors (id, last_created_at, last_cert_id, updated_at)
		 VALUES ('default', $1, $2, NOW())
		 ON CONFLICT (id) DO UPDATE SET
		   last_created_at = EXCLUDED.last_created_at,
		   last_cert_id = EXCLUDED.last_cert_id,
		   updated_at = NOW()`,
		lastCreatedAt, lastCertID,
	)
	if err != nil {
		return fmt.Errorf("store.UpdateWatcherCursor: %w", err)
	}
	return nil
}

// --- Events ---

// Event is an admin event.
type Event struct {
	ID        int64           `json:"id"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}

// EmitEvent inserts an admin event.
func (s *Store) EmitEvent(ctx context.Context, eventType string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("store.EmitEvent: marshal: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO events (event_type, payload) VALUES ($1, $2)`,
		eventType, data,
	)
	if err != nil {
		return fmt.Errorf("store.EmitEvent: %w", err)
	}
	return nil
}

// RecentEvents returns the most recent n events.
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]*Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, event_type, payload, created_at
		 FROM events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.RecentEvents: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.EventType, &e.Payload, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("store.RecentEvents: scan: %w", err)
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// EventsSince returns events with ID > sinceID.
func (s *Store) EventsSince(ctx context.Context, sinceID int64) ([]*Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, event_type, payload, created_at
		 FROM events WHERE id > $1 ORDER BY id ASC`, sinceID)
	if err != nil {
		return nil, fmt.Errorf("store.EventsSince: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.EventType, &e.Payload, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("store.EventsSince: scan: %w", err)
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// --- Stats ---

// Stats holds aggregate statistics for the admin dashboard.
type Stats struct {
	TreeSize         int64     `json:"tree_size"`
	RevocationCount  int64     `json:"revocation_count"`
	CheckpointCount  int64     `json:"checkpoint_count"`
	LatestCheckpoint time.Time `json:"latest_checkpoint"`
	EventCount       int64     `json:"event_count"`
}

// GetStats returns aggregate statistics.
func (s *Store) GetStats(ctx context.Context) (*Stats, error) {
	var stats Stats
	err := s.db.QueryRowContext(ctx,
		`SELECT
			COALESCE((SELECT MAX(idx) + 1 FROM log_entries), 0),
			COALESCE((SELECT COUNT(*) FROM revoked_indices), 0),
			COALESCE((SELECT COUNT(*) FROM checkpoints), 0),
			COALESCE((SELECT MAX(created_at) FROM checkpoints), '1970-01-01'),
			COALESCE((SELECT COUNT(*) FROM events), 0)
		`).Scan(&stats.TreeSize, &stats.RevocationCount, &stats.CheckpointCount,
		&stats.LatestCheckpoint, &stats.EventCount)
	if err != nil {
		return nil, fmt.Errorf("store.GetStats: %w", err)
	}
	return &stats, nil
}

// DB returns the underlying *sql.DB for advanced use cases (e.g., transactions).
func (s *Store) DB() *sql.DB {
	return s.db
}
