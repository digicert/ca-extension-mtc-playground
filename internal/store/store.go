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

	"strings"

	"github.com/briantrzupek/ca-extension-merkle/internal/certutil"
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
	`CREATE INDEX IF NOT EXISTS idx_log_entries_ca_cert_id ON log_entries(ca_cert_id)`,

	// Phase 2: assertion bundles table for pre-computed assertion bundles.
	`CREATE TABLE IF NOT EXISTS assertion_bundles (
		entry_idx      BIGINT PRIMARY KEY REFERENCES log_entries(idx),
		serial_hex     TEXT NOT NULL,
		checkpoint_id  BIGINT NOT NULL REFERENCES checkpoints(id),
		tree_size      BIGINT NOT NULL,
		bundle_json    JSONB NOT NULL,
		bundle_pem     TEXT NOT NULL,
		stale          BOOLEAN NOT NULL DEFAULT FALSE,
		created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_assertion_bundles_serial ON assertion_bundles(serial_hex)`,
	`CREATE INDEX IF NOT EXISTS idx_assertion_bundles_stale ON assertion_bundles(stale) WHERE stale = TRUE`,
	`CREATE INDEX IF NOT EXISTS idx_assertion_bundles_checkpoint ON assertion_bundles(checkpoint_id)`,
	`CREATE INDEX IF NOT EXISTS idx_assertion_bundles_created ON assertion_bundles(created_at DESC)`,

	// Phase 3: ACME server tables.
	`CREATE TABLE IF NOT EXISTS acme_accounts (
		id          TEXT PRIMARY KEY,
		status      TEXT NOT NULL DEFAULT 'valid',
		key_thumbprint TEXT NOT NULL UNIQUE,
		jwk         JSONB NOT NULL,
		contact     JSONB NOT NULL DEFAULT '[]',
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS acme_orders (
		id              TEXT PRIMARY KEY,
		account_id      TEXT NOT NULL REFERENCES acme_accounts(id),
		status          TEXT NOT NULL DEFAULT 'pending',
		identifiers     JSONB NOT NULL,
		not_before      TIMESTAMPTZ,
		not_after       TIMESTAMPTZ,
		expires         TIMESTAMPTZ NOT NULL,
		csr             TEXT,
		certificate_url TEXT,
		cert_serial     TEXT,
		assertion_url   TEXT,
		error_type      TEXT,
		error_detail    TEXT,
		created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id)`,
	`CREATE INDEX IF NOT EXISTS idx_acme_orders_status ON acme_orders(status) WHERE status IN ('pending', 'ready', 'processing')`,
	`CREATE INDEX IF NOT EXISTS idx_acme_orders_cert_serial ON acme_orders(cert_serial) WHERE cert_serial IS NOT NULL`,
	`CREATE TABLE IF NOT EXISTS acme_authorizations (
		id          TEXT PRIMARY KEY,
		order_id    TEXT NOT NULL REFERENCES acme_orders(id),
		identifier  JSONB NOT NULL,
		status      TEXT NOT NULL DEFAULT 'pending',
		expires     TIMESTAMPTZ NOT NULL,
		wildcard    BOOLEAN NOT NULL DEFAULT FALSE,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id)`,
	`CREATE TABLE IF NOT EXISTS acme_challenges (
		id          TEXT PRIMARY KEY,
		authz_id    TEXT NOT NULL REFERENCES acme_authorizations(id),
		type        TEXT NOT NULL,
		status      TEXT NOT NULL DEFAULT 'pending',
		token       TEXT NOT NULL,
		validated   TIMESTAMPTZ,
		error_type  TEXT,
		error_detail TEXT,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_acme_challenges_authz ON acme_challenges(authz_id)`,
	`CREATE INDEX IF NOT EXISTS idx_acme_challenges_token ON acme_challenges(token)`,

	// Phase 4: visualization cert_metadata cache table.
	`CREATE TABLE IF NOT EXISTS cert_metadata (
		entry_idx     BIGINT PRIMARY KEY REFERENCES log_entries(idx),
		ca_cert_id    TEXT NOT NULL,
		ca_name       TEXT NOT NULL DEFAULT '',
		key_algorithm TEXT NOT NULL,
		sig_algorithm TEXT NOT NULL,
		common_name   TEXT NOT NULL DEFAULT '',
		is_pq         BOOLEAN NOT NULL DEFAULT FALSE,
		batch_window  TIMESTAMPTZ NOT NULL,
		created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_cert_metadata_ca ON cert_metadata(ca_cert_id)`,
	`CREATE INDEX IF NOT EXISTS idx_cert_metadata_batch ON cert_metadata(batch_window)`,
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

// SearchResult extends LogEntry with revocation status for search results.
type SearchResult struct {
	LogEntry
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// SearchEntries searches log entries by serial number prefix, CA cert ID, or index.
// The query is matched against serial_hex (ILIKE) and, if numeric, against idx.
// Results are ordered by index descending and limited to the given count.
func (s *Store) SearchEntries(ctx context.Context, query string, limit int) ([]*SearchResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT le.idx, le.entry_type, le.entry_data, le.cert_sha256, le.serial_hex,
		        le.ca_cert_id, le.created_at, ri.revoked_at
		 FROM log_entries le
		 LEFT JOIN revoked_indices ri ON le.idx = ri.entry_idx
		 WHERE le.serial_hex ILIKE $1 OR le.ca_cert_id = $2
		 ORDER BY le.idx DESC
		 LIMIT $3`,
		"%"+query+"%", query, limit)
	if err != nil {
		return nil, fmt.Errorf("store.SearchEntries: %w", err)
	}
	defer rows.Close()

	var results []*SearchResult
	for rows.Next() {
		var r SearchResult
		var certSHA256 []byte
		var serialHex, caCertID sql.NullString
		var revokedAt sql.NullTime
		if err := rows.Scan(&r.Index, &r.EntryType, &r.EntryData, &certSHA256,
			&serialHex, &caCertID, &r.CreatedAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("store.SearchEntries: scan: %w", err)
		}
		r.CertSHA256 = certSHA256
		r.SerialHex = serialHex.String
		r.CACertID = caCertID.String
		if revokedAt.Valid {
			r.Revoked = true
			r.RevokedAt = &revokedAt.Time
		}
		results = append(results, &r)
	}
	return results, rows.Err()
}

// GetEntryDetail retrieves a log entry with revocation status by index.
func (s *Store) GetEntryDetail(ctx context.Context, idx int64) (*SearchResult, error) {
	var r SearchResult
	var certSHA256 []byte
	var serialHex, caCertID sql.NullString
	var revokedAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT le.idx, le.entry_type, le.entry_data, le.cert_sha256, le.serial_hex,
		        le.ca_cert_id, le.created_at, ri.revoked_at
		 FROM log_entries le
		 LEFT JOIN revoked_indices ri ON le.idx = ri.entry_idx
		 WHERE le.idx = $1`, idx).
		Scan(&r.Index, &r.EntryType, &r.EntryData, &certSHA256,
			&serialHex, &caCertID, &r.CreatedAt, &revokedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetEntryDetail: %w", err)
	}
	r.CertSHA256 = certSHA256
	r.SerialHex = serialHex.String
	r.CACertID = caCertID.String
	if revokedAt.Valid {
		r.Revoked = true
		r.RevokedAt = &revokedAt.Time
	}
	return &r, nil
}

// RecentEntries returns the most recent n log entries with revocation status.
func (s *Store) RecentEntries(ctx context.Context, limit int) ([]*SearchResult, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT le.idx, le.entry_type, le.entry_data, le.cert_sha256, le.serial_hex,
		        le.ca_cert_id, le.created_at, ri.revoked_at
		 FROM log_entries le
		 LEFT JOIN revoked_indices ri ON le.idx = ri.entry_idx
		 ORDER BY le.idx DESC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.RecentEntries: %w", err)
	}
	defer rows.Close()

	var results []*SearchResult
	for rows.Next() {
		var r SearchResult
		var certSHA256 []byte
		var serialHex, caCertID sql.NullString
		var revokedAt sql.NullTime
		if err := rows.Scan(&r.Index, &r.EntryType, &r.EntryData, &certSHA256,
			&serialHex, &caCertID, &r.CreatedAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("store.RecentEntries: scan: %w", err)
		}
		r.CertSHA256 = certSHA256
		r.SerialHex = serialHex.String
		r.CACertID = caCertID.String
		if revokedAt.Valid {
			r.Revoked = true
			r.RevokedAt = &revokedAt.Time
		}
		results = append(results, &r)
	}
	return results, rows.Err()
}

// RevokedEntries returns revoked log entries, optionally filtered by a search query.
func (s *Store) RevokedEntries(ctx context.Context, query string, limit int) ([]*SearchResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	var rows *sql.Rows
	var err error

	if query == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT le.idx, le.entry_type, le.entry_data, le.cert_sha256, le.serial_hex,
			        le.ca_cert_id, le.created_at, ri.revoked_at
			 FROM log_entries le
			 INNER JOIN revoked_indices ri ON le.idx = ri.entry_idx
			 ORDER BY ri.revoked_at DESC
			 LIMIT $1`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT le.idx, le.entry_type, le.entry_data, le.cert_sha256, le.serial_hex,
			        le.ca_cert_id, le.created_at, ri.revoked_at
			 FROM log_entries le
			 INNER JOIN revoked_indices ri ON le.idx = ri.entry_idx
			 WHERE le.serial_hex ILIKE $1 OR le.ca_cert_id = $2
			 ORDER BY ri.revoked_at DESC
			 LIMIT $3`,
			"%"+query+"%", query, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("store.RevokedEntries: %w", err)
	}
	defer rows.Close()

	var results []*SearchResult
	for rows.Next() {
		var r SearchResult
		var certSHA256 []byte
		var serialHex, caCertID sql.NullString
		var revokedAt sql.NullTime
		if err := rows.Scan(&r.Index, &r.EntryType, &r.EntryData, &certSHA256,
			&serialHex, &caCertID, &r.CreatedAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("store.RevokedEntries: scan: %w", err)
		}
		r.CertSHA256 = certSHA256
		r.SerialHex = serialHex.String
		r.CACertID = caCertID.String
		if revokedAt.Valid {
			r.Revoked = true
			r.RevokedAt = &revokedAt.Time
		}
		results = append(results, &r)
	}
	return results, rows.Err()
}

// --- Assertion Bundles ---

// AssertionBundle is a pre-computed assertion bundle stored in PostgreSQL.
type AssertionBundle struct {
	EntryIdx     int64           `json:"entry_idx"`
	SerialHex    string          `json:"serial_hex"`
	CheckpointID int64           `json:"checkpoint_id"`
	TreeSize     int64           `json:"tree_size"`
	BundleJSON   json.RawMessage `json:"bundle_json"`
	BundlePEM    string          `json:"bundle_pem"`
	Stale        bool            `json:"stale"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// UpsertAssertionBundle inserts or updates a pre-computed assertion bundle.
func (s *Store) UpsertAssertionBundle(ctx context.Context, ab *AssertionBundle) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO assertion_bundles (entry_idx, serial_hex, checkpoint_id, tree_size, bundle_json, bundle_pem, stale)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (entry_idx) DO UPDATE SET
		   checkpoint_id = EXCLUDED.checkpoint_id,
		   tree_size = EXCLUDED.tree_size,
		   bundle_json = EXCLUDED.bundle_json,
		   bundle_pem = EXCLUDED.bundle_pem,
		   stale = EXCLUDED.stale,
		   updated_at = NOW()`,
		ab.EntryIdx, ab.SerialHex, ab.CheckpointID, ab.TreeSize, ab.BundleJSON, ab.BundlePEM, ab.Stale,
	)
	if err != nil {
		return fmt.Errorf("store.UpsertAssertionBundle: %w", err)
	}
	return nil
}

// UpsertAssertionBundles inserts or updates multiple assertion bundles in a transaction.
func (s *Store) UpsertAssertionBundles(ctx context.Context, bundles []*AssertionBundle) error {
	if len(bundles) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertAssertionBundles: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO assertion_bundles (entry_idx, serial_hex, checkpoint_id, tree_size, bundle_json, bundle_pem, stale)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (entry_idx) DO UPDATE SET
		   checkpoint_id = EXCLUDED.checkpoint_id,
		   tree_size = EXCLUDED.tree_size,
		   bundle_json = EXCLUDED.bundle_json,
		   bundle_pem = EXCLUDED.bundle_pem,
		   stale = EXCLUDED.stale,
		   updated_at = NOW()`)
	if err != nil {
		return fmt.Errorf("store.UpsertAssertionBundles: prepare: %w", err)
	}
	defer stmt.Close()

	for _, ab := range bundles {
		if _, err := stmt.ExecContext(ctx, ab.EntryIdx, ab.SerialHex, ab.CheckpointID, ab.TreeSize, ab.BundleJSON, ab.BundlePEM, ab.Stale); err != nil {
			return fmt.Errorf("store.UpsertAssertionBundles: idx=%d: %w", ab.EntryIdx, err)
		}
	}
	return tx.Commit()
}

// GetAssertionBundle retrieves a pre-computed assertion bundle by entry index.
func (s *Store) GetAssertionBundle(ctx context.Context, entryIdx int64) (*AssertionBundle, error) {
	var ab AssertionBundle
	err := s.db.QueryRowContext(ctx,
		`SELECT entry_idx, serial_hex, checkpoint_id, tree_size, bundle_json, bundle_pem, stale, created_at, updated_at
		 FROM assertion_bundles WHERE entry_idx = $1`, entryIdx).
		Scan(&ab.EntryIdx, &ab.SerialHex, &ab.CheckpointID, &ab.TreeSize,
			&ab.BundleJSON, &ab.BundlePEM, &ab.Stale, &ab.CreatedAt, &ab.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetAssertionBundle: %w", err)
	}
	return &ab, nil
}

// GetAssertionBundleBySerial retrieves a pre-computed assertion bundle by serial number.
func (s *Store) GetAssertionBundleBySerial(ctx context.Context, serialHex string) (*AssertionBundle, error) {
	var ab AssertionBundle
	err := s.db.QueryRowContext(ctx,
		`SELECT entry_idx, serial_hex, checkpoint_id, tree_size, bundle_json, bundle_pem, stale, created_at, updated_at
		 FROM assertion_bundles WHERE serial_hex = $1`, serialHex).
		Scan(&ab.EntryIdx, &ab.SerialHex, &ab.CheckpointID, &ab.TreeSize,
			&ab.BundleJSON, &ab.BundlePEM, &ab.Stale, &ab.CreatedAt, &ab.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetAssertionBundleBySerial: %w", err)
	}
	return &ab, nil
}

// ListPendingEntries returns log entry indices that don't have a fresh assertion bundle.
// It returns entries of type 1 (TBSCertificateLogEntry) that either have no bundle
// or have a stale bundle.
func (s *Store) ListPendingEntries(ctx context.Context, limit int) ([]int64, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT le.idx FROM log_entries le
		 LEFT JOIN assertion_bundles ab ON le.idx = ab.entry_idx AND ab.stale = FALSE
		 WHERE le.entry_type = 1 AND ab.entry_idx IS NULL
		 ORDER BY le.idx DESC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListPendingEntries: %w", err)
	}
	defer rows.Close()

	var indices []int64
	for rows.Next() {
		var idx int64
		if err := rows.Scan(&idx); err != nil {
			return nil, fmt.Errorf("store.ListPendingEntries: scan: %w", err)
		}
		indices = append(indices, idx)
	}
	return indices, rows.Err()
}

// MarkStaleBundles marks all assertion bundles with tree_size < currentTreeSize as stale.
func (s *Store) MarkStaleBundles(ctx context.Context, currentTreeSize int64) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE assertion_bundles SET stale = TRUE, updated_at = NOW()
		 WHERE tree_size < $1 AND stale = FALSE`, currentTreeSize)
	if err != nil {
		return 0, fmt.Errorf("store.MarkStaleBundles: %w", err)
	}
	return result.RowsAffected()
}

// ListStaleBundles returns entry indices with stale assertion bundles.
func (s *Store) ListStaleBundles(ctx context.Context, limit int) ([]int64, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT entry_idx FROM assertion_bundles
		 WHERE stale = TRUE
		 ORDER BY entry_idx DESC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListStaleBundles: %w", err)
	}
	defer rows.Close()

	var indices []int64
	for rows.Next() {
		var idx int64
		if err := rows.Scan(&idx); err != nil {
			return nil, fmt.Errorf("store.ListStaleBundles: scan: %w", err)
		}
		indices = append(indices, idx)
	}
	return indices, rows.Err()
}

// GetFreshBundlesSince returns assertion bundles created/updated since the given checkpoint ID.
func (s *Store) GetFreshBundlesSince(ctx context.Context, sinceCheckpointID int64, limit int) ([]*AssertionBundle, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT entry_idx, serial_hex, checkpoint_id, tree_size, bundle_json, bundle_pem, stale, created_at, updated_at
		 FROM assertion_bundles
		 WHERE checkpoint_id > $1 AND stale = FALSE
		 ORDER BY created_at DESC
		 LIMIT $2`, sinceCheckpointID, limit)
	if err != nil {
		return nil, fmt.Errorf("store.GetFreshBundlesSince: %w", err)
	}
	defer rows.Close()

	var bundles []*AssertionBundle
	for rows.Next() {
		var ab AssertionBundle
		if err := rows.Scan(&ab.EntryIdx, &ab.SerialHex, &ab.CheckpointID, &ab.TreeSize,
			&ab.BundleJSON, &ab.BundlePEM, &ab.Stale, &ab.CreatedAt, &ab.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store.GetFreshBundlesSince: scan: %w", err)
		}
		bundles = append(bundles, &ab)
	}
	return bundles, rows.Err()
}

// AssertionStats holds aggregate statistics for assertion bundles.
type AssertionStats struct {
	TotalBundles   int64     `json:"total_bundles"`
	FreshBundles   int64     `json:"fresh_bundles"`
	StaleBundles   int64     `json:"stale_bundles"`
	PendingEntries int64     `json:"pending_entries"`
	LastGenerated  time.Time `json:"last_generated"`
}

// GetAssertionStats returns aggregate statistics for assertion bundles.
func (s *Store) GetAssertionStats(ctx context.Context) (*AssertionStats, error) {
	var stats AssertionStats
	err := s.db.QueryRowContext(ctx,
		`SELECT
			COALESCE((SELECT COUNT(*) FROM assertion_bundles), 0),
			COALESCE((SELECT COUNT(*) FROM assertion_bundles WHERE stale = FALSE), 0),
			COALESCE((SELECT COUNT(*) FROM assertion_bundles WHERE stale = TRUE), 0),
			COALESCE((SELECT COUNT(*) FROM log_entries le
			          LEFT JOIN assertion_bundles ab ON le.idx = ab.entry_idx AND ab.stale = FALSE
			          WHERE le.entry_type = 1 AND ab.entry_idx IS NULL), 0),
			COALESCE((SELECT MAX(updated_at) FROM assertion_bundles), '1970-01-01')
		`).Scan(&stats.TotalBundles, &stats.FreshBundles, &stats.StaleBundles,
		&stats.PendingEntries, &stats.LastGenerated)
	if err != nil {
		return nil, fmt.Errorf("store.GetAssertionStats: %w", err)
	}
	return &stats, nil
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

// --- ACME Types ---

// ACMEAccount is an ACME account.
type ACMEAccount struct {
	ID            string          `json:"id"`
	Status        string          `json:"status"`
	KeyThumbprint string          `json:"key_thumbprint"`
	JWK           json.RawMessage `json:"jwk"`
	Contact       json.RawMessage `json:"contact"`
	CreatedAt     time.Time       `json:"created_at"`
}

// ACMEOrder is an ACME order.
type ACMEOrder struct {
	ID             string          `json:"id"`
	AccountID      string          `json:"account_id"`
	Status         string          `json:"status"`
	Identifiers    json.RawMessage `json:"identifiers"`
	NotBefore      *time.Time      `json:"not_before,omitempty"`
	NotAfter       *time.Time      `json:"not_after,omitempty"`
	Expires        time.Time       `json:"expires"`
	CSR            string          `json:"csr,omitempty"`
	CertificateURL string          `json:"certificate_url,omitempty"`
	CertSerial     string          `json:"cert_serial,omitempty"`
	AssertionURL   string          `json:"assertion_url,omitempty"`
	ErrorType      string          `json:"error_type,omitempty"`
	ErrorDetail    string          `json:"error_detail,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// ACMEAuthorization is an ACME authorization.
type ACMEAuthorization struct {
	ID         string          `json:"id"`
	OrderID    string          `json:"order_id"`
	Identifier json.RawMessage `json:"identifier"`
	Status     string          `json:"status"`
	Expires    time.Time       `json:"expires"`
	Wildcard   bool            `json:"wildcard"`
	CreatedAt  time.Time       `json:"created_at"`
}

// ACMEChallenge is an ACME challenge.
type ACMEChallenge struct {
	ID          string     `json:"id"`
	AuthzID     string     `json:"authz_id"`
	Type        string     `json:"type"`
	Status      string     `json:"status"`
	Token       string     `json:"token"`
	Validated   *time.Time `json:"validated,omitempty"`
	ErrorType   string     `json:"error_type,omitempty"`
	ErrorDetail string     `json:"error_detail,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// --- ACME Account Methods ---

// CreateACMEAccount inserts a new ACME account.
func (s *Store) CreateACMEAccount(ctx context.Context, acct *ACMEAccount) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO acme_accounts (id, status, key_thumbprint, jwk, contact)
		 VALUES ($1, $2, $3, $4, $5)`,
		acct.ID, acct.Status, acct.KeyThumbprint, acct.JWK, acct.Contact,
	)
	if err != nil {
		return fmt.Errorf("store.CreateACMEAccount: %w", err)
	}
	return nil
}

// GetACMEAccount retrieves an ACME account by ID.
func (s *Store) GetACMEAccount(ctx context.Context, id string) (*ACMEAccount, error) {
	var acct ACMEAccount
	err := s.db.QueryRowContext(ctx,
		`SELECT id, status, key_thumbprint, jwk, contact, created_at
		 FROM acme_accounts WHERE id = $1`, id).
		Scan(&acct.ID, &acct.Status, &acct.KeyThumbprint, &acct.JWK, &acct.Contact, &acct.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetACMEAccount: %w", err)
	}
	return &acct, nil
}

// GetACMEAccountByThumbprint retrieves an ACME account by key thumbprint.
func (s *Store) GetACMEAccountByThumbprint(ctx context.Context, thumbprint string) (*ACMEAccount, error) {
	var acct ACMEAccount
	err := s.db.QueryRowContext(ctx,
		`SELECT id, status, key_thumbprint, jwk, contact, created_at
		 FROM acme_accounts WHERE key_thumbprint = $1`, thumbprint).
		Scan(&acct.ID, &acct.Status, &acct.KeyThumbprint, &acct.JWK, &acct.Contact, &acct.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetACMEAccountByThumbprint: %w", err)
	}
	return &acct, nil
}

// --- ACME Order Methods ---

// CreateACMEOrder inserts a new ACME order with its authorizations and challenges.
func (s *Store) CreateACMEOrder(ctx context.Context, order *ACMEOrder, authzs []*ACMEAuthorization, challenges []*ACMEChallenge) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.CreateACMEOrder: begin: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO acme_orders (id, account_id, status, identifiers, not_before, not_after, expires)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		order.ID, order.AccountID, order.Status, order.Identifiers, order.NotBefore, order.NotAfter, order.Expires,
	)
	if err != nil {
		return fmt.Errorf("store.CreateACMEOrder: order: %w", err)
	}

	for _, authz := range authzs {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO acme_authorizations (id, order_id, identifier, status, expires, wildcard)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			authz.ID, authz.OrderID, authz.Identifier, authz.Status, authz.Expires, authz.Wildcard,
		)
		if err != nil {
			return fmt.Errorf("store.CreateACMEOrder: authz %s: %w", authz.ID, err)
		}
	}

	for _, ch := range challenges {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO acme_challenges (id, authz_id, type, status, token)
			 VALUES ($1, $2, $3, $4, $5)`,
			ch.ID, ch.AuthzID, ch.Type, ch.Status, ch.Token,
		)
		if err != nil {
			return fmt.Errorf("store.CreateACMEOrder: challenge %s: %w", ch.ID, err)
		}
	}

	return tx.Commit()
}

// GetACMEOrder retrieves an ACME order by ID.
func (s *Store) GetACMEOrder(ctx context.Context, id string) (*ACMEOrder, error) {
	var o ACMEOrder
	var nb, na sql.NullTime
	var csr, certURL, certSerial, assertionURL, errType, errDetail sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, account_id, status, identifiers, not_before, not_after, expires,
		        csr, certificate_url, cert_serial, assertion_url, error_type, error_detail,
		        created_at, updated_at
		 FROM acme_orders WHERE id = $1`, id).
		Scan(&o.ID, &o.AccountID, &o.Status, &o.Identifiers, &nb, &na, &o.Expires,
			&csr, &certURL, &certSerial, &assertionURL, &errType, &errDetail,
			&o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetACMEOrder: %w", err)
	}
	if nb.Valid {
		o.NotBefore = &nb.Time
	}
	if na.Valid {
		o.NotAfter = &na.Time
	}
	o.CSR = csr.String
	o.CertificateURL = certURL.String
	o.CertSerial = certSerial.String
	o.AssertionURL = assertionURL.String
	o.ErrorType = errType.String
	o.ErrorDetail = errDetail.String
	return &o, nil
}

// UpdateACMEOrderStatus updates the status and related fields of an ACME order.
func (s *Store) UpdateACMEOrderStatus(ctx context.Context, id, status string, updates map[string]interface{}) error {
	// Build a minimal dynamic update. Only known safe columns are accepted.
	set := "status = $2, updated_at = NOW()"
	args := []interface{}{id, status}
	i := 3
	for _, col := range []string{"csr", "certificate_url", "cert_serial", "assertion_url", "error_type", "error_detail"} {
		if v, ok := updates[col]; ok {
			set += fmt.Sprintf(", %s = $%d", col, i)
			args = append(args, v)
			i++
		}
	}
	_, err := s.db.ExecContext(ctx,
		fmt.Sprintf("UPDATE acme_orders SET %s WHERE id = $1", set), args...)
	if err != nil {
		return fmt.Errorf("store.UpdateACMEOrderStatus: %w", err)
	}
	return nil
}

// ListACMEOrdersByAccount returns orders for an account.
func (s *Store) ListACMEOrdersByAccount(ctx context.Context, accountID string, limit int) ([]*ACMEOrder, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, status, identifiers, not_before, not_after, expires,
		        csr, certificate_url, cert_serial, assertion_url, error_type, error_detail,
		        created_at, updated_at
		 FROM acme_orders WHERE account_id = $1
		 ORDER BY created_at DESC LIMIT $2`, accountID, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListACMEOrdersByAccount: %w", err)
	}
	defer rows.Close()
	return scanACMEOrders(rows)
}

// FindACMEOrderBySerial returns orders matching a cert serial.
func (s *Store) FindACMEOrderBySerial(ctx context.Context, serial string) (*ACMEOrder, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, status, identifiers, not_before, not_after, expires,
		        csr, certificate_url, cert_serial, assertion_url, error_type, error_detail,
		        created_at, updated_at
		 FROM acme_orders WHERE cert_serial = $1 LIMIT 1`, serial)
	if err != nil {
		return nil, fmt.Errorf("store.FindACMEOrderBySerial: %w", err)
	}
	defer rows.Close()
	orders, err := scanACMEOrders(rows)
	if err != nil {
		return nil, err
	}
	if len(orders) == 0 {
		return nil, sql.ErrNoRows
	}
	return orders[0], nil
}

func scanACMEOrders(rows *sql.Rows) ([]*ACMEOrder, error) {
	var orders []*ACMEOrder
	for rows.Next() {
		var o ACMEOrder
		var nb, na sql.NullTime
		var csr, certURL, certSerial, assertionURL, errType, errDetail sql.NullString
		if err := rows.Scan(&o.ID, &o.AccountID, &o.Status, &o.Identifiers, &nb, &na, &o.Expires,
			&csr, &certURL, &certSerial, &assertionURL, &errType, &errDetail,
			&o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanACMEOrders: %w", err)
		}
		if nb.Valid {
			o.NotBefore = &nb.Time
		}
		if na.Valid {
			o.NotAfter = &na.Time
		}
		o.CSR = csr.String
		o.CertificateURL = certURL.String
		o.CertSerial = certSerial.String
		o.AssertionURL = assertionURL.String
		o.ErrorType = errType.String
		o.ErrorDetail = errDetail.String
		orders = append(orders, &o)
	}
	return orders, rows.Err()
}

// --- ACME Authorization/Challenge Methods ---

// GetACMEAuthorization retrieves an authorization by ID.
func (s *Store) GetACMEAuthorization(ctx context.Context, id string) (*ACMEAuthorization, error) {
	var a ACMEAuthorization
	err := s.db.QueryRowContext(ctx,
		`SELECT id, order_id, identifier, status, expires, wildcard, created_at
		 FROM acme_authorizations WHERE id = $1`, id).
		Scan(&a.ID, &a.OrderID, &a.Identifier, &a.Status, &a.Expires, &a.Wildcard, &a.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetACMEAuthorization: %w", err)
	}
	return &a, nil
}

// ListACMEAuthorizationsByOrder returns authorizations for an order.
func (s *Store) ListACMEAuthorizationsByOrder(ctx context.Context, orderID string) ([]*ACMEAuthorization, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, order_id, identifier, status, expires, wildcard, created_at
		 FROM acme_authorizations WHERE order_id = $1`, orderID)
	if err != nil {
		return nil, fmt.Errorf("store.ListACMEAuthorizationsByOrder: %w", err)
	}
	defer rows.Close()

	var authzs []*ACMEAuthorization
	for rows.Next() {
		var a ACMEAuthorization
		if err := rows.Scan(&a.ID, &a.OrderID, &a.Identifier, &a.Status, &a.Expires, &a.Wildcard, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("store.ListACMEAuthorizationsByOrder: scan: %w", err)
		}
		authzs = append(authzs, &a)
	}
	return authzs, rows.Err()
}

// UpdateACMEAuthorizationStatus updates an authorization status.
func (s *Store) UpdateACMEAuthorizationStatus(ctx context.Context, id, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_authorizations SET status = $2 WHERE id = $1`, id, status)
	if err != nil {
		return fmt.Errorf("store.UpdateACMEAuthorizationStatus: %w", err)
	}
	return nil
}

// GetACMEChallenge retrieves a challenge by ID.
func (s *Store) GetACMEChallenge(ctx context.Context, id string) (*ACMEChallenge, error) {
	var ch ACMEChallenge
	var validated sql.NullTime
	var errType, errDetail sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, authz_id, type, status, token, validated, error_type, error_detail, created_at
		 FROM acme_challenges WHERE id = $1`, id).
		Scan(&ch.ID, &ch.AuthzID, &ch.Type, &ch.Status, &ch.Token, &validated, &errType, &errDetail, &ch.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetACMEChallenge: %w", err)
	}
	if validated.Valid {
		ch.Validated = &validated.Time
	}
	ch.ErrorType = errType.String
	ch.ErrorDetail = errDetail.String
	return &ch, nil
}

// ListACMEChallengesByAuthz returns challenges for an authorization.
func (s *Store) ListACMEChallengesByAuthz(ctx context.Context, authzID string) ([]*ACMEChallenge, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, authz_id, type, status, token, validated, error_type, error_detail, created_at
		 FROM acme_challenges WHERE authz_id = $1`, authzID)
	if err != nil {
		return nil, fmt.Errorf("store.ListACMEChallengesByAuthz: %w", err)
	}
	defer rows.Close()

	var challenges []*ACMEChallenge
	for rows.Next() {
		var ch ACMEChallenge
		var validated sql.NullTime
		var errType, errDetail sql.NullString
		if err := rows.Scan(&ch.ID, &ch.AuthzID, &ch.Type, &ch.Status, &ch.Token, &validated, &errType, &errDetail, &ch.CreatedAt); err != nil {
			return nil, fmt.Errorf("store.ListACMEChallengesByAuthz: scan: %w", err)
		}
		if validated.Valid {
			ch.Validated = &validated.Time
		}
		ch.ErrorType = errType.String
		ch.ErrorDetail = errDetail.String
		challenges = append(challenges, &ch)
	}
	return challenges, rows.Err()
}

// UpdateACMEChallengeStatus updates a challenge status.
func (s *Store) UpdateACMEChallengeStatus(ctx context.Context, id, status string, validated *time.Time, errType, errDetail string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_challenges SET status = $2, validated = $3, error_type = $4, error_detail = $5
		 WHERE id = $1`, id, status, validated, errType, errDetail)
	if err != nil {
		return fmt.Errorf("store.UpdateACMEChallengeStatus: %w", err)
	}
	return nil
}

// GetACMEChallengeByToken retrieves a challenge by its token.
func (s *Store) GetACMEChallengeByToken(ctx context.Context, token string) (*ACMEChallenge, error) {
	var ch ACMEChallenge
	var validated sql.NullTime
	var errType, errDetail sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, authz_id, type, status, token, validated, error_type, error_detail, created_at
		 FROM acme_challenges WHERE token = $1`, token).
		Scan(&ch.ID, &ch.AuthzID, &ch.Type, &ch.Status, &ch.Token, &validated, &errType, &errDetail, &ch.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetACMEChallengeByToken: %w", err)
	}
	if validated.Valid {
		ch.Validated = &validated.Time
	}
	ch.ErrorType = errType.String
	ch.ErrorDetail = errDetail.String
	return &ch, nil
}

// --- Visualization Types ---

// VizSummary is a hierarchical aggregation of certificate data for visualization.
type VizSummary struct {
	Name           string        `json:"name"`
	Level          string        `json:"level"`
	CertCount      int64         `json:"certCount"`
	RevokedCount   int64         `json:"revokedCount"`
	PQCount        int64         `json:"pqCount"`
	ClassicalCount int64         `json:"classicalCount"`
	FreshCount     int64         `json:"freshCount"`
	StaleCount     int64         `json:"staleCount"`
	MissingCount   int64         `json:"missingCount"`
	Children       []*VizSummary `json:"children,omitempty"`
	Color          string        `json:"color,omitempty"`
}

// VizCertificate is a leaf-level certificate for the visualization detail view.
type VizCertificate struct {
	Index        int64  `json:"index"`
	SerialHex    string `json:"serialHex"`
	CommonName   string `json:"commonName"`
	CAName       string `json:"ca"`
	KeyAlgorithm string `json:"algorithm"`
	IsPQ         bool   `json:"isPQ"`
	BatchWindow  string `json:"batchWindow"`
	CreatedAt    string `json:"issuedAt"`
	Revoked      bool   `json:"revoked"`
}

// VizStats holds aggregate statistics for the visualization stats bar.
type VizStats struct {
	Total        int64   `json:"total"`
	Valid        int64   `json:"valid"`
	Revoked      int64   `json:"revoked"`
	PQCount      int64   `json:"pqCount"`
	CACount      int64   `json:"caCount"`
	RevRate      float64 `json:"revocationRate"`
	FreshCount   int64   `json:"freshCount"`
	StaleCount   int64   `json:"staleCount"`
	MissingCount int64   `json:"missingCount"`
	CoverageRate float64 `json:"coverageRate"`
}

// --- Visualization Methods ---

// isPQAlgorithm returns true if the key algorithm name indicates a post-quantum algorithm.
func isPQAlgorithm(keyAlgo string) bool {
	upper := strings.ToUpper(keyAlgo)
	for _, prefix := range []string{"ML-DSA", "ML-KEM", "SLH-DSA", "DILITHIUM", "KYBER", "SPHINCS", "FALCON"} {
		if strings.Contains(upper, prefix) {
			return true
		}
	}
	return false
}

// batchWindowTime truncates a timestamp to 6-hour intervals.
func batchWindowTime(t time.Time) time.Time {
	t = t.UTC()
	hour := (t.Hour() / 6) * 6
	return time.Date(t.Year(), t.Month(), t.Day(), hour, 0, 0, 0, time.UTC)
}

// vizCAColors is a palette of distinct colors for CA segments.
var vizCAColors = []string{
	"#34d399", "#38bdf8", "#818cf8", "#fbbf24",
	"#fb923c", "#f472b6", "#a78bfa", "#22d3ee",
	"#f87171", "#84cc16", "#e879f9", "#2dd4bf",
}

// vizCAColor returns a stable color for a CA name.
func vizCAColor(name string) string {
	var h uint32
	for _, c := range name {
		h = h*31 + uint32(c)
	}
	return vizCAColors[h%uint32(len(vizCAColors))]
}

// PopulateCertMetadata incrementally populates the cert_metadata cache table
// by parsing DER certificates from log_entries that have no metadata yet.
func (s *Store) PopulateCertMetadata(ctx context.Context, caNames map[string]string) (int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT le.idx, le.entry_data, le.ca_cert_id, le.created_at
		 FROM log_entries le
		 LEFT JOIN cert_metadata cm ON le.idx = cm.entry_idx
		 WHERE le.entry_type = 1 AND cm.entry_idx IS NULL
		 ORDER BY le.idx
		 LIMIT 1000`)
	if err != nil {
		return 0, fmt.Errorf("store.PopulateCertMetadata: query: %w", err)
	}
	defer rows.Close()

	type metaRow struct {
		idx       int64
		caCertID  string
		caName    string
		keyAlgo   string
		sigAlgo   string
		cn        string
		isPQ      bool
		batchWin  time.Time
		createdAt time.Time
	}

	var pending []metaRow
	for rows.Next() {
		var idx int64
		var entryData []byte
		var caCertID string
		var createdAt time.Time
		if err := rows.Scan(&idx, &entryData, &caCertID, &createdAt); err != nil {
			return 0, fmt.Errorf("store.PopulateCertMetadata: scan: %w", err)
		}

		meta, _, err := certutil.ParseLogEntry(entryData)
		if err != nil {
			s.logger.Warn("viz: skip unparseable entry", "idx", idx, "error", err)
			continue
		}

		caName := caCertID
		if name, ok := caNames[caCertID]; ok && name != "" {
			caName = name
		}

		pending = append(pending, metaRow{
			idx:       idx,
			caCertID:  caCertID,
			caName:    caName,
			keyAlgo:   meta.KeyAlgorithm,
			sigAlgo:   meta.SignatureAlgorithm,
			cn:        meta.CommonName,
			isPQ:      isPQAlgorithm(meta.KeyAlgorithm),
			batchWin:  batchWindowTime(createdAt),
			createdAt: createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store.PopulateCertMetadata: rows: %w", err)
	}

	if len(pending) == 0 {
		return 0, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.PopulateCertMetadata: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO cert_metadata (entry_idx, ca_cert_id, ca_name, key_algorithm, sig_algorithm, common_name, is_pq, batch_window, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (entry_idx) DO NOTHING`)
	if err != nil {
		return 0, fmt.Errorf("store.PopulateCertMetadata: prepare: %w", err)
	}
	defer stmt.Close()

	for _, r := range pending {
		if _, err := stmt.ExecContext(ctx, r.idx, r.caCertID, r.caName, r.keyAlgo, r.sigAlgo, r.cn, r.isPQ, r.batchWin, r.createdAt); err != nil {
			return 0, fmt.Errorf("store.PopulateCertMetadata: insert idx %d: %w", r.idx, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.PopulateCertMetadata: commit: %w", err)
	}

	return int64(len(pending)), nil
}

// GetCertLocation returns a certificate's position in the visualization hierarchy.
func (s *Store) GetCertLocation(ctx context.Context, idx int64) (caName string, batchWindow time.Time, keyAlgo string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT ca_name, batch_window, key_algorithm FROM cert_metadata WHERE entry_idx = $1`, idx,
	).Scan(&caName, &batchWindow, &keyAlgo)
	if err != nil {
		err = fmt.Errorf("store.GetCertLocation: %w", err)
	}
	return
}

// GetVizSummary returns the aggregated certificate hierarchy for visualization.
func (s *Store) GetVizSummary(ctx context.Context) (*VizSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT cm.ca_name, cm.batch_window, cm.key_algorithm, cm.is_pq,
		        COUNT(*) AS cert_count,
		        COUNT(ri.entry_idx) AS revoked_count,
		        COUNT(CASE WHEN ab.entry_idx IS NOT NULL AND ab.stale = FALSE THEN 1 END) AS fresh_count,
		        COUNT(CASE WHEN ab.entry_idx IS NOT NULL AND ab.stale = TRUE THEN 1 END) AS stale_count,
		        COUNT(CASE WHEN ab.entry_idx IS NULL THEN 1 END) AS missing_count
		 FROM cert_metadata cm
		 LEFT JOIN revoked_indices ri ON cm.entry_idx = ri.entry_idx
		 LEFT JOIN assertion_bundles ab ON cm.entry_idx = ab.entry_idx
		 WHERE cm.entry_idx > 0
		 GROUP BY cm.ca_name, cm.batch_window, cm.key_algorithm, cm.is_pq
		 ORDER BY cm.ca_name, cm.batch_window DESC, cert_count DESC`)
	if err != nil {
		return nil, fmt.Errorf("store.GetVizSummary: %w", err)
	}
	defer rows.Close()

	root := &VizSummary{Name: "All CAs", Level: "root"}
	caMap := make(map[string]*VizSummary)
	type batchKey struct{ ca, batch string }
	batchMap := make(map[batchKey]*VizSummary)

	for rows.Next() {
		var caName, keyAlgo string
		var batchWin time.Time
		var isPQ bool
		var certCount, revokedCount, freshCount, staleCount, missingCount int64
		if err := rows.Scan(&caName, &batchWin, &keyAlgo, &isPQ, &certCount, &revokedCount,
			&freshCount, &staleCount, &missingCount); err != nil {
			return nil, fmt.Errorf("store.GetVizSummary: scan: %w", err)
		}

		ca, ok := caMap[caName]
		if !ok {
			ca = &VizSummary{Name: caName, Level: "ca", Color: vizCAColor(caName)}
			caMap[caName] = ca
			root.Children = append(root.Children, ca)
		}
		ca.CertCount += certCount
		ca.RevokedCount += revokedCount
		ca.FreshCount += freshCount
		ca.StaleCount += staleCount
		ca.MissingCount += missingCount

		batchLabel := batchWin.Format("Jan 2 15:04")
		bk := batchKey{caName, batchLabel}
		batch, ok := batchMap[bk]
		if !ok {
			batch = &VizSummary{Name: batchLabel, Level: "batch", Color: ca.Color}
			batchMap[bk] = batch
			ca.Children = append(ca.Children, batch)
		}
		batch.CertCount += certCount
		batch.RevokedCount += revokedCount
		batch.FreshCount += freshCount
		batch.StaleCount += staleCount
		batch.MissingCount += missingCount

		algo := &VizSummary{
			Name:         keyAlgo,
			Level:        "algo",
			CertCount:    certCount,
			RevokedCount: revokedCount,
			FreshCount:   freshCount,
			StaleCount:   staleCount,
			MissingCount: missingCount,
			Color:        ca.Color,
		}
		if isPQ {
			algo.PQCount = certCount
			batch.PQCount += certCount
			ca.PQCount += certCount
			root.PQCount += certCount
		} else {
			algo.ClassicalCount = certCount
			batch.ClassicalCount += certCount
			ca.ClassicalCount += certCount
			root.ClassicalCount += certCount
		}
		batch.Children = append(batch.Children, algo)

		root.CertCount += certCount
		root.RevokedCount += revokedCount
		root.FreshCount += freshCount
		root.StaleCount += staleCount
		root.MissingCount += missingCount
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.GetVizSummary: rows: %w", err)
	}

	return root, nil
}

// GetVizCertificates returns paginated certificates for leaf-level visualization.
func (s *Store) GetVizCertificates(ctx context.Context, caName, batchWin, algo string, limit, offset int) ([]*VizCertificate, int64, error) {
	if limit <= 0 {
		limit = 500
	}

	where := "cm.entry_idx > 0"
	var args []interface{}
	argIdx := 1

	if caName != "" {
		where += fmt.Sprintf(" AND cm.ca_name = $%d", argIdx)
		args = append(args, caName)
		argIdx++
	}
	if batchWin != "" {
		where += fmt.Sprintf(" AND cm.batch_window = $%d::timestamptz", argIdx)
		args = append(args, batchWin)
		argIdx++
	}
	if algo != "" {
		where += fmt.Sprintf(" AND cm.key_algorithm = $%d", argIdx)
		args = append(args, algo)
		argIdx++
	}

	var total int64
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM cert_metadata cm WHERE %s`, where),
		countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("store.GetVizCertificates: count: %w", err)
	}

	limitPlaceholder := fmt.Sprintf("$%d", argIdx)
	offsetPlaceholder := fmt.Sprintf("$%d", argIdx+1)
	dataArgs := append(args, limit, offset)

	dataRows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT cm.entry_idx, le.serial_hex, cm.common_name, cm.ca_name,
		        cm.key_algorithm, cm.is_pq, cm.batch_window, le.created_at,
		        CASE WHEN ri.entry_idx IS NOT NULL THEN TRUE ELSE FALSE END AS revoked
		 FROM cert_metadata cm
		 JOIN log_entries le ON cm.entry_idx = le.idx
		 LEFT JOIN revoked_indices ri ON cm.entry_idx = ri.entry_idx
		 WHERE %s
		 ORDER BY cm.entry_idx DESC
		 LIMIT %s OFFSET %s`, where, limitPlaceholder, offsetPlaceholder),
		dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("store.GetVizCertificates: query: %w", err)
	}
	defer dataRows.Close()

	var certs []*VizCertificate
	for dataRows.Next() {
		var c VizCertificate
		var bw time.Time
		var ca time.Time
		if err := dataRows.Scan(&c.Index, &c.SerialHex, &c.CommonName, &c.CAName,
			&c.KeyAlgorithm, &c.IsPQ, &bw, &ca, &c.Revoked); err != nil {
			return nil, 0, fmt.Errorf("store.GetVizCertificates: scan: %w", err)
		}
		c.BatchWindow = bw.Format("Jan 2 15:04")
		c.CreatedAt = ca.Format(time.RFC3339)
		certs = append(certs, &c)
	}
	if err := dataRows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store.GetVizCertificates: rows: %w", err)
	}

	return certs, total, nil
}

// GetVizStats returns aggregate statistics for the visualization stats bar.
func (s *Store) GetVizStats(ctx context.Context) (*VizStats, error) {
	var stats VizStats
	err := s.db.QueryRowContext(ctx,
		`SELECT
			COUNT(*),
			COUNT(ri.entry_idx),
			COALESCE(SUM(CASE WHEN cm.is_pq THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT cm.ca_name),
			COUNT(CASE WHEN ab.entry_idx IS NOT NULL AND ab.stale = FALSE THEN 1 END),
			COUNT(CASE WHEN ab.entry_idx IS NOT NULL AND ab.stale = TRUE THEN 1 END),
			COUNT(CASE WHEN ab.entry_idx IS NULL THEN 1 END)
		 FROM cert_metadata cm
		 LEFT JOIN revoked_indices ri ON cm.entry_idx = ri.entry_idx
		 LEFT JOIN assertion_bundles ab ON cm.entry_idx = ab.entry_idx
		 WHERE cm.entry_idx > 0`).
		Scan(&stats.Total, &stats.Revoked, &stats.PQCount, &stats.CACount,
			&stats.FreshCount, &stats.StaleCount, &stats.MissingCount)
	if err != nil {
		return nil, fmt.Errorf("store.GetVizStats: %w", err)
	}
	stats.Valid = stats.Total - stats.Revoked
	if stats.Total > 0 {
		stats.RevRate = float64(stats.Revoked) / float64(stats.Total)
		stats.CoverageRate = float64(stats.FreshCount) / float64(stats.Total)
	}
	return &stats, nil
}
