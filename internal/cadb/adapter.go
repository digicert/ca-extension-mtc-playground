// Package cadb provides a read-only adapter for the DigiCert Private CA's
// MariaDB database. It polls for new certificate issuances and revocations
// without modifying the CA database.
package cadb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/config"

	_ "github.com/go-sql-driver/mysql"
)

// Adapter is a read-only adapter for the DigiCert CA MariaDB database.
type Adapter struct {
	db      *sql.DB
	cfg     config.MariaDBConfig
	logger  *slog.Logger
	caCache map[string]*CAInfo
}

// CAInfo represents a Certificate Authority from the CA database.
type CAInfo struct {
	ID       string
	Name     string
	CertType string
	Status   string
	CertBlob []byte
}

// Certificate represents a certificate from the CA database.
type Certificate struct {
	ID               string
	SerialNumber     string
	CertBlob         []byte
	ValidFrom        time.Time
	ValidTo          time.Time
	CreatedDate      time.Time
	IsRevoked        bool
	RevokedDate      *time.Time
	RevokedReason    *int
	IssuerID         string
	ThumbprintSHA256 string
}

// CertSHA256 returns the SHA-256 hash of the DER certificate blob.
func (c *Certificate) CertSHA256() [32]byte {
	return sha256.Sum256(c.CertBlob)
}

// RevocationEvent represents a detected revocation.
type RevocationEvent struct {
	CertID        string
	SerialNumber  string
	RevokedDate   time.Time
	RevokedReason int
}

// New creates a new CA database adapter.
func New(ctx context.Context, cfg config.MariaDBConfig, logger *slog.Logger) (*Adapter, error) {
	db, err := sql.Open("mysql", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("cadb.New: open: %w", err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("cadb.New: ping: %w", err)
	}
	a := &Adapter{db: db, cfg: cfg, logger: logger, caCache: make(map[string]*CAInfo)}
	if err := a.loadCAs(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("cadb.New: load CAs: %w", err)
	}
	return a, nil
}

// Close closes the database connection.
func (a *Adapter) Close() error {
	return a.db.Close()
}

func (a *Adapter) loadCAs(ctx context.Context) error {
	rows, err := a.db.QueryContext(ctx, "SELECT id, name, cert_type, status, cert_blob FROM ca WHERE status = 'active'")
	if err != nil {
		return fmt.Errorf("cadb.loadCAs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ca CAInfo
		if err := rows.Scan(&ca.ID, &ca.Name, &ca.CertType, &ca.Status, &ca.CertBlob); err != nil {
			return fmt.Errorf("cadb.loadCAs: scan: %w", err)
		}
		a.caCache[ca.ID] = &ca
		a.logger.Info("loaded CA", "id", ca.ID, "name", ca.Name, "type", ca.CertType)
	}
	return rows.Err()
}

// GetCAs returns all cached CA infos.
func (a *Adapter) GetCAs() []*CAInfo {
	cas := make([]*CAInfo, 0, len(a.caCache))
	for _, ca := range a.caCache {
		cas = append(cas, ca)
	}
	return cas
}

// GetCA returns a cached CA by ID.
func (a *Adapter) GetCA(id string) (*CAInfo, bool) {
	ca, ok := a.caCache[id]
	return ca, ok
}

// FetchNewCertificates retrieves certificates created after the given cursor.
func (a *Adapter) FetchNewCertificates(ctx context.Context, afterDate time.Time, afterID string, limit int) ([]*Certificate, error) {
	q := "SELECT id, serial_number, cert_blob, valid_from, valid_to, created_date, is_revoked, revoked_date, revoked_reason, issuer_id, thumbprint_sha256 FROM certificate WHERE (created_date > ? OR (created_date = ? AND id > ?)) ORDER BY created_date, id LIMIT ?"
	args := []interface{}{afterDate, afterDate, afterID, limit}
	if a.cfg.IssuerID != "" {
		q = "SELECT id, serial_number, cert_blob, valid_from, valid_to, created_date, is_revoked, revoked_date, revoked_reason, issuer_id, thumbprint_sha256 FROM certificate WHERE issuer_id = ? AND (created_date > ? OR (created_date = ? AND id > ?)) ORDER BY created_date, id LIMIT ?"
		args = []interface{}{a.cfg.IssuerID, afterDate, afterDate, afterID, limit}
	}
	rows, err := a.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cadb.FetchNewCertificates: %w", err)
	}
	defer rows.Close()
	return scanCertificates(rows)
}

// FetchNewRevocations detects certificates revoked since a given time.
func (a *Adapter) FetchNewRevocations(ctx context.Context, since time.Time) ([]*RevocationEvent, error) {
	rows, err := a.db.QueryContext(ctx, "SELECT id, serial_number, revoked_date, revoked_reason FROM certificate WHERE is_revoked = 1 AND revoked_date > ? ORDER BY revoked_date", since)
	if err != nil {
		return nil, fmt.Errorf("cadb.FetchNewRevocations: %w", err)
	}
	defer rows.Close()
	var events []*RevocationEvent
	for rows.Next() {
		var e RevocationEvent
		var rd sql.NullTime
		var rr sql.NullInt32
		if err := rows.Scan(&e.CertID, &e.SerialNumber, &rd, &rr); err != nil {
			return nil, fmt.Errorf("cadb.FetchNewRevocations: scan: %w", err)
		}
		if rd.Valid {
			e.RevokedDate = rd.Time
		}
		if rr.Valid {
			e.RevokedReason = int(rr.Int32)
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// CertificateCount returns the total number of certificates.
func (a *Adapter) CertificateCount(ctx context.Context) (int64, error) {
	var count int64
	if err := a.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificate").Scan(&count); err != nil {
		return 0, fmt.Errorf("cadb.CertificateCount: %w", err)
	}
	return count, nil
}

// RevokedCount returns the number of revoked certificates.
func (a *Adapter) RevokedCount(ctx context.Context) (int64, error) {
	var count int64
	if err := a.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificate WHERE is_revoked = 1").Scan(&count); err != nil {
		return 0, fmt.Errorf("cadb.RevokedCount: %w", err)
	}
	return count, nil
}

func scanCertificates(rows *sql.Rows) ([]*Certificate, error) {
	var certs []*Certificate
	for rows.Next() {
		var c Certificate
		var rd sql.NullTime
		var rr sql.NullInt32
		var tp sql.NullString
		err := rows.Scan(&c.ID, &c.SerialNumber, &c.CertBlob, &c.ValidFrom, &c.ValidTo, &c.CreatedDate, &c.IsRevoked, &rd, &rr, &c.IssuerID, &tp)
		if err != nil {
			return nil, fmt.Errorf("cadb.scanCertificates: %w", err)
		}
		if rd.Valid {
			c.RevokedDate = &rd.Time
		}
		if rr.Valid {
			reason := int(rr.Int32)
			c.RevokedReason = &reason
		}
		c.ThumbprintSHA256 = tp.String
		certs = append(certs, &c)
	}
	return certs, rows.Err()
}
