// Package watcher implements the background polling orchestrator that watches
// the CA database for new certificates and revocations, appends them to the
// issuance log, and creates periodic checkpoints.
package watcher

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/cadb"
	"github.com/briantrzupek/ca-extension-merkle/internal/issuancelog"
	"github.com/briantrzupek/ca-extension-merkle/internal/revocation"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Config holds watcher configuration.
type Config struct {
	PollInterval        time.Duration
	CheckpointInterval  time.Duration
	BatchSize           int
	RevocationPollInterval time.Duration
}

// Watcher polls the CA database and manages the issuance log.
type Watcher struct {
	cadb    *cadb.Adapter
	store   *store.Store
	log     *issuancelog.Log
	revMgr  *revocation.Manager
	cfg     Config
	logger  *slog.Logger

	mu              sync.Mutex
	running         bool
	lastCheckpoint  time.Time
	certsProcessed  int64
	revocsProcessed int64
}

// New creates a new Watcher.
func New(
	ca *cadb.Adapter,
	s *store.Store,
	ilog *issuancelog.Log,
	revMgr *revocation.Manager,
	cfg Config,
	logger *slog.Logger,
) *Watcher {
	return &Watcher{
		cadb:   ca,
		store:  s,
		log:    ilog,
		revMgr: revMgr,
		cfg:    cfg,
		logger: logger,
	}
}

// Run starts the watcher loop. It blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	w.mu.Lock()
	w.running = true
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
	}()

	w.logger.Info("watcher starting",
		"poll_interval", w.cfg.PollInterval,
		"checkpoint_interval", w.cfg.CheckpointInterval,
		"batch_size", w.cfg.BatchSize,
	)

	// Initialize the log if needed.
	if err := w.log.Initialize(ctx); err != nil {
		return fmt.Errorf("watcher.Run: initialize log: %w", err)
	}

	// Emit startup event.
	_ = w.store.EmitEvent(ctx, "watcher_started", map[string]interface{}{
		"timestamp": time.Now().UTC(),
	})

	certTicker := time.NewTicker(w.cfg.PollInterval)
	defer certTicker.Stop()

	revocTicker := time.NewTicker(w.cfg.RevocationPollInterval)
	defer revocTicker.Stop()

	cpTicker := time.NewTicker(w.cfg.CheckpointInterval)
	defer cpTicker.Stop()

	// Initial poll immediately.
	if err := w.pollCertificates(ctx); err != nil {
		w.logger.Error("initial certificate poll failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("watcher stopping")
			_ = w.store.EmitEvent(ctx, "watcher_stopped", map[string]interface{}{
				"timestamp":        time.Now().UTC(),
				"certs_processed":  w.certsProcessed,
				"revocs_processed": w.revocsProcessed,
			})
			return ctx.Err()

		case <-certTicker.C:
			if err := w.pollCertificates(ctx); err != nil {
				w.logger.Error("certificate poll failed", "error", err)
			}

		case <-revocTicker.C:
			if err := w.pollRevocations(ctx); err != nil {
				w.logger.Error("revocation poll failed", "error", err)
			}

		case <-cpTicker.C:
			if err := w.createCheckpoint(ctx); err != nil {
				w.logger.Error("checkpoint creation failed", "error", err)
			}
		}
	}
}

func (w *Watcher) pollCertificates(ctx context.Context) error {
	// Get cursor from store.
	cursor, err := w.store.GetWatcherCursor(ctx)
	if err != nil {
		// No cursor yet — start from epoch.
		cursor = &store.WatcherCursor{
			LastCreatedAt: time.Time{},
			LastCertID:    "",
		}
	}

	certs, err := w.cadb.FetchNewCertificates(ctx, cursor.LastCreatedAt, cursor.LastCertID, w.cfg.BatchSize)
	if err != nil {
		return fmt.Errorf("watcher: fetch certs: %w", err)
	}

	if len(certs) == 0 {
		return nil
	}

	count, newSize, err := w.log.AppendCertificates(ctx, certs)
	if err != nil {
		return fmt.Errorf("watcher: append certs: %w", err)
	}

	// Update cursor to last certificate.
	last := certs[len(certs)-1]
	if err := w.store.UpdateWatcherCursor(ctx, last.CreatedDate, last.ID); err != nil {
		return fmt.Errorf("watcher: update cursor: %w", err)
	}

	w.mu.Lock()
	w.certsProcessed += int64(count)
	w.mu.Unlock()

	w.logger.Info("poll: appended certificates",
		"count", count,
		"tree_size", newSize,
		"last_id", last.ID,
	)

	_ = w.store.EmitEvent(ctx, "certificates_appended", map[string]interface{}{
		"count":     count,
		"tree_size": newSize,
		"last_id":   last.ID,
	})

	return nil
}

func (w *Watcher) pollRevocations(ctx context.Context) error {
	// Use 24h lookback to catch any missed revocations.
	since := time.Now().Add(-24 * time.Hour)

	events, err := w.cadb.FetchNewRevocations(ctx, since)
	if err != nil {
		return fmt.Errorf("watcher: fetch revocations: %w", err)
	}

	if len(events) == 0 {
		return nil
	}

	count, err := w.revMgr.ProcessRevocations(ctx, events)
	if err != nil {
		return fmt.Errorf("watcher: process revocations: %w", err)
	}

	w.mu.Lock()
	w.revocsProcessed += int64(count)
	w.mu.Unlock()

	if count > 0 {
		w.logger.Info("poll: processed revocations", "count", count)
	}

	return nil
}

func (w *Watcher) createCheckpoint(ctx context.Context) error {
	cp, err := w.log.CreateCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("watcher: create checkpoint: %w", err)
	}

	w.mu.Lock()
	w.lastCheckpoint = cp.Timestamp
	w.mu.Unlock()

	return nil
}

// Stats returns watcher runtime statistics.
type Stats struct {
	Running         bool      `json:"running"`
	CertsProcessed  int64     `json:"certs_processed"`
	RevocsProcessed int64     `json:"revocs_processed"`
	LastCheckpoint  time.Time `json:"last_checkpoint"`
}

// GetStats returns current watcher statistics.
func (w *Watcher) GetStats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Stats{
		Running:         w.running,
		CertsProcessed:  w.certsProcessed,
		RevocsProcessed: w.revocsProcessed,
		LastCheckpoint:  w.lastCheckpoint,
	}
}
