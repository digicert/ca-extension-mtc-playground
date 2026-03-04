// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package assertionissuer implements the background assertion generation pipeline.
//
// After each checkpoint, the issuer scans for log entries without fresh assertion
// bundles, batch-generates them using the assertion.Builder, stores them in
// PostgreSQL, and optionally fires webhook notifications.
//
// This is the "post-issuance stapling" pipeline: certificates are issued normally
// by the CA, then the issuer proactively pre-computes companion assertion bundles.
package assertionissuer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/assertion"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Config holds assertion issuer configuration.
type Config struct {
	// Enabled turns the issuer on/off.
	Enabled bool

	// BatchSize is entries per generation batch.
	BatchSize int

	// Concurrency is the number of parallel bundle builders.
	Concurrency int

	// StalenessThreshold regenerates if proof is >N checkpoints old.
	StalenessThreshold int

	// Webhooks is a list of webhook targets to notify after generation.
	Webhooks []WebhookConfig
}

// WebhookConfig configures a single webhook target.
type WebhookConfig struct {
	URL     string `yaml:"url"`
	Pattern string `yaml:"pattern"` // CN/SAN glob pattern (* = wildcard)
	Secret  string `yaml:"secret"`  // HMAC-SHA256 secret for signature header
}

// Stats holds assertion issuer runtime statistics.
type Stats struct {
	TotalGenerated  int64     `json:"total_generated"`
	TotalRefreshed  int64     `json:"total_refreshed"`
	TotalErrors     int64     `json:"total_errors"`
	LastRunTime     time.Time `json:"last_run_time"`
	LastRunDuration string    `json:"last_run_duration"`
	WebhooksSent    int64     `json:"webhooks_sent"`
	WebhookErrors   int64     `json:"webhook_errors"`
}

// Issuer is the background assertion generation pipeline.
type Issuer struct {
	store   *store.Store
	builder *assertion.Builder
	cfg     Config
	logger  *slog.Logger

	mu    sync.Mutex
	stats Stats
}

// New creates a new Issuer.
func New(s *store.Store, logOrigin string, cfg Config, logger *slog.Logger) *Issuer {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.StalenessThreshold <= 0 {
		cfg.StalenessThreshold = 5
	}

	return &Issuer{
		store:   s,
		builder: assertion.NewBuilder(s, logOrigin),
		cfg:     cfg,
		logger:  logger,
	}
}

// RunOnCheckpoint is called after a new checkpoint is created.
// It marks stale bundles, generates new assertions, and fires webhooks.
func (iss *Issuer) RunOnCheckpoint(ctx context.Context, checkpointID int64, treeSize int64) {
	if !iss.cfg.Enabled {
		return
	}

	start := time.Now()
	iss.logger.Info("assertion issuer: starting generation cycle",
		"checkpoint_id", checkpointID,
		"tree_size", treeSize,
	)

	// Step 1: Mark stale bundles (proofs for smaller tree sizes are now outdated).
	staleCount, err := iss.store.MarkStaleBundles(ctx, treeSize)
	if err != nil {
		iss.logger.Error("assertion issuer: mark stale", "error", err)
	} else if staleCount > 0 {
		iss.logger.Info("assertion issuer: marked stale bundles", "count", staleCount)
	}

	// Step 2: Generate bundles for entries without fresh ones.
	generated := iss.generatePending(ctx, checkpointID)

	// Step 3: Refresh stale bundles.
	refreshed := iss.refreshStale(ctx, checkpointID)

	duration := time.Since(start)

	iss.mu.Lock()
	iss.stats.LastRunTime = start
	iss.stats.LastRunDuration = duration.String()
	iss.mu.Unlock()

	iss.logger.Info("assertion issuer: generation cycle complete",
		"generated", generated,
		"refreshed", refreshed,
		"duration", duration,
	)

	// Step 4: Fire webhooks for newly generated bundles.
	if len(iss.cfg.Webhooks) > 0 && (generated > 0 || refreshed > 0) {
		iss.fireWebhooks(ctx, checkpointID, generated+refreshed)
	}

	// Emit event.
	_ = iss.store.EmitEvent(ctx, "assertions_generated", map[string]interface{}{
		"checkpoint_id": checkpointID,
		"tree_size":     treeSize,
		"generated":     generated,
		"refreshed":     refreshed,
		"stale_marked":  staleCount,
		"duration_ms":   duration.Milliseconds(),
	})
}

func (iss *Issuer) generatePending(ctx context.Context, checkpointID int64) int64 {
	indices, err := iss.store.ListPendingEntries(ctx, iss.cfg.BatchSize)
	if err != nil {
		iss.logger.Error("assertion issuer: list pending", "error", err)
		return 0
	}
	if len(indices) == 0 {
		return 0
	}

	iss.logger.Info("assertion issuer: generating pending bundles", "count", len(indices))
	return iss.buildAndStore(ctx, indices, checkpointID)
}

func (iss *Issuer) refreshStale(ctx context.Context, checkpointID int64) int64 {
	indices, err := iss.store.ListStaleBundles(ctx, iss.cfg.BatchSize)
	if err != nil {
		iss.logger.Error("assertion issuer: list stale", "error", err)
		return 0
	}
	if len(indices) == 0 {
		return 0
	}

	iss.logger.Info("assertion issuer: refreshing stale bundles", "count", len(indices))
	return iss.buildAndStore(ctx, indices, checkpointID)
}

func (iss *Issuer) buildAndStore(ctx context.Context, indices []int64, checkpointID int64) int64 {
	type result struct {
		bundle *store.AssertionBundle
		err    error
		idx    int64
	}

	sem := make(chan struct{}, iss.cfg.Concurrency)
	results := make(chan result, len(indices))

	var wg sync.WaitGroup
	for _, idx := range indices {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ab, err := iss.buildOne(ctx, i, checkpointID)
			results <- result{bundle: ab, err: err, idx: i}
		}(idx)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var bundles []*store.AssertionBundle
	var errCount int64
	for r := range results {
		if r.err != nil {
			iss.logger.Error("assertion issuer: build failed",
				"entry_idx", r.idx, "error", r.err)
			errCount++
			continue
		}
		bundles = append(bundles, r.bundle)
	}

	if len(bundles) == 0 {
		return 0
	}

	if err := iss.store.UpsertAssertionBundles(ctx, bundles); err != nil {
		iss.logger.Error("assertion issuer: batch store failed", "error", err)
		iss.mu.Lock()
		iss.stats.TotalErrors += int64(len(bundles))
		iss.mu.Unlock()
		return 0
	}

	iss.mu.Lock()
	iss.stats.TotalGenerated += int64(len(bundles))
	iss.stats.TotalErrors += errCount
	iss.mu.Unlock()

	return int64(len(bundles))
}

func (iss *Issuer) buildOne(ctx context.Context, entryIdx int64, checkpointID int64) (*store.AssertionBundle, error) {
	bundle, err := iss.builder.BuildByIndex(ctx, entryIdx)
	if err != nil {
		return nil, fmt.Errorf("build index %d: %w", entryIdx, err)
	}

	bundleJSON, err := assertion.FormatJSON(bundle)
	if err != nil {
		return nil, fmt.Errorf("format JSON index %d: %w", entryIdx, err)
	}

	bundlePEM, err := assertion.FormatPEM(bundle)
	if err != nil {
		return nil, fmt.Errorf("format PEM index %d: %w", entryIdx, err)
	}

	return &store.AssertionBundle{
		EntryIdx:     entryIdx,
		SerialHex:    bundle.SerialHex,
		CheckpointID: checkpointID,
		TreeSize:     bundle.TreeSize,
		BundleJSON:   json.RawMessage(bundleJSON),
		BundlePEM:    string(bundlePEM),
		Stale:        false,
	}, nil
}

func (iss *Issuer) fireWebhooks(ctx context.Context, checkpointID int64, count int64) {
	payload := map[string]interface{}{
		"event":         "assertions_ready",
		"checkpoint_id": checkpointID,
		"count":         count,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		iss.logger.Error("assertion issuer: marshal webhook payload", "error", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, wh := range iss.cfg.Webhooks {
		go func(webhook WebhookConfig) {
			iss.sendWebhook(ctx, client, webhook, body)
		}(wh)
	}
}

func (iss *Issuer) sendWebhook(ctx context.Context, client *http.Client, wh WebhookConfig, body []byte) {
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, jsonReader(body))
		if err != nil {
			iss.logger.Error("assertion issuer: create webhook request", "url", wh.URL, "error", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-MTC-Event", "assertions_ready")

		if wh.Secret != "" {
			sig := hmacSign(wh.Secret, body)
			req.Header.Set("X-MTC-Signature", sig)
		}

		resp, err := client.Do(req)
		if err != nil {
			iss.logger.Warn("assertion issuer: webhook failed",
				"url", wh.URL, "attempt", attempt, "error", err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 2 * time.Second)
				continue
			}
			iss.mu.Lock()
			iss.stats.WebhookErrors++
			iss.mu.Unlock()
			return
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			iss.mu.Lock()
			iss.stats.WebhooksSent++
			iss.mu.Unlock()
			iss.logger.Info("assertion issuer: webhook sent", "url", wh.URL)
			return
		}

		iss.logger.Warn("assertion issuer: webhook non-2xx",
			"url", wh.URL, "status", resp.StatusCode, "attempt", attempt)
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}

	iss.mu.Lock()
	iss.stats.WebhookErrors++
	iss.mu.Unlock()
}

// GetStats returns current issuer statistics.
func (iss *Issuer) GetStats() Stats {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	return iss.stats
}
