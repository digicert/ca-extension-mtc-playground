// Package revocation manages MTC revocation-by-index tracking.
//
// Per draft-ietf-plants-merkle-tree-certs-01 section 7.5, revocation is tracked by
// log entry index rather than serial number. This package maps CA revocation
// events to log indices and maintains the revocation set.
package revocation

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/cadb"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Manager handles revocation tracking.
type Manager struct {
	store  *store.Store
	logger *slog.Logger
}

// New creates a new revocation Manager.
func New(s *store.Store, logger *slog.Logger) *Manager {
	return &Manager{store: s, logger: logger}
}

// ProcessRevocations takes revocation events from the CA database and maps them
// to log entry indices. Returns the number of new revocations recorded.
func (m *Manager) ProcessRevocations(ctx context.Context, events []*cadb.RevocationEvent) (int, error) {
	recorded := 0
	for _, ev := range events {
		// Look up the log entry index for this certificate's serial number.
		idx, err := m.store.FindEntryBySerial(ctx, ev.SerialNumber)
		if err != nil {
			m.logger.Warn("revocation: cert not in log",
				"serial", ev.SerialNumber,
				"cert_id", ev.CertID,
			)
			continue
		}

		rev := &store.RevokedIndex{
			EntryIdx:  idx,
			SerialHex: ev.SerialNumber,
			RevokedAt: ev.RevokedDate,
			Reason:    int16(ev.RevokedReason),
		}

		if err := m.store.AddRevocation(ctx, rev); err != nil {
			return recorded, fmt.Errorf("revocation.ProcessRevocations: %w", err)
		}
		recorded++

		m.logger.Info("recorded revocation",
			"serial", ev.SerialNumber,
			"entry_idx", idx,
			"reason", ev.RevokedReason,
		)
	}

	if recorded > 0 {
		if err := m.store.EmitEvent(ctx, "revocation_batch", map[string]interface{}{
			"count":     recorded,
			"timestamp": time.Now().UTC(),
		}); err != nil {
			m.logger.Error("failed to emit revocation event", "error", err)
		}
	}

	return recorded, nil
}

// GetRevokedIndices returns all revoked entry indices sorted ascending.
func (m *Manager) GetRevokedIndices(ctx context.Context) ([]int64, error) {
	indices, err := m.store.GetRevokedIndices(ctx)
	if err != nil {
		return nil, fmt.Errorf("revocation.GetRevokedIndices: %w", err)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	return indices, nil
}

// BuildRevocationBitmap creates a compact bitmap of revoked indices for a given
// tree size. Bit i is set if entry i is revoked. Returns the bitmap as a byte
// slice (big-endian bit order).
func (m *Manager) BuildRevocationBitmap(ctx context.Context, treeSize int64) ([]byte, error) {
	indices, err := m.GetRevokedIndices(ctx)
	if err != nil {
		return nil, err
	}

	if treeSize == 0 {
		return nil, nil
	}

	// Bitmap: ceil(treeSize/8) bytes.
	bitmapLen := (treeSize + 7) / 8
	bitmap := make([]byte, bitmapLen)

	for _, idx := range indices {
		if idx >= treeSize {
			continue
		}
		byteIdx := idx / 8
		bitIdx := uint(7 - idx%8) // big-endian bit order
		bitmap[byteIdx] |= 1 << bitIdx
	}

	return bitmap, nil
}

// Count returns the total number of revocations.
func (m *Manager) Count(ctx context.Context) (int64, error) {
	return m.store.RevocationCount(ctx)
}
