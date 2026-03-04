// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package batch

import (
	"context"
	"fmt"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// LandmarkVerifier verifies MTC certificates in signatureless mode
// by checking the subtree root against known landmarks.
type LandmarkVerifier struct {
	store *store.Store
}

// NewLandmarkVerifier creates a LandmarkVerifier backed by the given store.
func NewLandmarkVerifier(s *store.Store) *LandmarkVerifier {
	return &LandmarkVerifier{store: s}
}

// GetLandmarks returns a map of tree_size → root_hash for signatureless verification.
func (v *LandmarkVerifier) GetLandmarks(ctx context.Context) (map[int64]merkle.Hash, error) {
	landmarks, err := v.store.ListLandmarks(ctx)
	if err != nil {
		return nil, fmt.Errorf("landmark: list: %w", err)
	}

	result := make(map[int64]merkle.Hash, len(landmarks))
	for _, lm := range landmarks {
		var h merkle.Hash
		copy(h[:], lm.RootHash)
		result[lm.TreeSize] = h
	}
	return result, nil
}

// DesignateLandmark marks the current tree state as a landmark.
// The landmark's tree_size and root_hash are taken from the latest checkpoint.
func (b *Batcher) DesignateLandmark(ctx context.Context) (*store.Landmark, error) {
	cp, err := b.store.LatestCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("landmark: latest checkpoint: %w", err)
	}

	lm := &store.Landmark{
		TreeSize:     cp.TreeSize,
		RootHash:     cp.RootHash,
		CheckpointID: cp.ID,
	}

	if err := b.store.SaveLandmark(ctx, lm); err != nil {
		return nil, fmt.Errorf("landmark: save: %w", err)
	}

	b.logger.Info("landmark designated",
		"tree_size", lm.TreeSize,
		"checkpoint_id", lm.CheckpointID,
	)

	return lm, nil
}
