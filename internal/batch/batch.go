// Package batch implements batch accumulation and multi-cosigner subtree signing
// for the MTC issuance log per the MTC spec §5.4.
package batch

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/briantrzupek/ca-extension-merkle/internal/cosigner"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Batcher signs subtrees of the Merkle tree using one or more cosigners.
type Batcher struct {
	store     *store.Store
	cosigners []*cosigner.Cosigner
	logID     []byte
	logger    *slog.Logger
}

// BatchResult contains the result of processing a batch.
type BatchResult struct {
	Start       int64
	End         int64
	SubtreeHash merkle.Hash
	Signatures  []mtcformat.MTCSignature
}

// New creates a new Batcher.
func New(s *store.Store, cosigners []*cosigner.Cosigner, logID []byte, logger *slog.Logger) *Batcher {
	return &Batcher{
		store:     s,
		cosigners: cosigners,
		logID:     logID,
		logger:    logger,
	}
}

// ProcessBatch signs the subtree [batchStart, currentTreeSize) with all cosigners.
// Returns the batch result including all cosigner signatures.
func (b *Batcher) ProcessBatch(ctx context.Context, batchStart int64) (*BatchResult, error) {
	treeSize, err := b.store.TreeSize(ctx)
	if err != nil {
		return nil, fmt.Errorf("batch: tree size: %w", err)
	}

	if batchStart >= treeSize {
		return nil, fmt.Errorf("batch: batchStart (%d) >= treeSize (%d)", batchStart, treeSize)
	}

	// Compute the subtree hash for [batchStart, treeSize).
	subtreeHash, err := b.computeSubtreeHash(ctx, batchStart, treeSize)
	if err != nil {
		return nil, fmt.Errorf("batch: compute subtree hash: %w", err)
	}

	// Sign with all cosigners.
	var sigs []mtcformat.MTCSignature
	for _, cs := range b.cosigners {
		sig, err := cs.SignSubtreeMTC(b.logID, batchStart, treeSize, subtreeHash)
		if err != nil {
			b.logger.Warn("batch: cosigner sign failed",
				"cosigner_id", cs.CosignerID(),
				"algorithm", cs.Algorithm(),
				"error", err,
			)
			continue
		}
		sigs = append(sigs, sig)
	}

	if len(sigs) == 0 && len(b.cosigners) > 0 {
		return nil, fmt.Errorf("batch: all cosigners failed to sign")
	}

	b.logger.Info("batch processed",
		"start", batchStart,
		"end", treeSize,
		"signatures", len(sigs),
	)

	return &BatchResult{
		Start:       batchStart,
		End:         treeSize,
		SubtreeHash: subtreeHash,
		Signatures:  sigs,
	}, nil
}

// BuildProof builds an MTCProof for a leaf at the given index, using the batch
// result for subtree signatures and computing the inclusion proof from the tree.
func (b *Batcher) BuildProof(ctx context.Context, leafIdx int64, batch *BatchResult) (*mtcformat.MTCProof, error) {
	if leafIdx < batch.Start || leafIdx >= batch.End {
		return nil, fmt.Errorf("batch: leaf %d not in batch [%d, %d)", leafIdx, batch.Start, batch.End)
	}

	// Compute inclusion proof.
	nodeAt := func(level int, idx int64) merkle.Hash {
		h, _ := b.store.GetTreeNode(ctx, level, idx)
		return h
	}
	proofHashes, err := merkle.InclusionProofFromNodes(leafIdx, batch.End, nodeAt)
	if err != nil {
		return nil, fmt.Errorf("batch: inclusion proof: %w", err)
	}

	proofBytes := make([][]byte, len(proofHashes))
	for i, h := range proofHashes {
		ph := make([]byte, merkle.HashSize)
		copy(ph, h[:])
		proofBytes[i] = ph
	}

	return &mtcformat.MTCProof{
		Start:          uint64(batch.Start),
		End:            uint64(batch.End),
		InclusionProof: proofBytes,
		Signatures:     batch.Signatures,
	}, nil
}

// computeSubtreeHash computes the Merkle tree hash for the range [start, end).
func (b *Batcher) computeSubtreeHash(ctx context.Context, start, end int64) (merkle.Hash, error) {
	n := end - start
	if n <= 0 {
		return merkle.Hash{}, fmt.Errorf("empty range")
	}
	if n == 1 {
		return b.store.GetTreeNode(ctx, 0, start)
	}

	// Find largest power of 2 < n.
	k := int64(1)
	for k*2 < n {
		k *= 2
	}

	left, err := b.computeSubtreeHash(ctx, start, start+k)
	if err != nil {
		return merkle.Hash{}, err
	}
	right, err := b.computeSubtreeHash(ctx, start+k, end)
	if err != nil {
		return merkle.Hash{}, err
	}

	return merkle.InteriorHash(left, right), nil
}
