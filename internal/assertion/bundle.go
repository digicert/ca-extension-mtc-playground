// Package assertion builds and verifies MTC assertion bundles.
//
// An assertion bundle is a self-contained proof artifact that accompanies
// an X.509 certificate. It contains the certificate, its inclusion proof
// in the Merkle tree, the signed checkpoint, and parsed certificate metadata.
//
// This is the "post-issuance stapling" approach: certificates are issued
// normally by the CA, then the bridge produces a companion assertion bundle
// that proves the certificate is included in the transparency log.
package assertion

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/certutil"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Bundle is a self-contained MTC assertion bundle for a certificate.
type Bundle struct {
	// Certificate identification
	LeafIndex int64  `json:"leaf_index"`
	SerialHex string `json:"serial_hex,omitempty"`

	// Certificate data (DER-encoded)
	CertDER []byte `json:"cert_der,omitempty"`

	// Parsed certificate metadata
	CertMeta *certutil.CertMeta `json:"cert_meta,omitempty"`

	// Merkle inclusion proof
	LeafHash string   `json:"leaf_hash"`
	Proof    []string `json:"proof"`

	// Checkpoint that anchors the proof
	TreeSize   int64  `json:"tree_size"`
	RootHash   string `json:"root_hash"`
	Checkpoint string `json:"checkpoint"`

	// Revocation status
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// Bundle metadata
	LogOrigin string    `json:"log_origin"`
	CreatedAt time.Time `json:"created_at"`
}

// Builder creates assertion bundles from the store.
type Builder struct {
	store     *store.Store
	logOrigin string
}

// NewBuilder creates a new assertion Builder.
func NewBuilder(s *store.Store, logOrigin string) *Builder {
	return &Builder{
		store:     s,
		logOrigin: logOrigin,
	}
}

// BuildBySerial builds an assertion bundle for a certificate identified by serial number.
func (b *Builder) BuildBySerial(ctx context.Context, serialHex string) (*Bundle, error) {
	idx, err := b.store.FindEntryBySerial(ctx, serialHex)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("certificate with serial %s not found", serialHex)
		}
		return nil, fmt.Errorf("assertion.BuildBySerial: %w", err)
	}
	return b.BuildByIndex(ctx, idx)
}

// BuildByIndex builds an assertion bundle for a certificate at the given log index.
func (b *Builder) BuildByIndex(ctx context.Context, idx int64) (*Bundle, error) {
	// Get entry with revocation status.
	detail, err := b.store.GetEntryDetail(ctx, idx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("entry at index %d not found", idx)
		}
		return nil, fmt.Errorf("assertion.BuildByIndex: get entry: %w", err)
	}

	// Reject null entries.
	if detail.EntryType == 0 {
		return nil, fmt.Errorf("entry at index %d is a null sentinel, not a certificate", idx)
	}

	// Get latest checkpoint.
	cp, err := b.store.LatestCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("assertion.BuildByIndex: latest checkpoint: %w", err)
	}

	if idx >= cp.TreeSize {
		return nil, fmt.Errorf("entry index %d >= tree size %d (not yet checkpointed)", idx, cp.TreeSize)
	}

	// Compute leaf hash.
	leafHash := merkle.LeafHash(detail.EntryData)

	// Compute inclusion proof from precomputed tree nodes.
	nodeAt := func(level int, nodeIdx int64) merkle.Hash {
		h, err := b.store.GetTreeNode(ctx, level, nodeIdx)
		if err != nil {
			return merkle.EmptyHash
		}
		return h
	}

	proof, err := merkle.InclusionProofFromNodes(idx, cp.TreeSize, nodeAt)
	if err != nil {
		return nil, fmt.Errorf("assertion.BuildByIndex: inclusion proof: %w", err)
	}

	// Encode proof hashes as hex.
	proofHex := make([]string, len(proof))
	for i, ph := range proof {
		proofHex[i] = hex.EncodeToString(ph[:])
	}

	// Parse certificate metadata and extract DER.
	var certDER []byte
	var certMeta *certutil.CertMeta
	if detail.EntryType == 1 && len(detail.EntryData) > 6 {
		meta, der, err := certutil.ParseLogEntry(detail.EntryData)
		if err == nil {
			certMeta = meta
			certDER = der
		}
	}

	bundle := &Bundle{
		LeafIndex:  idx,
		SerialHex:  detail.SerialHex,
		CertDER:    certDER,
		CertMeta:   certMeta,
		LeafHash:   hex.EncodeToString(leafHash[:]),
		Proof:      proofHex,
		TreeSize:   cp.TreeSize,
		RootHash:   hex.EncodeToString(cp.RootHash),
		Checkpoint: cp.Body,
		Revoked:    detail.Revoked,
		RevokedAt:  detail.RevokedAt,
		LogOrigin:  b.logOrigin,
		CreatedAt:  time.Now().UTC(),
	}

	return bundle, nil
}

// Resolve takes a query string (serial hex or numeric index) and returns the bundle.
func (b *Builder) Resolve(ctx context.Context, query string) (*Bundle, error) {
	// Try as numeric index first.
	if idx, err := strconv.ParseInt(query, 10, 64); err == nil && idx >= 0 {
		return b.BuildByIndex(ctx, idx)
	}
	// Otherwise treat as serial hex.
	return b.BuildBySerial(ctx, query)
}
