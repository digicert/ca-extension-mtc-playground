// Package issuancelog manages the MTC issuance log: constructing log entries
// from certificates, appending them to the store, and maintaining the
// incremental Merkle tree.
package issuancelog

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/cadb"
	"github.com/briantrzupek/ca-extension-merkle/internal/cosigner"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Entry type constants matching the MTC spec.
const (
	EntryTypeNull        int16 = 0 // null sentinel at index 0
	EntryTypeCertificate int16 = 1 // X.509 certificate (full DER)
	EntryTypePrecert     int16 = 2 // pre-certificate (canonical TBSCertificate DER)
	EntryTypeMTC         int16 = 3 // MerkleTreeCertEntry with TBSCertificateLogEntry
)

// Log manages the issuance log lifecycle.
type Log struct {
	store    *store.Store
	cosigner *cosigner.Cosigner
	logger   *slog.Logger
	origin   string
}

// New creates a new issuance Log.
func New(s *store.Store, cs *cosigner.Cosigner, origin string, logger *slog.Logger) *Log {
	return &Log{
		store:    s,
		cosigner: cs,
		logger:   logger,
		origin:   origin,
	}
}

// Initialize ensures the log has a null entry at index 0.
func (l *Log) Initialize(ctx context.Context) error {
	size, err := l.store.TreeSize(ctx)
	if err != nil {
		return fmt.Errorf("issuancelog.Initialize: tree size: %w", err)
	}
	if size > 0 {
		l.logger.Info("log already initialized", "tree_size", size)
		return nil
	}

	nullData := make([]byte, 2)
	entry := &store.LogEntry{
		Index:     0,
		EntryType: EntryTypeNull,
		EntryData: nullData,
	}

	if err := l.store.AppendEntry(ctx, entry); err != nil {
		return fmt.Errorf("issuancelog.Initialize: append null entry: %w", err)
	}

	leafHash := merkle.LeafHash(nullData)
	if err := l.store.SetTreeNode(ctx, 0, 0, leafHash); err != nil {
		return fmt.Errorf("issuancelog.Initialize: set leaf hash: %w", err)
	}

	l.logger.Info("log initialized with null entry at index 0")
	return nil
}

// BuildEntry constructs a log entry from a CA certificate.
func BuildEntry(cert *cadb.Certificate) *store.LogEntry {
	certHash := cert.CertSHA256()
	data := make([]byte, 2+4+len(cert.CertBlob))
	binary.LittleEndian.PutUint16(data[0:2], uint16(EntryTypeCertificate))
	binary.LittleEndian.PutUint32(data[2:6], uint32(len(cert.CertBlob)))
	copy(data[6:], cert.CertBlob)

	return &store.LogEntry{
		EntryType:  EntryTypeCertificate,
		EntryData:  data,
		CertSHA256: certHash[:],
		SerialHex:  cert.SerialNumber,
		CACertID:   cert.IssuerID,
	}
}

// BuildPrecertEntry constructs a log entry from a canonical TBSCertificate DER.
// This is used by the local CA flow where the TBSCertificate (without MTC
// extension) is the canonical form hashed into the tree.
func BuildPrecertEntry(tbsDER []byte, serialHex string) *store.LogEntry {
	certHash := sha256.Sum256(tbsDER)
	data := make([]byte, 2+4+len(tbsDER))
	binary.LittleEndian.PutUint16(data[0:2], uint16(EntryTypePrecert))
	binary.LittleEndian.PutUint32(data[2:6], uint32(len(tbsDER)))
	copy(data[6:], tbsDER)

	return &store.LogEntry{
		EntryType:  EntryTypePrecert,
		EntryData:  data,
		CertSHA256: certHash[:],
		SerialHex:  serialHex,
		CACertID:   "local-ca",
	}
}

// BuildMTCEntry constructs a spec-compliant log entry from a TBSCertificateLogEntry DER.
// The entry data is a MerkleTreeCertEntry (1-byte type + 3-byte length + DER).
// This is what gets leaf-hashed and appended to the Merkle tree in MTC mode.
func BuildMTCEntry(logEntryDER []byte, serialHex string) (*store.LogEntry, error) {
	entry := &mtcformat.MerkleTreeCertEntry{
		Type: mtcformat.EntryTypeTBSCert,
		Data: logEntryDER,
	}
	wireData, err := mtcformat.MarshalEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("issuancelog.BuildMTCEntry: marshal: %w", err)
	}

	certHash := sha256.Sum256(logEntryDER)
	return &store.LogEntry{
		EntryType:  EntryTypeMTC,
		EntryData:  wireData,
		CertSHA256: certHash[:],
		SerialHex:  serialHex,
		CACertID:   "local-ca",
	}, nil
}

// AppendDirectEntry appends a single entry directly to the log, updates the
// Merkle tree, and returns the leaf index. This is used by the local CA flow
// where entries bypass the watcher.
func (l *Log) AppendDirectEntry(ctx context.Context, entry *store.LogEntry) (int64, error) {
	currentSize, err := l.store.TreeSize(ctx)
	if err != nil {
		return 0, fmt.Errorf("issuancelog.AppendDirectEntry: tree size: %w", err)
	}

	entry.Index = currentSize
	if err := l.store.AppendEntry(ctx, entry); err != nil {
		return 0, fmt.Errorf("issuancelog.AppendDirectEntry: append: %w", err)
	}

	leafHash := merkle.LeafHash(entry.EntryData)
	if err := l.store.SetTreeNode(ctx, 0, currentSize, leafHash); err != nil {
		return 0, fmt.Errorf("issuancelog.AppendDirectEntry: set leaf: %w", err)
	}

	newSize := currentSize + 1
	if err := l.recomputeInterior(ctx, currentSize, newSize); err != nil {
		return 0, fmt.Errorf("issuancelog.AppendDirectEntry: recompute: %w", err)
	}

	l.logger.Info("appended direct entry",
		"index", currentSize,
		"entry_type", entry.EntryType,
		"serial", entry.SerialHex,
	)

	return currentSize, nil
}

// Store returns the underlying store (needed by the ACME server to build proofs).
func (l *Log) Store() *store.Store {
	return l.store
}

// AppendCertificates processes a batch of certificates: builds entries, appends
// them to the log, and updates the Merkle tree.
func (l *Log) AppendCertificates(ctx context.Context, certs []*cadb.Certificate) (int, int64, error) {
	if len(certs) == 0 {
		size, err := l.store.TreeSize(ctx)
		return 0, size, err
	}

	currentSize, err := l.store.TreeSize(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("issuancelog.AppendCertificates: tree size: %w", err)
	}

	entries := make([]*store.LogEntry, len(certs))
	leafHashes := make([]merkle.Hash, len(certs))

	for i, cert := range certs {
		entry := BuildEntry(cert)
		entry.Index = currentSize + int64(i)
		entries[i] = entry
		leafHashes[i] = merkle.LeafHash(entry.EntryData)
	}

	if err := l.store.AppendEntries(ctx, entries); err != nil {
		return 0, currentSize, fmt.Errorf("issuancelog.AppendCertificates: append: %w", err)
	}

	nodes := make([]store.TreeNode, len(leafHashes))
	for i, h := range leafHashes {
		nodes[i] = store.TreeNode{
			Level: 0,
			Index: currentSize + int64(i),
			Hash:  h,
		}
	}

	if err := l.store.SetTreeNodes(ctx, nodes); err != nil {
		return 0, currentSize, fmt.Errorf("issuancelog.AppendCertificates: set leaf hashes: %w", err)
	}

	newSize := currentSize + int64(len(certs))

	if err := l.recomputeInterior(ctx, currentSize, newSize); err != nil {
		return 0, currentSize, fmt.Errorf("issuancelog.AppendCertificates: recompute: %w", err)
	}

	l.logger.Info("appended certificates",
		"count", len(certs),
		"old_size", currentSize,
		"new_size", newSize,
	)

	return len(certs), newSize, nil
}

// recomputeInterior recomputes interior Merkle tree nodes from bottom up
// after leaves in [oldSize, newSize) were added.
func (l *Log) recomputeInterior(ctx context.Context, oldSize, newSize int64) error {
	for level := 1; level < 64; level++ {
		startIdx := oldSize >> uint(level)
		endIdx := (newSize - 1) >> uint(level)

		if startIdx > endIdx {
			break
		}

		var nodes []store.TreeNode
		for idx := startIdx; idx <= endIdx; idx++ {
			leftChild := idx * 2
			rightChild := idx*2 + 1

			left, err := l.store.GetTreeNode(ctx, level-1, leftChild)
			if err != nil {
				continue
			}

			right, err := l.store.GetTreeNode(ctx, level-1, rightChild)
			if err != nil {
				nodes = append(nodes, store.TreeNode{
					Level: level,
					Index: idx,
					Hash:  left,
				})
				continue
			}

			hash := merkle.InteriorHash(left, right)
			nodes = append(nodes, store.TreeNode{
				Level: level,
				Index: idx,
				Hash:  hash,
			})
		}

		if len(nodes) == 0 {
			break
		}

		if err := l.store.SetTreeNodes(ctx, nodes); err != nil {
			return fmt.Errorf("issuancelog: recompute level %d: %w", level, err)
		}
	}

	return nil
}

// CreateCheckpoint creates a signed checkpoint at the current tree size.
func (l *Log) CreateCheckpoint(ctx context.Context) (*store.Checkpoint, error) {
	treeSize, err := l.store.TreeSize(ctx)
	if err != nil {
		return nil, fmt.Errorf("issuancelog.CreateCheckpoint: tree size: %w", err)
	}

	if treeSize == 0 {
		return nil, fmt.Errorf("issuancelog.CreateCheckpoint: log is empty")
	}

	rootHash, err := l.computeRootHash(ctx, treeSize)
	if err != nil {
		return nil, fmt.Errorf("issuancelog.CreateCheckpoint: root hash: %w", err)
	}

	now := time.Now()
	note, sig, err := l.cosigner.SignCheckpoint(treeSize, rootHash, now)
	if err != nil {
		return nil, fmt.Errorf("issuancelog.CreateCheckpoint: sign: %w", err)
	}

	cp := &store.Checkpoint{
		TreeSize:  treeSize,
		RootHash:  rootHash[:],
		Timestamp: now,
		Signature: sig,
		Body:      note,
	}

	if err := l.store.SaveCheckpoint(ctx, cp); err != nil {
		return nil, fmt.Errorf("issuancelog.CreateCheckpoint: save: %w", err)
	}

	l.logger.Info("created checkpoint",
		"tree_size", treeSize,
		"root_hash", fmt.Sprintf("%x", rootHash[:8]),
	)

	return cp, nil
}

// computeRootHash computes the tree root from stored interior nodes.
func (l *Log) computeRootHash(ctx context.Context, treeSize int64) (merkle.Hash, error) {
	if treeSize == 0 {
		return sha256.Sum256(nil), nil
	}
	if treeSize == 1 {
		return l.store.GetTreeNode(ctx, 0, 0)
	}

	maxLevel := 0
	for n := treeSize; n > 1; n = (n + 1) / 2 {
		maxLevel++
	}

	hash, err := l.store.GetTreeNode(ctx, maxLevel, 0)
	if err == nil {
		return hash, nil
	}

	return l.computeMTH(ctx, 0, treeSize)
}

// computeMTH recursively computes the Merkle Tree Hash for [start, start+n).
func (l *Log) computeMTH(ctx context.Context, start, n int64) (merkle.Hash, error) {
	if n == 0 {
		return sha256.Sum256(nil), nil
	}
	if n == 1 {
		return l.store.GetTreeNode(ctx, 0, start)
	}

	k := int64(1)
	for k*2 < n {
		k *= 2
	}

	left, err := l.computeMTH(ctx, start, k)
	if err != nil {
		return merkle.Hash{}, err
	}

	right, err := l.computeMTH(ctx, start+k, n-k)
	if err != nil {
		return merkle.Hash{}, err
	}

	return merkle.InteriorHash(left, right), nil
}

// TreeSize returns the current log size.
func (l *Log) TreeSize(ctx context.Context) (int64, error) {
	return l.store.TreeSize(ctx)
}
