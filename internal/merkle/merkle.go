// Package merkle implements RFC 9162 Merkle tree operations for the MTC issuance log.
//
// It provides leaf and interior hashing, Merkle Tree Hash (MTH) computation,
// inclusion and consistency proof generation/verification, tile coordinate
// computation, and subtree operations per draft-ietf-plants-merkle-tree-certs-01.
//
// All hash operations use SHA-256 with domain separation:
//   - Leaf:     SHA-256(0x00 || data)
//   - Interior: SHA-256(0x01 || left || right)
package merkle

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
)

// HashSize is the size of a SHA-256 hash in bytes.
const HashSize = sha256.Size

// TileWidth is the number of hashes per full tile (2^8 = 256).
const TileWidth = 256

// TileWidthBits is log2(TileWidth) = 8.
const TileWidthBits = 8

// Hash is a 32-byte SHA-256 hash.
type Hash [HashSize]byte

// EmptyHash is the zero hash (used as sentinel).
var EmptyHash Hash

// LeafHash computes SHA-256(0x00 || data) per RFC 9162 §2.1.
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// InteriorHash computes SHA-256(0x01 || left || right) per RFC 9162 §2.1.
func InteriorHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

// MTH computes the Merkle Tree Hash for a list of leaf data entries per RFC 9162 §2.1.
// For an empty list, returns SHA-256("") (the empty hash per RFC 9162 §2.1).
func MTH(entries [][]byte) Hash {
	n := len(entries)
	if n == 0 {
		return sha256.Sum256(nil)
	}
	if n == 1 {
		return LeafHash(entries[0])
	}
	// Split at the largest power of two smaller than n.
	k := splitPoint(n)
	left := MTH(entries[:k])
	right := MTH(entries[k:])
	return InteriorHash(left, right)
}

// splitPoint returns the largest power of two smaller than n.
// Requires n > 1.
func splitPoint(n int) int {
	if n < 2 {
		panic("merkle: splitPoint requires n >= 2")
	}
	// Largest power of 2 less than n.
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// InclusionProof computes the inclusion proof for leaf at index in a tree of size.
// Returns the list of sibling hashes needed to recompute the root.
// The hashes parameter provides the leaf hash function: hashes(i) returns LeafHash(entry[i]).
func InclusionProof(index, size int64, hashAt func(idx int64) Hash) ([]Hash, error) {
	if index < 0 || index >= size {
		return nil, fmt.Errorf("merkle.InclusionProof: index %d out of range [0, %d)", index, size)
	}
	if size <= 0 {
		return nil, fmt.Errorf("merkle.InclusionProof: invalid tree size %d", size)
	}
	return inclusionProof(index, 0, size, hashAt), nil
}

func inclusionProof(index, start, end int64, hashAt func(int64) Hash) []Hash {
	n := end - start
	if n == 1 {
		return nil
	}
	k := int64(splitPoint(int(n)))
	var proof []Hash
	if index-start < k {
		proof = inclusionProof(index, start, start+k, hashAt)
		proof = append(proof, computeSubtreeHash(start+k, end, hashAt))
	} else {
		proof = inclusionProof(index, start+k, end, hashAt)
		proof = append(proof, computeSubtreeHash(start, start+k, hashAt))
	}
	return proof
}

// ConsistencyProof computes the consistency proof between old and new tree sizes
// per RFC 9162 §2.1.4.
func ConsistencyProof(oldSize, newSize int64, hashAt func(int64) Hash) ([]Hash, error) {
	if oldSize < 0 || oldSize > newSize {
		return nil, fmt.Errorf("merkle.ConsistencyProof: invalid sizes old=%d new=%d", oldSize, newSize)
	}
	if oldSize == 0 {
		return nil, nil // empty proof for empty old tree
	}
	if oldSize == newSize {
		return nil, nil // same tree
	}
	proof := consistencyProof(oldSize, newSize, 0, true, hashAt)
	return proof, nil
}

func consistencyProof(m, n int64, start int64, openRight bool, hashAt func(int64) Hash) []Hash {
	end := start + n
	if m == n {
		if openRight {
			return nil
		}
		return []Hash{computeSubtreeHash(start, end, hashAt)}
	}
	k := int64(splitPoint(int(n)))
	if m <= k {
		proof := consistencyProof(m, k, start, openRight, hashAt)
		proof = append(proof, computeSubtreeHash(start+k, end, hashAt))
		return proof
	}
	proof := consistencyProof(m-k, n-k, start+k, false, hashAt)
	proof = append(proof, computeSubtreeHash(start, start+k, hashAt))
	return proof
}

// computeSubtreeHash computes the Merkle hash for entries [start, end).
func computeSubtreeHash(start, end int64, hashAt func(int64) Hash) Hash {
	n := end - start
	if n == 1 {
		return hashAt(start)
	}
	k := int64(splitPoint(int(n)))
	left := computeSubtreeHash(start, start+k, hashAt)
	right := computeSubtreeHash(start+k, end, hashAt)
	return InteriorHash(left, right)
}

// VerifyInclusion verifies an inclusion proof for a leaf hash at index in a tree
// with the given root and size.
func VerifyInclusion(leafHash Hash, index, size int64, proof []Hash, root Hash) bool {
	if index < 0 || index >= size {
		return false
	}
	hash := leafHash
	for i, sibling := range proof {
		_ = i
		// Walk up the tree: the bit at each level tells us which side we're on.
		if index%2 == 0 {
			hash = InteriorHash(hash, sibling)
		} else {
			hash = InteriorHash(sibling, hash)
		}
		index /= 2
	}
	return hash == root
}

// RootFromInclusionProof recomputes the root hash from a leaf, its index, tree size, and proof.
func RootFromInclusionProof(index, size int64, leafHash Hash, proof []Hash) Hash {
	return rootFromProof(index, 0, size, leafHash, proof, 0)
}

func rootFromProof(index, start, end int64, leafHash Hash, proof []Hash, proofIdx int) Hash {
	n := end - start
	if n == 1 {
		return leafHash
	}
	if proofIdx >= len(proof) {
		return leafHash
	}
	k := int64(splitPoint(int(n)))
	if index-start < k {
		leftHash := rootFromProof(index, start, start+k, leafHash, proof, proofIdx)
		if proofIdx+pathLen(index-start, k) < len(proof) {
			rightHash := proof[proofIdx+pathLen(index-start, k)]
			return InteriorHash(leftHash, rightHash)
		}
		return leftHash
	}
	rightHash := rootFromProof(index, start+k, end, leafHash, proof, proofIdx)
	if proofIdx+pathLen(index-start-k, n-k) < len(proof) {
		leftHash := proof[proofIdx+pathLen(index-start-k, n-k)]
		return InteriorHash(leftHash, rightHash)
	}
	return rightHash
}

func pathLen(index, size int64) int {
	if size <= 1 {
		return 0
	}
	k := int64(splitPoint(int(size)))
	if index < k {
		return pathLen(index, k) + 1
	}
	return pathLen(index-k, size-k) + 1
}

// TileCoord represents the coordinates of a tile in the tlog-tiles scheme.
type TileCoord struct {
	Level int   // tile level (0 for leaf tiles)
	Index int64 // tile index at this level
	Width int   // number of hashes in this tile (1-256)
}

// TileForEntry returns the tile coordinates for the hash tile containing
// the leaf at the given entry index.
func TileForEntry(index int64) TileCoord {
	return TileCoord{
		Level: 0,
		Index: index / TileWidth,
		Width: TileWidth,
	}
}

// TilesForRange returns all tile coordinates needed to serve entries [start, end)
// at level 0 (leaf tiles).
func TilesForRange(start, end int64) []TileCoord {
	if start >= end {
		return nil
	}
	firstTile := start / TileWidth
	lastTile := (end - 1) / TileWidth
	var tiles []TileCoord
	for t := firstTile; t <= lastTile; t++ {
		tiles = append(tiles, TileCoord{
			Level: 0,
			Index: t,
			Width: TileWidth,
		})
	}
	return tiles
}

// TilePath returns the URL path component for a tile per C2SP tlog-tiles.
// For hash tiles: tile/<L>/<N...>
// For entry tiles: tile/entries/<N...>
// N is encoded as zero-padded 3-digit x-prefixed path segments.
func (tc TileCoord) TilePath() string {
	nPath := encodeTileIndex(tc.Index)
	if tc.Level == -1 {
		// Entry tile
		return "tile/entries/" + nPath
	}
	return fmt.Sprintf("tile/%d/%s", tc.Level, nPath)
}

// encodeTileIndex encodes a tile index as a path with 3-digit segments.
// Examples: 0 → "000", 1 → "001", 256 → "x001/000", 1000 → "x003/232"
func encodeTileIndex(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%03d", n)
	}
	rest := encodeTileIndex(n / 1000)
	return fmt.Sprintf("x%s/%03d", rest, n%1000)
}

// EntryTileCoord returns the tile coordinates for the entry bundle tile
// containing the entry at the given index.
func EntryTileCoord(index int64) TileCoord {
	return TileCoord{
		Level: -1, // sentinel for entry tiles
		Index: index / TileWidth,
		Width: TileWidth,
	}
}

// HashTileCoord returns the tile coordinates for a hash tile at the given
// tree level and node index.
func HashTileCoord(level int, nodeIndex int64) TileCoord {
	return TileCoord{
		Level: level / TileWidthBits,
		Index: nodeIndex / TileWidth,
		Width: TileWidth,
	}
}

// BitCeil returns the smallest power of 2 >= n.
// Per MTC §4.1: BIT_CEIL used for subtree alignment.
func BitCeil(n int64) int64 {
	if n <= 1 {
		return 1
	}
	return 1 << bits.Len64(uint64(n-1))
}

// IsValidSubtree checks if [start, end) is a valid subtree per MTC §4.1.
// A subtree is valid when start is a multiple of BIT_CEIL(end - start).
func IsValidSubtree(start, end int64) bool {
	if start >= end {
		return false
	}
	size := end - start
	alignment := BitCeil(size)
	return start%alignment == 0
}

// SubtreeHash computes the Merkle hash for the subtree [start, end).
func SubtreeHash(start, end int64, hashAt func(int64) Hash) Hash {
	return computeSubtreeHash(start, end, hashAt)
}

// InclusionProofFromNodes computes an inclusion proof using precomputed tree
// node hashes instead of recomputing from raw leaves. The nodeAt callback
// returns the stored hash at (level, index). This is O(log₂ n) node
// retrievals vs O(n) for InclusionProof with leaf-level hashAt.
//
// The proof walks from the target leaf to the root, collecting the sibling
// hash at each level. When the sibling is a complete subtree, nodeAt returns
// the precomputed interior hash directly. When the sibling is a right-edge
// partial subtree, the function computes it recursively from stored nodes.
func InclusionProofFromNodes(index, size int64, nodeAt func(level int, idx int64) Hash) ([]Hash, error) {
	if index < 0 || index >= size {
		return nil, fmt.Errorf("merkle.InclusionProofFromNodes: index %d out of range [0, %d)", index, size)
	}
	if size <= 0 {
		return nil, fmt.Errorf("merkle.InclusionProofFromNodes: invalid tree size %d", size)
	}
	return inclusionProofFromNodes(index, 0, size, 0, nodeAt), nil
}

func inclusionProofFromNodes(index, start, end int64, level int, nodeAt func(int, int64) Hash) []Hash {
	n := end - start
	if n == 1 {
		return nil
	}
	k := int64(splitPoint(int(n)))
	var proof []Hash
	if index-start < k {
		// Target is in the left subtree; sibling is the right subtree [start+k, end).
		proof = inclusionProofFromNodes(index, start, start+k, level, nodeAt)
		proof = append(proof, subtreeHashFromNodes(start+k, end, level, nodeAt))
	} else {
		// Target is in the right subtree; sibling is the left subtree [start, start+k).
		proof = inclusionProofFromNodes(index, start+k, end, level, nodeAt)
		proof = append(proof, subtreeHashFromNodes(start, start+k, level, nodeAt))
	}
	return proof
}

// subtreeHashFromNodes computes the Merkle hash for [start, end) at the given
// base level using precomputed nodes. For complete power-of-two subtrees, it
// reads a single stored node. For right-edge partial subtrees, it recurses.
func subtreeHashFromNodes(start, end int64, level int, nodeAt func(int, int64) Hash) Hash {
	n := end - start
	if n == 1 {
		return nodeAt(level, start)
	}
	// If n is a power of 2, the subtree hash is stored at a higher level.
	if n&(n-1) == 0 {
		// n = 2^h leaves → stored at level+h.
		h := bits.TrailingZeros64(uint64(n))
		storageIdx := start >> uint(h)
		return nodeAt(level+h, storageIdx)
	}
	// Partial subtree (right edge of tree): recurse.
	k := int64(splitPoint(int(n)))
	left := subtreeHashFromNodes(start, start+k, level, nodeAt)
	right := subtreeHashFromNodes(start+k, end, level, nodeAt)
	return InteriorHash(left, right)
}
