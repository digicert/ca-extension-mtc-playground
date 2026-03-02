// Package mtcformat implements the wire format encodings defined in the
// Merkle Tree Certificates specification (draft-ietf-plants-merkle-tree-certs).
//
// It provides binary encoding/decoding for:
//   - MerkleTreeCertEntry (leaf wrapper for tree hashing)
//   - MTCProof (the structure that replaces traditional signatures)
//   - TBSCertificateLogEntry (the ASN.1 structure hashed into the tree)
package mtcformat

import "encoding/asn1"

// OIDMTCProof is id-alg-mtcProof per the MTC specification (§6.1).
// This OID replaces traditional signature algorithm OIDs (ECDSA, RSA, etc.)
// in MTC certificates. The signatureValue field contains an MTCProof
// structure instead of a cryptographic signature.
//
// Experimental OID arc: 1.3.6.1.4.1.44363.47.0
var OIDMTCProof = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
