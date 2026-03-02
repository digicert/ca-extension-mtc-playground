# MTC Spec Compliance Analysis

## Reference: draft-ietf-plants-merkle-tree-certs-01

Adopted by the IETF **PLANTS** (PKI, Logs, And Tree Signatures) working group.
Formerly: `draft-davidben-tls-merkle-tree-certs-10`.

Sources:
- IETF Draft: https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/
- Google Security Blog (Feb 2026): https://security.googleblog.com/2026/02/cultivating-robust-and-efficient.html
- Cloudflare implementation blog: https://blog.cloudflare.com/bootstrap-mtc/

---

## Core Concept: Signatureless Certificates

MTC fundamentally replaces per-certificate signatures with **batch signing**:

1. The CA accumulates certificates into a Merkle tree
2. The CA (and cosigners) sign a single **tree head / subtree** covering potentially millions of certs
3. Each certificate carries an **inclusion proof** to that signed subtree — not its own signature
4. For up-to-date relying parties with predistributed **landmarks**, even the subtree signatures are omitted

This solves the post-quantum bandwidth problem: ML-DSA-65 signatures are 3,309 bytes, but with MTC, one signature covers millions of certs. Individual certs carry only ~736 bytes of inclusion proof.

---

## Key Data Structures

### 1. TBSCertificateLogEntry (§5.3) — What Gets Hashed Into the Tree

```asn1
TBSCertificateLogEntry ::= SEQUENCE {
    version                  [0] EXPLICIT Version DEFAULT v1,
    issuer                   Name,
    validity                 Validity,
    subject                  Name,
    subjectPublicKeyInfoHash OCTET STRING,   -- SHA-256(SubjectPublicKeyInfo DER)
    issuerUniqueID           [1] IMPLICIT UniqueIdentifier OPTIONAL,
    subjectUniqueID          [2] IMPLICIT UniqueIdentifier OPTIONAL,
    extensions               [3] EXPLICIT Extensions OPTIONAL
}
```

**Critical difference from X.509 TBSCertificate:**
- Uses `subjectPublicKeyInfoHash` (32 bytes) instead of full `subjectPublicKeyInfo` (variable, ~91 bytes for P-256, ~1952 bytes for ML-DSA-65)
- No `serialNumber` field — the serial is derived from the leaf index
- No `signature` algorithm field — the log entry format is fixed

### 2. MerkleTreeCertEntry (§5.3) — Leaf Wrapper

TLS presentation language (binary, NOT ASN.1):
```
enum { null_entry(0), tbs_cert_entry(1), (2^16-1) } MerkleTreeCertEntryType;

struct {
    MerkleTreeCertEntryType type;  // 1 byte
    select (type) {
        case null_entry: Empty;
        case tbs_cert_entry: opaque tbs_cert_entry_data<1..2^24-1>;
    }
} MerkleTreeCertEntry;
```

- Entry 0 MUST be `null_entry` (just a zero byte)
- All others: type=1 + 3-byte length prefix + DER of TBSCertificateLogEntry
- Leaf hash: `SHA-256(0x00 || MerkleTreeCertEntry_bytes)` per RFC 9162

### 3. id-alg-mtcProof (§6.1) — Signature Algorithm OID

```
OID: 1.3.6.1.4.1.44363.47.0 (experimental)
```

This replaces ECDSA/RSA/Ed25519 as the `signatureAlgorithm` in the X.509 Certificate structure. The `signatureValue` field contains an MTCProof instead of a cryptographic signature.

### 4. MTCProof (§6.1) — The "Signature" Replacement

TLS presentation language (binary):
```
struct {
    uint64 start;                               // subtree start index
    uint64 end;                                 // subtree end index
    opaque inclusion_proof<0..2^16-1>;          // array of 32-byte hashes
    MTCSignature signatures<0..2^16-1>;         // cosigner signatures (empty for signatureless)
} MTCProof;

struct {
    uint16 cosigner_id;                         // numeric cosigner identifier
    opaque signature<0..2^16-1>;                // raw signature bytes
} MTCSignature;
```

**Two modes:**
- **Signed mode**: `signatures` contains cosigner signatures over the subtree → any party can verify
- **Signatureless mode**: `signatures` is empty → relying party uses predistributed landmark to verify

### 5. Final Certificate Structure

The MTC certificate is a standard X.509 Certificate DER with:
- `TBSCertificate.serialNumber` = leaf index (zero-based, so first real cert = 1)
- `TBSCertificate.signature` = `AlgorithmIdentifier { id-alg-mtcProof }` (per X.509, must match outer)
- `TBSCertificate.issuer` = log's distinguished name
- `TBSCertificate.subjectPublicKeyInfo` = full SPKI (not hashed — only the log entry uses the hash)
- `signatureAlgorithm` = `AlgorithmIdentifier { id-alg-mtcProof }`
- `signatureValue` = BIT STRING wrapping MTCProof bytes

### 6. MTCSubtreeSignatureInput (§5.4.1) — What Cosigners Sign

```
struct {
    uint8 label[16] = "mtc-subtree/v1\n\0";    // fixed 16-byte label
    uint16 cosigner_id;                          // signing cosigner's ID
    TrustAnchorID log_id;                        // log identifier
    uint64 start;
    uint64 end;
    HashValue hash;                              // 32-byte subtree hash
} MTCSubtreeSignatureInput;
```

---

## Signature Algorithms for Cosigners (§5.4.2)

| Algorithm | Public Key | Signature | Security Level |
|-----------|-----------|-----------|----------------|
| Ed25519 | 32 bytes | 64 bytes | ~128-bit |
| ECDSA P-256 | 64 bytes | ~72 bytes | ~128-bit |
| ECDSA P-384 | 96 bytes | ~104 bytes | ~192-bit |
| ML-DSA-44 | 1,312 bytes | 2,420 bytes | NIST Level 2 |
| ML-DSA-65 | 1,952 bytes | 3,309 bytes | NIST Level 3 |
| ML-DSA-87 | 2,592 bytes | 4,627 bytes | NIST Level 5 |

ML-DSA (FIPS 204) is the post-quantum signature algorithm. The key insight: these large signatures are amortized across millions of certs because cosigners sign subtrees, not individual certificates.

---

## Batch/Window Model

1. CA accumulates certificate issuances
2. Periodically (e.g., every 60s or after N entries), CA creates a **checkpoint**
3. CA identifies **subtrees** covering entries added since last checkpoint
4. Cosigners sign each subtree using MTCSubtreeSignatureInput
5. Individual certificates get inclusion proofs relative to these subtrees

Subtrees use half-open intervals `[start, end)` where `start` is aligned to `BIT_CEIL(end - start)`.

## Landmark / Predistribution Model (§6.3)

1. Periodically (e.g., every hour), the CA designates the current tree size as a **landmark**
2. Landmark subtree hashes + cosigner signatures are predistributed to relying parties (browsers)
3. Certificates issued between landmarks can use **signatureless mode**:
   - MTCProof contains inclusion proof to the landmark subtree
   - `signatures` array is empty
   - Relying party verifies against its cached landmark hash
4. If relying party doesn't have the landmark → fall back to signed mode

---

## Verification (§7)

### Signed Mode
1. Parse certificate → extract MTCProof from `signatureValue`
2. Reconstruct TBSCertificateLogEntry from cert fields (hash the SPKI)
3. Wrap in MerkleTreeCertEntry { type=1, data=logEntryDER }
4. Compute leaf hash: `SHA-256(0x00 || entryBytes)`
5. Verify inclusion proof against subtree `[start, end)`
6. Verify at least one cosigner signature over the subtree hash

### Signatureless Mode
1-4. Same as above
5. Verify inclusion proof against a **landmark** subtree
6. Relying party trusts the landmark (predistributed with cosigner signatures verified out-of-band)

---

## Gap Analysis: Current Implementation vs. Spec

| Aspect | Current (Phase 5) | Required by Spec | Gap |
|--------|-------------------|-------------------|-----|
| Signature algorithm | ECDSA P-256 per cert | `id-alg-mtcProof` (no per-cert sig) | **MAJOR** |
| Proof location | X.509 extension (OID 99999.1.1) | `signatureValue` field | **MAJOR** |
| Proof encoding | ASN.1 `SEQUENCE` | TLS presentation language (binary) | **MAJOR** |
| Log entry format | Raw TBSCertificate DER | TBSCertificateLogEntry (SPKI hash) | **MAJOR** |
| Serial number | Random | Leaf index | **MAJOR** |
| Entry type | LE uint16 (custom) | MerkleTreeCertEntry (spec-defined) | MODERATE |
| Cosigner algorithms | Ed25519 only | Ed25519 + ML-DSA-44/65/87 | **MAJOR** |
| Subtree signing format | Custom (start‖end‖hash) | MTCSubtreeSignatureInput (with label) | MODERATE |
| Batch model | Immediate (batch of 1) | Configurable window | MODERATE |
| Landmarks | Not implemented | Required for signatureless | NEW |
| Cosigner model | Single cosigner | Multiple cosigners | MODERATE |
| Tree hash | SHA-256 (RFC 9162) | SHA-256 (RFC 9162) | **COMPLIANT** |
| Leaf hash | SHA-256(0x00‖data) | SHA-256(0x00‖data) | **COMPLIANT** |
| Interior hash | SHA-256(0x01‖L‖R) | SHA-256(0x01‖L‖R) | **COMPLIANT** |
| Inclusion proofs | RFC 9162 §2.1.5 | RFC 9162 §2.1.5 | **COMPLIANT** |
| Consistency proofs | RFC 9162 §2.1.4 | RFC 9162 §2.1.4 | **COMPLIANT** |
| tlog-tiles API | C2SP compliant | C2SP compliant | **COMPLIANT** |

**Summary**: Merkle tree operations, hashing, and proof computation are fully compliant. The certificate format, signing model, log entry structure, and cosigner algorithms need significant rework.

---

## Go ML-DSA Library Options

Go stdlib (go 1.25) includes `crypto/mlkem` but NOT `crypto/mldsa`. Options:

1. **`github.com/cloudflare/circl`** — Production-grade, includes `sign/dilithium` (ML-DSA-44/65/87). Used by Cloudflare in their MTC deployment.
2. **`github.com/trailofbits/ml-dsa`** — Pure Go FIPS 204 implementation. Smaller dependency footprint.

Recommendation: Use `circl` — battle-tested, maintained by Cloudflare (who are co-deploying MTC with Google).

---

## TLS Considerations

Go's `crypto/x509.ParseCertificate` will reject `id-alg-mtcProof` as an unknown algorithm. MTC certificates must be handled using raw ASN.1 parsing. For TLS:

- `tls.Certificate.Certificate` accepts raw DER bytes (works regardless of algorithm)
- `tls.Certificate.Leaf` cannot be populated with `x509.ParseCertificate` for MTC certs
- Verification in TLS handshakes requires custom `VerifyPeerCertificate` hook
