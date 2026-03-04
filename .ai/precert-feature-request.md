# Feature Request: Pre-Certificate Workflow with External Data Embedding

## Summary

Add native support for a two-phase certificate issuance flow in DigiCert Private CA: (1) issue a pre-certificate, (2) pause to allow gathering of external data, (3) embed that data into the final certificate and issue it. This generic capability should specifically support two key use cases: **Merkle Tree Certificates (MTC)** per the IETF draft, and **Certificate Transparency (CT)** Signed Certificate Timestamps (SCTs).

## Problem

Embedding externally-derived data into certificates (inclusion proofs, SCTs, etc.) creates a chicken-and-egg problem — the external system needs the certificate content to produce its artifact, but the artifact must be embedded in the certificate before final signing. Today this requires building a standalone bridge service that watches the CA database, extracts pre-certificate data, interacts with external systems, and re-signs certificates — significant operational complexity that belongs inside the CA itself.

## Proposed Capability

A generic two-phase issuance pipeline:

1. **Pre-certificate issuance** — CA produces a signed pre-certificate (or canonical TBS structure) and holds the order open.
2. **External data gathering** — A configurable hook (webhook, plugin, or polling target) sends the pre-certificate content to one or more external systems and collects their responses (e.g., Merkle inclusion proofs, cosigner signatures, CT SCTs).
3. **Final certificate issuance** — CA embeds the collected data into a designated X.509 extension and issues the final certificate.

### Use Case 1: Merkle Tree Certificates (MTC)

- Pre-cert TBS is appended to a transparency log; a Merkle inclusion proof and signed checkpoint are returned.
- Proof data is embedded in a custom X.509v3 extension (e.g., OID `id-alg-mtcProof`).
- Supports multiple cosigners (Ed25519, ML-DSA) signing the same tree checkpoint.

### Use Case 2: Certificate Transparency (CT)

- Pre-cert is submitted to one or more CT logs; SCTs are returned.
- SCTs are embedded in the standard SCT List extension (OID `1.3.6.1.4.1.11129.2.4.2`).

---

## Technical Details: Pre-Certificate vs. Final Certificate

### What is a Pre-Certificate?

A pre-certificate is a **fully valid, signed X.509 certificate** that is structurally identical to the final certificate — same serial number, same subject, same validity, same public key — **except** it does not contain the external data extension. It exists temporarily so that external systems can hash/process its content and return an artifact to embed.

### Structural Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRE-CERTIFICATE (Phase 1)                    │
├─────────────────────────────────────────────────────────────────┤
│  tbsCertificate:                                                │
│    version:            v3                                       │
│    serialNumber:       <random 128-bit>                         │
│    signature:          ecdsa-with-SHA256                         │
│    issuer:             CN=DigiCert Private CA                   │
│    validity:           notBefore / notAfter                     │
│    subject:            CN=app.example.com                       │
│    subjectPublicKeyInfo: <client's public key>                  │
│    extensions:                                                  │
│      - subjectAltName:  DNS:app.example.com, DNS:*.example.com  │
│      - keyUsage:        digitalSignature, keyEncipherment       │
│      - extKeyUsage:     serverAuth, clientAuth                  │
│      ┌──────────────────────────────────────────────────────┐   │
│      │  (NO external data extension — this is the only      │   │
│      │   difference from the final certificate)             │   │
│      └──────────────────────────────────────────────────────┘   │
│  signatureAlgorithm:   ecdsa-with-SHA256                        │
│  signatureValue:       <CA signature over tbsCertificate>       │
└─────────────────────────────────────────────────────────────────┘

                    ┃
                    ┃  The canonical TBSCertificate (DER bytes)
                    ┃  is extracted and sent to external system(s).
                    ┃  External system returns proof/artifact data.
                    ▼

┌─────────────────────────────────────────────────────────────────┐
│                    FINAL CERTIFICATE (Phase 2)                  │
├─────────────────────────────────────────────────────────────────┤
│  tbsCertificate:                                                │
│    version:            v3                                       │
│    serialNumber:       <same serial as pre-cert>                │
│    signature:          ecdsa-with-SHA256                         │
│    issuer:             CN=DigiCert Private CA                   │
│    validity:           <same notBefore / notAfter>              │
│    subject:            CN=app.example.com                       │
│    subjectPublicKeyInfo: <same public key>                      │
│    extensions:                                                  │
│      - subjectAltName:  DNS:app.example.com, DNS:*.example.com  │
│      - keyUsage:        digitalSignature, keyEncipherment       │
│      - extKeyUsage:     serverAuth, clientAuth                  │
│      ┌──────────────────────────────────────────────────────┐   │
│      │  + NEW: External data extension (non-critical)       │   │
│      │    OID: 1.3.6.1.4.1.99999.1.1 (MTC Inclusion Proof) │   │
│      │    -or- 1.3.6.1.4.1.11129.2.4.2 (CT SCT List)       │   │
│      │    Value: <proof/artifact data from external system>  │   │
│      └──────────────────────────────────────────────────────┘   │
│  signatureAlgorithm:   ecdsa-with-SHA256                        │
│  signatureValue:       <NEW CA signature over updated TBS>      │
└─────────────────────────────────────────────────────────────────┘
```

### Why Re-Signing is Required

The CA must sign the certificate **twice**:

1. **First signature** (pre-cert): Signs the TBS without the external extension. This produces the canonical bytes that external systems hash/process.
2. **Second signature** (final cert): Signs the TBS *with* the external extension added. Since any change to the TBS invalidates the signature, a new signature is mandatory.

The pre-cert's serial number, validity dates, subject, and all other fields are preserved exactly. Only the extensions list changes (one extension is appended), and a fresh signature is computed.

### What Gets Sent to External Systems

The **canonical TBSCertificate** — the DER-encoded `tbsCertificate` field from the pre-certificate (everything inside the outer SEQUENCE, before the signatureAlgorithm and signatureValue). This is the bytes that get hashed (SHA-256) and added to a Merkle tree or submitted to a CT log. Approximately 400–800 bytes for a typical certificate.

### What Comes Back from External Systems

**For MTC — an inclusion proof structure:**

```asn1
MTCInclusionProof ::= SEQUENCE {
    logOrigin    UTF8String,              -- transparency log identifier
    leafIndex    INTEGER,                 -- position in the Merkle tree
    treeSize     INTEGER,                 -- tree size at proof time
    rootHash     OCTET STRING (SIZE(32)), -- SHA-256 root hash
    proofHashes  SEQUENCE OF OCTET STRING (SIZE(32)),  -- sibling hashes
    checkpoint   UTF8String               -- signed tree head (cosigner signatures)
}
```

**For CT — an SCT list:** a DER-encoded `SignedCertificateTimestampList` containing one or more SCTs from CT log operators.

---

## Proposed API Design

### New Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/certificate-authority/api/v1/precertificate` | Create a pre-certificate (Phase 1) |
| `GET` | `/certificate-authority/api/v1/precertificate/{id}` | Retrieve pre-cert status and canonical TBS |
| `POST` | `/certificate-authority/api/v1/precertificate/{id}/embed` | Submit external data for embedding |
| `POST` | `/certificate-authority/api/v1/precertificate/{id}/finalize` | Trigger final cert issuance (Phase 2) |
| `GET` | `/certificate-authority/api/v1/precertificate/{id}/certificate` | Download the final certificate |

### Sample End-to-End Flow

#### Step 1: Create Pre-Certificate

```http
POST /certificate-authority/api/v1/precertificate
Content-Type: application/json
x-api-key: {{api_key}}

{
  "issuer": { "id": "ca-abc123" },
  "template_id": "tpl-mtc-server-cert",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIBIjAN...\n-----END CERTIFICATE REQUEST-----",
  "subject": {
    "common_name": "app.example.com",
    "organization_name": "Example Corp",
    "country": "US"
  },
  "validity": {
    "valid_from": "2026-03-01T00:00:00Z",
    "valid_to": "2026-05-30T00:00:00Z"
  },
  "extensions": {
    "san": {
      "dns_names": ["app.example.com", "*.example.com"]
    }
  },
  "embed_config": {
    "workflow": "mtc",
    "timeout_seconds": 300,
    "webhook_url": "https://mtc-log.example.com/api/submit"
  }
}
```

**Response:**

```json
{
  "id": "precert-7f3a9b2c",
  "status": "pending_external_data",
  "serial_number": "4A8B2C1D9E0F37A6B5C4D3E2F1A09876",
  "canonical_tbs_sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "canonical_tbs_base64": "MIICpTCCAYkCAQ...==",
  "created_at": "2026-03-01T12:00:00Z",
  "expires_at": "2026-03-01T12:05:00Z"
}
```

The `canonical_tbs_base64` field contains the DER-encoded TBSCertificate — these are the exact bytes that external systems will hash and process. The `canonical_tbs_sha256` is the SHA-256 of those bytes, provided as a convenience for systems that only need the hash.

#### Step 2: Submit External Data to the Pre-Certificate

After the caller (or webhook) obtains the proof/artifact from the external system, it submits the data back:

```http
POST /certificate-authority/api/v1/precertificate/precert-7f3a9b2c/embed
Content-Type: application/json
x-api-key: {{api_key}}

{
  "extensions": [
    {
      "oid": "1.3.6.1.4.1.99999.1.1",
      "critical": false,
      "value_base64": "MIGqDBtodHRwczovL210Yy1sb2cuZXhhbXBsZS5jb20CBBK...==",
      "label": "MTC Inclusion Proof"
    }
  ]
}
```

The `value_base64` is the DER-encoded ASN.1 value of the extension. For MTC, this is the `MTCInclusionProof` structure containing:

```json
{
  "log_origin":   "https://mtc-log.example.com",
  "leaf_index":   42,
  "tree_size":    1024,
  "root_hash":    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "proof_hashes": [
    "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
  ],
  "checkpoint":   "mtc-log.example.com\n1024\nb94d27b993...\n\n— mtc-log.example.com Az3g...\n"
}
```

**Response:**

```json
{
  "id": "precert-7f3a9b2c",
  "status": "ready_to_finalize",
  "embedded_extensions": [
    {
      "oid": "1.3.6.1.4.1.99999.1.1",
      "label": "MTC Inclusion Proof",
      "size_bytes": 312
    }
  ]
}
```

#### Step 3: Finalize — Issue the Final Certificate

```http
POST /certificate-authority/api/v1/precertificate/precert-7f3a9b2c/finalize
Content-Type: application/json
x-api-key: {{api_key}}

{}
```

**Response:**

```json
{
  "id": "precert-7f3a9b2c",
  "status": "issued",
  "serial_number": "4A8B2C1D9E0F37A6B5C4D3E2F1A09876",
  "certificate_id": "cert-e4f5a6b7",
  "certificate_url": "/certificate-authority/api/v1/precertificate/precert-7f3a9b2c/certificate"
}
```

#### Step 4: Download Final Certificate

```http
GET /certificate-authority/api/v1/precertificate/precert-7f3a9b2c/certificate
Accept: application/pem-certificate-chain
x-api-key: {{api_key}}
```

**Response:**

```
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIQSossFdnkI6a... (final cert with embedded MTC proof extension)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIQK8JQNRFKV... (issuing CA)
-----END CERTIFICATE-----
```

### Alternative Flow: CT SCT Embedding

The same API supports CT with different embed data:

```http
POST /certificate-authority/api/v1/precertificate/precert-7f3a9b2c/embed
Content-Type: application/json

{
  "extensions": [
    {
      "oid": "1.3.6.1.4.1.11129.2.4.2",
      "critical": false,
      "value_base64": "BHgEdgB1AKS5CZC0GFgUH7kes...==",
      "label": "CT Signed Certificate Timestamp List"
    }
  ]
}
```

### Webhook Integration (Optional Automation)

For fully automated flows, the CA can call an external webhook when the pre-cert is ready and receive the embed data via callback:

**Template configuration:**

```json
{
  "template_id": "tpl-mtc-server-cert",
  "name": "MTC-Enabled Server Certificate",
  "precert_workflow": {
    "enabled": true,
    "hooks": [
      {
        "type": "webhook",
        "url": "https://mtc-log.example.com/api/submit",
        "payload_fields": ["canonical_tbs_base64", "canonical_tbs_sha256", "serial_number"],
        "response_mapping": {
          "extensions[0].oid": "1.3.6.1.4.1.99999.1.1",
          "extensions[0].value_base64": "$.proof_extension_base64"
        },
        "timeout_seconds": 120,
        "retry_count": 3
      }
    ],
    "auto_finalize": true
  }
}
```

With this configuration, a standard `POST /certificate` request using template `tpl-mtc-server-cert` would automatically execute the two-phase flow behind the scenes — the caller receives the final certificate with embedded proof data without needing to call the pre-cert APIs directly.

---

## Requested Integration Points

| Surface | Capability |
|---------|------------|
| **API** | Expose pre-cert creation, external data submission, and final issuance as distinct API operations. Support webhook/callback configuration for external system integration. |
| **UX** | Allow administrators to configure pre-cert workflows per certificate profile — define which external systems to call, what extension OIDs to populate, and timeout/retry policies. Provide visibility into orders awaiting external data. |
| **Templates** | Allow certificate templates to declare required external data fields, target extension OIDs, and data format (ASN.1 structure or opaque blob). Templates should be reusable across MTC, CT, and future use cases. |

---

## Why Native Support Matters

We have built a [working proof-of-concept bridge](https://github.com/briantrzupek/ca-extension-merkle) that implements the full MTC two-phase signing flow with DigiCert Private CA today, but it requires: a database watcher polling for new issuances, a standalone Merkle tree and checkpoint service, an ACME server proxy, and a local re-signing CA. Native support would eliminate this operational overhead, provide serialization guarantees the bridge cannot offer, and make MTC/CT adoption turnkey for Private CA customers.
