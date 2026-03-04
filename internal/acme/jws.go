// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// jws represents a flattened JWS object per RFC 7515.
type jws struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// jwsHeader represents the protected header of a JWS.
type jwsHeader struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	KID   string          `json:"kid,omitempty"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
}

// verifyJWS parses and verifies a JWS request body.
func (srv *Server) verifyJWS(r *http.Request, requireKID bool) (*jwsHeader, []byte, *store.ACMEAccount, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read body: %w", err)
	}

	var j jws
	if err := json.Unmarshal(body, &j); err != nil {
		return nil, nil, nil, fmt.Errorf("parse JWS: %w", err)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(j.Protected)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode protected: %w", err)
	}

	var hdr jwsHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, nil, nil, fmt.Errorf("parse protected header: %w", err)
	}

	if !srv.consumeNonce(hdr.Nonce) {
		return nil, nil, nil, fmt.Errorf("invalid or expired nonce")
	}

	expectedURL := srv.cfg.ExternalURL + r.URL.Path
	if hdr.URL != expectedURL {
		return nil, nil, nil, fmt.Errorf("URL mismatch: got %q, want %q", hdr.URL, expectedURL)
	}

	var payload []byte
	if j.Payload != "" {
		payload, err = base64.RawURLEncoding.DecodeString(j.Payload)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode payload: %w", err)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(j.Signature)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode signature: %w", err)
	}

	var pubKey crypto.PublicKey
	var acct *store.ACMEAccount

	if requireKID {
		if hdr.KID == "" {
			return nil, nil, nil, fmt.Errorf("kid required")
		}
		acctID := hdr.KID
		if idx := strings.LastIndex(acctID, "/"); idx >= 0 {
			acctID = acctID[idx+1:]
		}
		acct, err = srv.store.GetACMEAccount(r.Context(), acctID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("account not found: %w", err)
		}
		pubKey, err = parseJWK(acct.JWK)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse stored JWK: %w", err)
		}
	} else {
		if len(hdr.JWK) == 0 {
			return nil, nil, nil, fmt.Errorf("jwk required for new account")
		}
		pubKey, err = parseJWK(hdr.JWK)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse JWK: %w", err)
		}
	}

	sigInput := j.Protected + "." + j.Payload
	if err := verifySignature(pubKey, hdr.Alg, []byte(sigInput), sig); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid signature: %w", err)
	}

	return &hdr, payload, acct, nil
}

// parseJWK parses a JWK JSON object into a crypto.PublicKey.
func parseJWK(raw json.RawMessage) (crypto.PublicKey, error) {
	var kty struct {
		Kty string `json:"kty"`
	}
	if err := json.Unmarshal(raw, &kty); err != nil {
		return nil, fmt.Errorf("parse kty: %w", err)
	}
	switch kty.Kty {
	case "EC":
		return parseECJWK(raw)
	case "RSA":
		return parseRSAJWK(raw)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty.Kty)
	}
}

func parseECJWK(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var key struct {
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, err
	}
	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", key.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func parseRSAJWK(raw json.RawMessage) (*rsa.PublicKey, error) {
	var key struct {
		N string `json:"n"`
		E string `json:"e"`
	}
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, err
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

// verifySignature verifies a JWS signature.
func verifySignature(pubKey crypto.PublicKey, alg string, sigInput, sig []byte) error {
	switch alg {
	case "ES256":
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ES256 requires EC key")
		}
		hash := sha256.Sum256(sigInput)
		if len(sig) != 64 {
			return fmt.Errorf("ES256 signature must be 64 bytes, got %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecKey, hash[:], r, s) {
			return fmt.Errorf("ES256 signature verification failed")
		}
		return nil
	case "RS256":
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RS256 requires RSA key")
		}
		hash := sha256.Sum256(sigInput)
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], sig)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// jwkThumbprint computes the JWK Thumbprint per RFC 7638.
func jwkThumbprint(raw json.RawMessage) (string, error) {
	var kty struct {
		Kty string `json:"kty"`
	}
	if err := json.Unmarshal(raw, &kty); err != nil {
		return "", err
	}
	var canonical string
	switch kty.Kty {
	case "EC":
		var key struct {
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		if err := json.Unmarshal(raw, &key); err != nil {
			return "", err
		}
		canonical = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, key.Crv, key.X, key.Y)
	case "RSA":
		var key struct {
			E string `json:"e"`
			N string `json:"n"`
		}
		if err := json.Unmarshal(raw, &key); err != nil {
			return "", err
		}
		canonical = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, key.E, key.N)
	default:
		return "", fmt.Errorf("unsupported kty: %s", kty.Kty)
	}
	hash := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
