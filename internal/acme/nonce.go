// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package acme

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

func (srv *Server) newNonce() string {
	b := make([]byte, 16)
	h := sha256.Sum256([]byte(fmt.Sprintf("%d-%p", time.Now().UnixNano(), &b)))
	nonce := base64.RawURLEncoding.EncodeToString(h[:16])
	srv.mu.Lock()
	srv.nonces[nonce] = time.Now().Add(1 * time.Hour)
	srv.mu.Unlock()
	return nonce
}

func (srv *Server) consumeNonce(nonce string) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	exp, ok := srv.nonces[nonce]
	if !ok {
		return false
	}
	delete(srv.nonces, nonce)
	return time.Now().Before(exp)
}

func (srv *Server) cleanupNonces() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		srv.mu.Lock()
		now := time.Now()
		for k, exp := range srv.nonces {
			if now.After(exp) {
				delete(srv.nonces, k)
			}
		}
		srv.mu.Unlock()
	}
}

// newID generates a random-looking ID for ACME objects.
func newID() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return base64.RawURLEncoding.EncodeToString(h[:12])
}
