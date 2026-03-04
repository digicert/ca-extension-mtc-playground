// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package assertionissuer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// jsonReader returns an io.ReadCloser for JSON body bytes.
func jsonReader(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}

// hmacSign computes HMAC-SHA256 of data with the given secret key.
func hmacSign(secret string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
