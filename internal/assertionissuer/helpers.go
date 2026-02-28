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
