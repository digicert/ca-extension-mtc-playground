// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package tlogtiles

import (
	"testing"
)

func TestDecodeTileIndex(t *testing.T) {
	tests := []struct {
		path string
		want int64
		err  bool
	}{
		{"000", 0, false},
		{"001", 1, false},
		{"x001/234", 1234, false},
		{"x012/x345/678", 12345678, false},
		{"0", 0, false},
		{"x001/000", 1000, false},
	}

	for _, tt := range tests {
		got, err := decodeTileIndex(tt.path)
		if tt.err {
			if err == nil {
				t.Errorf("decodeTileIndex(%q) = %d, want error", tt.path, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("decodeTileIndex(%q) error: %v", tt.path, err)
			continue
		}
		if got != tt.want {
			t.Errorf("decodeTileIndex(%q) = %d, want %d", tt.path, got, tt.want)
		}
	}
}
