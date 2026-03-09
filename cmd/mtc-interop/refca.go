// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package main

import (
	"fmt"
	"time"

	mtcref "github.com/bwesterb/mtc"
	"github.com/bwesterb/mtc/ca"
)

func tryCreateCA(caDir string, issuerOID mtcref.RelativeOID) (*refCAHandle, error) {
	h, err := ca.New(caDir, ca.NewOpts{
		Issuer:          issuerOID,
		ServerPrefix:    "interop-test.example.com/mtc",
		SignatureScheme: mtcref.TLSMLDSA87,
		BatchDuration:   5 * time.Minute,
		Lifetime:        time.Hour,
		StorageDuration: 2 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("ca.New: %w", err)
	}

	return &refCAHandle{
		params: h.Params(),
		dir:    caDir,
		inner:  h,
		queue:  h.Queue,
		issue:  h.Issue,
	}, nil
}
