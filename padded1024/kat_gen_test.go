//go:build genkat

// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: MIT

// One-shot generator for the canonical .rsp fixture. Run with:
//
//   go test -tags genkat -run TestGenerateKAT ./padded1024/
//
// after which `git diff` should show only formatting changes if any.
// The non-tagged TestCanonicalKATFingerprint then independently confirms
// the regenerated file's SHA-256 still matches the published value.

package padded1024_test

import (
	"os"
	"testing"
)

func TestGenerateKAT(t *testing.T) {
	body := buildKAT(t)
	if err := os.WriteFile(
		"testdata/PQCsignKAT_falcon-padded-1024.rsp",
		body, 0o644,
	); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %d bytes", len(body))
}
