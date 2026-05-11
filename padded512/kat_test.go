// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: MIT

package padded512_test

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/katzenpost/falcon/internal/aesctrdrbg"
	"github.com/katzenpost/falcon/padded512"
)

//go:embed testdata/PQCsignKAT_falcon-padded-512.rsp
var canonicalKAT []byte

// canonicalKATSha256 is the SHA-256 of testdata/PQCsignKAT_falcon-padded-512.rsp.
// It is also the value published by Open Quantum Safe's liboqs at
//
//   tests/KATs/sig/kats.json
//
// in the "Falcon-padded-512" -> "all" field, and represents the 100-case
// NIST KAT output produced by PQClean's nistkat driver for this scheme.
// A human auditor can verify provenance with one command:
//
//   sha256sum padded512/testdata/PQCsignKAT_falcon-padded-512.rsp
//
// and compare against the value below and the liboqs kats.json entry.
const canonicalKATSha256 = "362ecc0537ca1fe25143fb7ccb04de8ee7703469d13ebcf311ab124a5c374a65"

// TestCanonicalKATFingerprint pins the vendored .rsp file against the
// upstream-published digest. Any tampering with the file changes its
// hash and fails this test loudly.
func TestCanonicalKATFingerprint(t *testing.T) {
	h := sha256.Sum256(canonicalKAT)
	got := hex.EncodeToString(h[:])
	if got != canonicalKATSha256 {
		t.Fatalf("vendored KAT sha256 mismatch:\n  got      %s\n  expected %s",
			got, canonicalKATSha256)
	}
}

// TestNistKAT reproduces the 100-case PQClean nistkat output for
// Falcon-padded-512 using our wrapper and asserts the bytes match the
// vendored canonical file exactly.
//
// The KAT framework's recipe is:
//
//  1. Seed an AES-256 CTR_DRBG with entropy = 0x00 0x01 ... 0x2F.
//  2. For i in [0, 100): draw 48 bytes (per-iteration seed) and
//     33*(i+1) bytes (the message).
//  3. For each i: re-seed a fresh DRBG with the per-iteration seed,
//     call crypto_sign_keypair, then crypto_sign.
//  4. Format and concatenate 100 entries, blank-line-separated.
//
// GenerateKey and Sign together draw randomness in the same order as
// PQClean's keypair+sign, so binding our DRBG into the trampoline
// reproduces byte-identical output.
func TestNistKAT(t *testing.T) {
	got := buildKAT(t)
	if bytes.Equal(got, canonicalKAT) {
		return
	}
	t.Fatal(firstDiffMessage(got, canonicalKAT))
}

type katCase struct {
	count int
	seed  [48]byte
	mlen  int
	msg   []byte
	pk    padded512.PublicKey
	sk    padded512.PrivateKey
	sig   []byte
}

func buildKAT(t *testing.T) []byte {
	const n = 100

	var entropy [48]byte
	for i := range entropy {
		entropy[i] = byte(i)
	}
	globalDRBG := aesctrdrbg.New(entropy[:])

	cases := make([]katCase, n)
	for i := range cases {
		cases[i].count = i
		if _, err := io.ReadFull(globalDRBG, cases[i].seed[:]); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
		cases[i].mlen = 33 * (i + 1)
		cases[i].msg = make([]byte, cases[i].mlen)
		if _, err := io.ReadFull(globalDRBG, cases[i].msg); err != nil {
			t.Fatalf("msg[%d]: %v", i, err)
		}
	}

	for i := range cases {
		caseDRBG := aesctrdrbg.New(cases[i].seed[:])
		restore := padded512.SetTestRNG(caseDRBG)
		pk, sk, err := padded512.GenerateKey()
		if err != nil {
			restore()
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		sig, err := padded512.Sign(&sk, cases[i].msg)
		restore()
		if err != nil {
			t.Fatalf("Sign[%d]: %v", i, err)
		}
		cases[i].pk = pk
		cases[i].sk = sk
		cases[i].sig = sig
	}

	var b strings.Builder
	for i := range cases {
		if i > 0 {
			b.WriteString("\n")
		}
		writeCase(&b, &cases[i])
	}
	return []byte(b.String())
}

func writeCase(b *strings.Builder, e *katCase) {
	sm := make([]byte, 0, len(e.sig)+len(e.msg))
	sm = append(sm, e.sig...)
	sm = append(sm, e.msg...)
	fmt.Fprintf(b, "count = %d\n", e.count)
	fmt.Fprintf(b, "seed = %s\n", upperHex(e.seed[:]))
	fmt.Fprintf(b, "mlen = %d\n", e.mlen)
	fmt.Fprintf(b, "msg = %s\n", upperHex(e.msg))
	fmt.Fprintf(b, "pk = %s\n", upperHex(e.pk[:]))
	fmt.Fprintf(b, "sk = %s\n", upperHex(e.sk[:]))
	fmt.Fprintf(b, "smlen = %d\n", len(sm))
	fmt.Fprintf(b, "sm = %s\n", upperHex(sm))
}

func upperHex(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func firstDiffMessage(got, want []byte) string {
	if len(got) != len(want) {
		return fmt.Sprintf("KAT length mismatch: got %d bytes, want %d bytes",
			len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			start := i - 30
			if start < 0 {
				start = 0
			}
			end := i + 30
			if end > len(got) {
				end = len(got)
			}
			return fmt.Sprintf("KAT byte mismatch at offset %d:\n  got:  %q\n  want: %q",
				i, string(got[start:end]), string(want[start:end]))
		}
	}
	return "KAT outputs equal but bytes.Equal returned false"
}
