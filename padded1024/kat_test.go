// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: MIT

package padded1024_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/katzenpost/falcon/internal/aesctrdrbg"
	"github.com/katzenpost/falcon/padded1024"
)

// nistKATSha256 is the SHA-256 of the count=0 KAT entry as published
// by PQClean in crypto_sign/falcon-padded-1024/META.yml. It pins our
// implementation against PQClean's reference.
const nistKATSha256 = "ddcc5683293388249e6fe85e992ea19d0986d34e060a44f82bc3db524a8c8390"

// TestNistKAT reproduces the count=0 NIST KAT entry from the PQClean
// nistkat driver and asserts its SHA-256 matches PQClean's published
// value. The KAT framework's recipe is:
//
//  1. Seed an AES-256 CTR_DRBG with entropy = 0x00 0x01 ... 0x2F.
//  2. Read 48 bytes (the per-iteration seed) and 33 bytes (the message).
//  3. Re-seed the DRBG with the per-iteration seed.
//  4. Call crypto_sign_keypair, then crypto_sign.
//  5. Format and SHA-256 the result; compare against nistkat-sha256.
//
// In our wrapper, GenerateKey and Sign together draw randomness in the
// same order as PQClean's keypair+sign, so binding our DRBG into the
// trampoline reproduces the byte-identical KAT output.
func TestNistKAT(t *testing.T) {
	var entropy [48]byte
	for i := range entropy {
		entropy[i] = byte(i)
	}
	globalDRBG := aesctrdrbg.New(entropy[:])

	var seed [48]byte
	if _, err := io.ReadFull(globalDRBG, seed[:]); err != nil {
		t.Fatalf("seed: %v", err)
	}
	msg := make([]byte, 33)
	if _, err := io.ReadFull(globalDRBG, msg); err != nil {
		t.Fatalf("msg: %v", err)
	}

	caseDRBG := aesctrdrbg.New(seed[:])
	restore := padded1024.SetTestRNG(caseDRBG)
	t.Cleanup(restore)

	pk, sk, err := padded1024.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := padded1024.Sign(&sk, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// PQClean's crypto_sign produces sm = signature || message and
	// smlen = mlen + CRYPTO_BYTES for padded variants. We reconstruct
	// the same bytes from the detached signature we receive.
	sm := make([]byte, 0, len(sig)+len(msg))
	sm = append(sm, sig...)
	sm = append(sm, msg...)
	smlen := len(sm)

	var b strings.Builder
	fmt.Fprintf(&b, "count = 0\n")
	fmt.Fprintf(&b, "seed = %s\n", upperHex(seed[:]))
	fmt.Fprintf(&b, "mlen = %d\n", len(msg))
	fmt.Fprintf(&b, "msg = %s\n", upperHex(msg))
	fmt.Fprintf(&b, "pk = %s\n", upperHex(pk[:]))
	fmt.Fprintf(&b, "sk = %s\n", upperHex(sk[:]))
	fmt.Fprintf(&b, "smlen = %d\n", smlen)
	fmt.Fprintf(&b, "sm = %s\n", upperHex(sm))

	got := sha256.Sum256([]byte(b.String()))
	if hex.EncodeToString(got[:]) != nistKATSha256 {
		t.Fatalf("KAT hash mismatch:\n  got      %s\n  expected %s\n--- output ---\n%s",
			hex.EncodeToString(got[:]), nistKATSha256, b.String())
	}

	// Sanity: the signature we just produced verifies against the
	// keypair, just like in the original KAT driver's crypto_sign_open.
	if !padded1024.Verify(&pk, msg, sig) {
		t.Fatal("KAT-produced signature did not verify under its keypair")
	}
}

func upperHex(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
