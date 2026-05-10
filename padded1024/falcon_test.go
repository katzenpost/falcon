// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package padded1024

import (
	"bytes"
	"testing"
)

func TestSizes(t *testing.T) {
	if PublicKeySize != 1793 {
		t.Fatalf("unexpected PublicKeySize %d", PublicKeySize)
	}
	if PrivateKeySize != 2305 {
		t.Fatalf("unexpected PrivateKeySize %d", PrivateKeySize)
	}
	if SignatureSize != 1280 {
		t.Fatalf("unexpected SignatureSize %d", SignatureSize)
	}
}

func TestSignVerify(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the quick brown fox jumps over the lazy dog")
	sig, err := Sign(&sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature has length %d, want %d", len(sig), SignatureSize)
	}
	if !Verify(&pk, msg, sig) {
		t.Fatal("valid signature did not verify")
	}

	tamper := bytes.Clone(sig)
	tamper[0] ^= 0xff
	if Verify(&pk, msg, tamper) {
		t.Fatal("tampered signature verified")
	}

	if Verify(&pk, []byte("different"), sig) {
		t.Fatal("signature verified against wrong message")
	}
}

func TestEmptyMessage(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(&sk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(&pk, nil, sig) {
		t.Fatal("signature over empty message did not verify")
	}
}

func TestTwoSignaturesDiffer(t *testing.T) {
	_, sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("randomised signing must produce different signatures")
	sig1, err := Sign(&sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := Sign(&sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sig1, sig2) {
		t.Fatal("two signatures over the same message under randomised Falcon were identical")
	}
}
