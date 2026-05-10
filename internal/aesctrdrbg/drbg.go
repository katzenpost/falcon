// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: MIT

// Package aesctrdrbg implements the NIST SP 800-90A AES-256 CTR_DRBG
// in the configuration used by the NIST PQC Known Answer Test
// framework: 48-byte entropy input, no derivation function, no
// personalisation string, no additional input on Generate.
//
// It is intended for test code that must reproduce the deterministic
// outputs published alongside post-quantum reference implementations.
// It is not a general-purpose RNG; production callers should use
// crypto/rand.
package aesctrdrbg

import (
	"crypto/aes"
	"crypto/cipher"
)

const (
	keyLen   = 32 // AES-256 key length
	blockLen = 16 // AES block length
	seedLen  = keyLen + blockLen
)

// DRBG is an AES-256 CTR_DRBG state.
type DRBG struct {
	block cipher.Block
	v     [blockLen]byte
	key   [keyLen]byte
}

// New returns a DRBG seeded with the given 48-byte entropy input,
// matching the initial state produced by NIST's reference
// randombytes_init(entropy, NULL, 256).
func New(entropy []byte) *DRBG {
	if len(entropy) != seedLen {
		panic("aesctrdrbg: entropy must be 48 bytes")
	}
	d := &DRBG{}
	d.refreshBlock()
	d.update(entropy)
	return d
}

func (d *DRBG) refreshBlock() {
	b, err := aes.NewCipher(d.key[:])
	if err != nil {
		panic(err)
	}
	d.block = b
}

func (d *DRBG) incrementV() {
	for i := blockLen - 1; i >= 0; i-- {
		d.v[i]++
		if d.v[i] != 0 {
			return
		}
	}
}

// update is CTR_DRBG_Update from SP 800-90A. The provided argument may
// be nil to indicate an empty additional-input string; otherwise it
// must be exactly 48 bytes.
func (d *DRBG) update(provided []byte) {
	if provided != nil && len(provided) != seedLen {
		panic("aesctrdrbg: update input must be 48 bytes or nil")
	}
	var buf [seedLen]byte
	for i := 0; i < seedLen; i += blockLen {
		d.incrementV()
		d.block.Encrypt(buf[i:i+blockLen], d.v[:])
	}
	if provided != nil {
		for i := range buf {
			buf[i] ^= provided[i]
		}
	}
	copy(d.key[:], buf[:keyLen])
	copy(d.v[:], buf[keyLen:])
	d.refreshBlock()
}

// Read fills p with deterministic random bytes, advancing the DRBG
// state per CTR_DRBG_Generate. It implements io.Reader and never
// returns an error.
func (d *DRBG) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var blk [blockLen]byte
	for i := 0; i < len(p); i += blockLen {
		d.incrementV()
		d.block.Encrypt(blk[:], d.v[:])
		copy(p[i:], blk[:])
	}
	d.update(nil)
	return len(p), nil
}
