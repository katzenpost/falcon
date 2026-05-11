# falcon

Go bindings for the [Falcon](https://falcon-sign.info/) post-quantum
signature scheme, exposing the **padded** parameter sets so that every
signature for a given key has the same fixed length.

The C is vendored from
[PQClean](https://github.com/PQClean/PQClean), specifically the
`crypto_sign/falcon-padded-512/clean` and
`crypto_sign/falcon-padded-1024/clean` directories. PQClean Falcon is
MIT-licensed by the Falcon Project; the licence text is preserved
alongside each vendored copy in `padded512/LICENSE` and
`padded1024/LICENSE`. The thin Go wrapper added by this repository is
also released under the MIT licence; see the top-level `LICENSE`.

## Parameter sets

| Variant              | Public key | Private key | Signature |
|----------------------|-----------:|------------:|----------:|
| Falcon-padded-512    |   897 B    |   1281 B    |   666 B   |
| Falcon-padded-1024   |  1793 B    |   2305 B    |  1280 B   |

Signatures are written in the padded encoding, i.e. the variable-length
compressed form is zero-padded to the fixed `SignatureSize` of each
parameter set. Verification accepts only signatures of exactly that
length.

## Usage

```go
import "github.com/katzenpost/falcon/padded512"

pub, priv, err := padded512.GenerateKey()
if err != nil { /* ... */ }

sig, err := padded512.Sign(&priv, []byte("hello"))
if err != nil { /* ... */ }

ok := padded512.Verify(&pub, []byte("hello"), sig)
```

The `padded1024` subpackage exposes the same API for Falcon-padded-1024.

## Constant-time considerations

Falcon signing relies on double-precision floating-point Gaussian
sampling. On modern x86 (SSE2/AVX) and ARMv8 CPUs the relevant FP
operations execute in constant time as a microarchitectural matter, but
the C source itself does not enforce constant-time behaviour. The same
caveat applies to every implementation derived from the Falcon
reference; it is intrinsic to the algorithm. Consumers concerned about
side-channel timing leakage from the FPU on unusual hardware should
prefer ML-DSA (FIPS 204).

Verification is by design variable-time, operating on public inputs
only, and is therefore unaffected.

## Building

The C sources are pure-C, no SIMD intrinsics, so they build with any
modern `cc` and require no system dependencies:

```
go build ./...
go test  ./...
```

## Provenance

### Vendored sources

| Source                                                    | Imported as           |
|-----------------------------------------------------------|-----------------------|
| `PQClean/crypto_sign/falcon-padded-512/clean/`            | `padded512/`          |
| `PQClean/crypto_sign/falcon-padded-1024/clean/`           | `padded1024/`         |
| `PQClean/common/{fips202,randombytes}.{c,h}`              | duplicated into both  |

### Verifying the KAT fixtures

Each subpackage ships a canonical NIST Known Answer Test response file
under `testdata/`. These are the 100-case outputs of PQClean's
`nistkat` driver for each parameter set, byte-identical to the
fixtures hashed by Open Quantum Safe's
[`liboqs`](https://github.com/open-quantum-safe/liboqs) in
`tests/KATs/sig/kats.json` under each variant's `"all"` field.

A human auditor can confirm provenance with one command:

```sh
scripts/verify-kat-against-liboqs.sh
```

The script fetches the current `tests/KATs/sig/kats.json` from
[`open-quantum-safe/liboqs`](https://github.com/open-quantum-safe/liboqs)
and compares the `"all"` digest of each padded variant against the
SHA-256 of our vendored `.rsp` file. A clean run looks like:

```
Falcon-padded-512    OK   362ecc0537ca1fe25143fb7ccb04de8ee7703469d13ebcf311ab124a5c374a65
Falcon-padded-1024   OK   907a4931ddc2ce8360478a45f1bffededd6a04015b00233ecd851a62ecba06c1
```

To pin against a specific liboqs commit rather than `main`, set
`LIBOQS_REF=<sha-or-tag>` in the environment.

To do the comparison by hand without running the script:

```sh
sha256sum padded512/testdata/PQCsignKAT_falcon-padded-512.rsp
sha256sum padded1024/testdata/PQCsignKAT_falcon-padded-1024.rsp
```

then compare against the `all` fields under `Falcon-padded-512` and
`Falcon-padded-1024` in
[`liboqs/tests/KATs/sig/kats.json`](https://github.com/open-quantum-safe/liboqs/blob/main/tests/KATs/sig/kats.json).

`TestCanonicalKATFingerprint` in each subpackage pins the on-disk
file against the literal constant in the test source; `TestNistKAT`
regenerates the bytes from the wrapper and asserts `bytes.Equal`
against the embedded fixture. Either test failing means either our
implementation has diverged from PQClean's reference or the fixture
file has been tampered with. To regenerate the fixture from scratch
(for example after an upstream PQClean update):

```sh
go test -tags genkat -run TestGenerateKAT ./padded512/
go test -tags genkat -run TestGenerateKAT ./padded1024/
```

The non-tagged tests will then independently confirm the regenerated
files still match the published digests.
