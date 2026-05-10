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
released under AGPL-3.0-only; see the top-level `LICENSE`.

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

| Source                                                    | Imported as           |
|-----------------------------------------------------------|-----------------------|
| `PQClean/crypto_sign/falcon-padded-512/clean/`            | `padded512/`          |
| `PQClean/crypto_sign/falcon-padded-1024/clean/`           | `padded1024/`         |
| `PQClean/common/{fips202,randombytes}.{c,h}`              | duplicated into both  |
