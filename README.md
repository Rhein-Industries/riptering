# riptering

> **Fork notice.** riptering is Rhein Industries' actively maintained fork of
> [kryptering](https://github.com/kushaldas/kryptering) by Kushal Das. It
> starts from kryptering 0.5.0 (upstream commit `cb733df`) and keeps
> kryptering's BSD-2-Clause license and copyright notice. riptering is **not
> affiliated with or endorsed by** the upstream author: please report
> problems with riptering to Rhein Industries, not to the kryptering project.
>
> - Bugs and feature requests:
>   <https://github.com/Rhein-Industries/riptering/issues>
> - Security problems: report them privately as described in
>   [SECURITY.md](SECURITY.md); do not open a public issue.

riptering is a compile-time cryptographic provider boundary: one
provider-neutral API for signatures, encryption, key wrap, key agreement and
KDFs over a software provider chosen at build time (RustCrypto or AWS-LC) and
over PKCS#11 HSMs. Requires Rust 1.88 or later.

## How riptering differs from kryptering 0.5.0

- **Name.** The crate is `riptering` (`use riptering::...`). Error messages
  say "riptering", and the SoftHSM2 test variable is
  `RIPTERING_TEST_SOFTHSM2_MODULE`.
- **Platform.** The non-FIPS AWS-LC provider also builds on macOS
  x86_64/aarch64. FIPS stays Linux-only. This is not a claim of FIPS
  certification.
- **Provider parity.** The RustCrypto and AWS-LC providers accept the same
  ECDSA signature encodings, reject RSA keys below 2048 bits at import (RustCrypto accepts them only
  with `legacy`, for historical interoperability),
  restrict raw key import to symmetric families, check key types for
  X25519/ECDH, and share `Pbkdf2Params::recommended(hash, salt, key_length)`
  (a breaking change for AWS-LC callers, which previously passed no hash).
  AWS-LC verifies the cross curve/digest ECDSA pairs XML-DSig produces.
- **FIPS (AWS-LC).** PBKDF2, HKDF and ConcatKDF use the AWS-LC module
  implementations; PBKDF2 enforces the SP 800-132 minimums; AES-128/256-GCM
  nonces are generated inside the module; AES-192-GCM encryption and SHA-224
  PBKDF2/HKDF are not reported as approved.
- **RustCrypto hardening.** AES-CBC and AES-KW length checks, a bounded
  RSA-PSS salt length, DH group and exponent validation, post-quantum import
  pair checks, and zeroization of additional secret intermediates.
- **PKCS#11.** Concurrent sessions on one token, with the PIN of a session
  joining an existing login verified against the login riptering performed
  (three mismatches lock further joins); raw-byte PINs; KEK length checks;
  AES key wrap through `C_WrapKey`/`C_UnwrapKey` where the token only offers
  those; the FIPS ECDH curve read from `CKA_EC_PARAMS`; derived ECDH secrets
  are session objects that are always destroyed.
- **Dependencies and CI.** `rustls` >= 0.23.45 (RUSTSEC-2026-0285) and
  `cryptoki` >= 0.12.1 (RUSTSEC-2026-0286). CI tests every provider,
  PKCS#11 against SoftHSM2, the Linux FIPS build and macOS on GitHub-hosted
  runners; `tests/provider_parity.rs` runs the same cases against every
  provider, including FIPS.

The full list is in the [changelog](CHANGELOG.md). Where a change is a
general fix, we intend to offer it to kryptering as well.

### Migrating from kryptering

```toml
[dependencies]
riptering = "0.6"
# or keep the `kryptering::` paths in your code:
# kryptering = { package = "riptering", version = "0.6" }
```

With the plain `riptering` dependency, replace `kryptering::` with
`riptering::` in your code. AWS-LC callers of `Pbkdf2Params::recommended`
pass the hash algorithm as the new first argument.

## Features

- **Trait-based key abstraction** -- `Signer`, `Verifier`, `Decryptor`, `Encryptor`, `KeyWrapper`, `KeyAgreement` traits that work with both software keys and HSM-backed keys; `Encapsulator`/`Decapsulator` KEM traits (software backend only, for now)
- **Selectable software provider** -- RustCrypto or AWS-LC
- **PKCS#11 backend** -- HSM-backed keys via the `cryptoki` crate (SoftHSM2, Kryoptic, hardware HSMs)
- **Post-quantum** -- ML-DSA (FIPS 204), SLH-DSA (FIPS 205), ML-KEM (FIPS 203), and the six composite ML-DSA signatures from `draft-ietf-jose-pq-composite-sigs-03`, with the RustCrypto provider behind a feature flag

## Supported algorithms

| Category | Algorithms |
|---|---|
| **Signatures** | RSA PKCS#1v1.5, RSA-PSS, ECDSA (P-256/P-384/P-521), Ed25519, HMAC, DSA (legacy), ML-DSA, SLH-DSA, composite ML-DSA |
| **Ciphers** | AES-GCM, AES-CBC (hazmat, unauthenticated — `riptering::hazmat::aes_cbc`), 3DES-CBC (legacy) |
| **Key wrap** | AES-KW (RFC 3394), 3DES-KW (legacy) |
| **Key transport** | RSA-OAEP, RSA PKCS#1v1.5 (legacy) |
| **Key agreement** | ECDH (P-256/P-384/P-521), X25519, DH (X9.42, hazmat — `riptering::hazmat::dh`) |
| **KEM** | ML-KEM-512/768/1024 (FIPS 203; RustCrypto provider) |
| **KDFs** | ConcatKDF, PBKDF2, HKDF, PKCS#12 Appendix B (import interoperability; non-FIPS only) |
| **Digests** | SHA-1, SHA-2 (224/256/384/512), SHA-3, MD5 (legacy), RIPEMD-160 (legacy) |

## Provider selection

| Feature | Default | Description |
|---|---|---|
| `rustcrypto` | Yes | RustCrypto document cryptography |
| `aws-lc` | No | AWS-LC document cryptography (Linux or macOS, x86_64/aarch64) |
| `pkcs11` | Yes | PKCS#11 HSM support via `cryptoki` |
| `legacy` | No | MD5, RIPEMD-160, 3DES, DSA |
| `post-quantum` | No | ML-DSA (FIPS 204), SLH-DSA (FIPS 205), ML-KEM (FIPS 203), composite ML-DSA signatures; RustCrypto only |
| `tls-ring` | No | rustls with ring |
| `tls-aws-lc` | No | rustls with AWS-LC |
| `fips` | No | Select AWS-LC and require explicit, attested FIPS initialization (Linux only) |

Exactly one document provider is required. TLS selection is independent and
at most one TLS provider may be enabled. Provider alternatives must therefore
use `--no-default-features`; `--all-features` is intentionally invalid.

```bash
cargo check                                      # rustcrypto + pkcs11
cargo check --no-default-features --features aws-lc,legacy
cargo check --no-default-features --features fips,tls-aws-lc
```

See [provider capabilities and FIPS behavior](docs/providers.md) for the exact
operation matrix and supported OAEP/signature combinations. The compile-time
provider architecture and future-backend contract are recorded in
[ADR 0002](docs/adr/0002-compile-time-provider-boundary.md).

## Usage

```rust
use riptering::{HashAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use riptering::{SoftwareKey, SoftwareSigner, Signer};

// Software signing
let key = SoftwareKey::from_symmetric_bytes(
    KeyAlgorithm::Hmac,
    b"my-secret-key",
)?;
let signer = SoftwareSigner::new(
    SignatureAlgorithm::Hmac(HashAlgorithm::Sha256),
    key,
)?;
let signature = signer.sign(b"data to sign")?;
# Ok::<(), riptering::Error>(())
```

Composite keys are opaque aggregate keys: component keys cannot be turned into
independent `SoftwareKey` handles. With the RustCrypto provider and `post-quantum` enabled:

```rust
use riptering::{
    generate_composite_ml_dsa, CompositeMlDsaVariant, SignatureAlgorithm,
    Signer, SoftwareSigner, SoftwareVerifier, Verifier,
};

let variant = CompositeMlDsaVariant::MlDsa44Ed25519;
let key = generate_composite_ml_dsa(variant)?;
let signer = SoftwareSigner::new(
    SignatureAlgorithm::CompositeMlDsa(variant),
    key.clone(),
)?;
let verifier = SoftwareVerifier::new(
    SignatureAlgorithm::CompositeMlDsa(variant),
    key,
)?;
let signature = signer.sign(b"data to sign")?;
assert!(verifier.verify(b"data to sign", &signature)?);
# Ok::<(), riptering::Error>(())
```

In a `fips` build, call `initialize_backend()` once during startup, before any
cryptographic or HTTPS operation, and check the returned `BackendInfo`.
Initialization is mandatory, process-wide, and idempotent. Feature activation
alone is not a statement that an application or deployment is FIPS certified.
FIPS policy rejects the PKCS#12 Appendix B KDF and RSA keys below 2048 bits.
The AWS-LC provider also reports non-digest-length RSA-PSS salts as
`UnsupportedAlgorithm` because its stable API does not expose them.

```rust
// HSM signing (with pkcs11 feature)
use riptering::pkcs11::{Pkcs11Provider, Pkcs11Signer};
use riptering::Signer;
use std::path::Path;

let provider = Pkcs11Provider::new(Path::new("/usr/lib/softhsm/libsofthsm2.so")).unwrap();
let session = provider.open_session("1234").unwrap();
let signer = Pkcs11Signer::new(
    &session,
    "my-key-label",
    riptering::SignatureAlgorithm::RsaPkcs1v15(riptering::HashAlgorithm::Sha256),
).unwrap();
let signature = signer.sign(b"data to sign").unwrap();
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the local check matrix and
[SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

BSD-2-Clause, see [LICENSE](LICENSE). riptering retains kryptering's
copyright notice (Copyright (c) 2025, Kushal Das) and adds Rhein Industries'
notice for the fork's modifications.
