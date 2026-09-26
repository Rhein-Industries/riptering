# Cryptographic providers

riptering selects document cryptography and network TLS independently at
compile time, as kryptering 0.5 introduced. It never falls back from one
provider to another.

See [ADR 0002](adr/0002-compile-time-provider-boundary.md) for the AWS-LC
selection rationale, the sealed provider-trait design, and the requirements
for adding future backends.

## Selection contract

| Domain | Features | Rule |
|---|---|---|
| Document crypto | `rustcrypto`, `aws-lc` | exactly one |
| Network TLS | `tls-ring`, `tls-aws-lc` | at most one |
| Compliance | `fips` | incompatible with `rustcrypto` and `tls-ring` |
| HSM | `pkcs11` | orthogonal to the software provider |

AWS-LC is gated to x86_64/aarch64 on Linux, plus non-FIPS builds on macOS.
FIPS builds are Linux-only.
`--all-features` is an expected compile failure.

## Non-FIPS capability registry

This table describes provider operations implemented and exercised by the
backend test matrix. A parameter combination outside the row returns
`UnsupportedAlgorithm` before key material is parsed or used.

| Operation | RustCrypto | AWS-LC |
|---|---|---|
| RNG | yes | yes |
| SHA-2 / HMAC-SHA-2 | yes | yes |
| RSA PKCS#1/PSS signatures | broad legacy + modern set | SHA-256/384/512 signing |
| ECDSA | broad curve/hash set | verify: P-256/P-384 with SHA-256/384/512, P-521 with SHA-224/256/384/512; sign: P-256/SHA-256, P-384/SHA-384, P-521 with SHA-224/256/384/512 |
| Ed25519 | yes | yes |
| AES-CBC/GCM | 128/192/256 | 128/192/256 |
| AES-KW | 128/192/256 | 128/256 |
| RSA-OAEP encryption | digest SHA-1/224/256/384/512, plus MD5/RIPEMD160 with `legacy`; independent MGF1 SHA-1/224/256/384/512 | SHA-1/256/384/512 when OAEP and MGF hashes match |
| RSA-OAEP decryption | same hash combinations, only with `legacy-rsa-decryption` | same combinations as encryption |
| RSA PKCS#1 v1.5 transport | encrypt with `legacy`; decrypt requires both `legacy` and `legacy-rsa-decryption` | with `legacy` |
| ECDH | P-256/P-384/P-521 | P-256/P-384/P-521 |
| X25519 | yes | yes |
| finite-field X9.42 DH | neutral hazmat parameters | unsupported |
| HKDF/PBKDF2/ConcatKDF | yes | SHA-1/SHA-2 family; AWS-LC module KDFs for SHA-1/256/384/512 (PBKDF2, HKDF) and SHA-224/256/384/512 (ConcatKDF) |
| DSA signatures | with `legacy` | unsupported |
| 3DES-CBC / 3DES key wrap | with `legacy` | unsupported |
| ML-DSA / SLH-DSA | feature-dependent | unsupported by stable AWS-LC APIs |
| Composite ML-DSA (`draft-ietf-jose-pq-composite-sigs-03`) | all six variants with `post-quantum` | unsupported |

The authoritative queries are `supports(Operation)` for a single fully
parameterized operation and `capabilities()` for the complete tested registry.
The latter is generated from the same parameter registry used by capability
tests, rather than from a separately maintained list.

RustCrypto RSA decryption is disabled by default to remove exposure to the
unpatched [RUSTSEC-2023-0071 timing advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html).
The separate `legacy-rsa-decryption` feature restores it for compatibility;
`legacy` alone does not. Refusal occurs before inspecting key material,
ciphertext, or labels, and decrypt primitives are compiled out when the opt-in
is absent. Opted-in decryption uses exponent blinding, which does not fix the
remaining upstream padding timing issue. AWS-LC and PKCS#11 are unaffected by
this feature, and FIPS software RSA transport remains refused in either mode.

## Initialization and FIPS

Non-FIPS builds initialize ergonomically on first use. In a `fips` build,
`initialize_backend()` must succeed first; cryptographic operations and TLS
configuration otherwise return `BackendNotInitialized`.

The `fips` feature selects AWS-LC for document cryptography. AWS-LC
initialization calls `try_fips_mode()`; when TLS is enabled, `tls-aws-lc` is
the only permitted TLS provider and must independently report active FIPS mode.

Stable AWS-LC APIs require RSA public keys of at least 2048 bits. They also do
not expose non-default RSA-PSS salt lengths. Those salt declarations are
reported as `UnsupportedAlgorithm` when the verifier is constructed, before
signature verification uses the key.

Both providers accept the same ECDSA signature encodings on verification:
fixed-width r||s, r||s with zero-padded or stripped components, and DER.
Both providers import RSA keys below 2048 bits but refuse to sign, verify or
transport keys with them, reporting the key size. The RustCrypto provider
uses them only with the `legacy` feature, for interoperability with
historical signatures and encrypted documents (decryption additionally requires
`legacy-rsa-decryption`); AWS-LC never does, and FIPS
builds refuse them already at import.

In a `fips` build, the software provider applies these restrictions:

- PBKDF2 requires a salt of at least 16 bytes, at least 1000 iterations, and a
  password of at least 14 bytes (SP 800-132, as enforced by AWS-LC's approval
  indicator).
- PBKDF2, HKDF and ConcatKDF run inside the AWS-LC module. SHA-224 PBKDF2 and
  HKDF have no module implementation and are not approved.
- HKDF requires nonempty `info` and rejects an explicitly empty salt.
  `salt: None` supplies the RFC 5869 hash-length zero salt; callers using
  `HkdfParams::default()` must add nonempty `info` in FIPS builds. These
  parameter checks preserve the pinned module's service approval conditions;
  non-FIPS builds continue accepting the full RFC 5869 parameter surface.
- AES-128/256-GCM encryption uses a nonce generated inside the module.
  The pinned module approves AES-GCM only with 128/256-bit keys, so
  AES-192-GCM encryption and decryption are both refused in FIPS builds.
- RSA imports require an even modulus bit length of at least 2048 bits,
  matching the pinned module's RSA signature service approval conditions.
- RSA key transport is refused for every digest. In the pinned
  `aws-lc-fips-sys` 0.14.2 source, RSA encryption/decryption and OAEP padding
  reside in `crypto/rsa_extra/rsa_crypt.c`, outside the validated
  `crypto/fipsmodule/bcm.c` aggregate. RSA signatures remain available.

The software module restrictions are separate from PKCS#11 algorithm policy.
The token may provide its own approved RSA-OAEP or AES-192-GCM decryption
service; enabling `fips` does not attest the token's module or deployment.
Operators remain responsible for the token's approval and parameter policy.

FIPS capability reporting excludes unavailable or unapproved operations.
Building with the `fips` feature does not certify the consuming binary or its
deployment. AWS-LC FIPS builds additionally need the native toolchain required
by aws-lc-rs.

## Key migration

Provider-specific public key enums are replaced by the cloneable,
`Arc`-backed `SoftwareKey`. Import PKCS#8 private keys, SPKI public keys, raw
symmetric bytes, X25519 components, neutral finite-field DH parameters,
post-quantum DER, or aggregate raw composite ML-DSA keys through explicit
constructors. Use `algorithm()`, `has_private_key()`, and `public_component()`
for metadata; private export is explicit and returns a zeroizing buffer.
`Debug` never prints secret material.

Digest one-shot and streaming construction are fallible in 0.5 because
initialization or provider capability checks can fail.
