# Changelog

riptering is Rhein Industries' maintained fork of
[kryptering](https://github.com/kushaldas/kryptering) by Kushal Das. Entries
from 0.6.0 on describe riptering. The history of kryptering up to 0.5.0, the
release riptering was forked from, is kept unchanged below.

## Unreleased

- Refuse RustCrypto RSA-OAEP and PKCS#1 v1.5 decryption by default, before key
  or input access. A separate off-by-default `legacy-rsa-decryption` feature
  restores compatibility while retaining the unpatched RUSTSEC-2023-0071
  timing risk; `legacy` alone does not enable it. Encryption, signatures,
  AWS-LC and PKCS#11 policies are unchanged. Capability queries distinguish
  encryption from decryption, and opted-in decryption enables exponent blinding.
- Bind imported X25519 private/public components on both providers; mismatched
  supplied public metadata now rejects.
- Require readable, unique PKCS#11 key type and parameter attributes matching
  the declared RSA/EC/AES/HMAC operation. RSA moduli must be at least 2048 bits,
  AES lengths and EC curves must match, and ECDH length must match its curve.
  Tokens that hide required parameters now fail closed.
- Blind RustCrypto RSA private exponentiation for both PKCS#1 v1.5 and PSS
  signing. Signature encodings are unchanged; this does not resolve the
  upstream RSA timing advisory.
- Enable the already-used GHASH/POLYVAL zeroization features and guard
  PKCS#11 value-attribute copies on error and unwind paths. Internal cryptoki
  retrieval copies remain an upstream limitation.
- Enforce AWS-LC's FIPS HKDF parameter requirements: nonempty `info` and
  no explicitly empty salt. Non-FIPS HKDF retains RFC 5869 compatibility.
- Refuse software AES-192-GCM decryption and odd-bit RSA imports in FIPS builds,
  matching the pinned module's service approval conditions. Non-FIPS
  interoperability remains available.
- Refuse software RSA key transport in FIPS builds because the pinned
  implementation is outside the validated module. Software capability
  approval flags now reflect this; PKCS#11 retains its separate token policy.
- Enable secret wiping in the existing AES, AES-KW, CBC, 3DES and SLH-DSA
  dependencies; wipe additional KDF, CBC and post-quantum seed intermediates.
- Correct RustCrypto OAEP and legacy PBKDF2 capability reporting to match
  implemented digest combinations. Route ML-KEM initialization and entropy
  through the selected provider boundary.
- Surface PKCS#11 temporary-object cleanup failures when reading also fails,
  and borrow token-hashed signature messages instead of copying them.
- Reduce AWS-LC GCM and AES-KW buffer allocations while retaining the wire
  formats, authentication checks and module-generated GCM nonces. Local
  measurements and workloads are in [docs/performance.md](docs/performance.md).
- Document that hazmat finite-field DH requires independently validated
  prime group parameters and protocol-appropriate strength.

## 0.6.2 — 2026-09-24

- RSA keys below 2048 bits are refused when they are used (signing,
  verification, key transport) instead of at import, on both providers, as
  kryptering did with AWS-LC. Callers get the "N-bit RSA key" error at the
  point of use; XML-DSig callers that skip unusable inline keys now see that
  error instead of a missing-key error. FIPS builds still refuse them at
  import. RustCrypto with `legacy` still accepts them.

## 0.6.1 — 2026-09-24

- The RustCrypto provider accepts RSA keys below 2048 bits again when the
  `legacy` feature is enabled, restoring kryptering's interoperability with
  historical signatures and encrypted documents (for example the xmlsec
  interop corpus used by ribergshamra). Without `legacy`, and always with
  AWS-LC or FIPS, the 2048-bit minimum stays.

## 0.6.0 — 2026-09-24 — first riptering release

Changes relative to kryptering 0.5.0
(upstream commit `cb733df`):

### Changed

- **Breaking:** the crate is renamed `riptering` (`use riptering::...`).
  Existing code can keep its paths with
  `kryptering = { package = "riptering", version = "0.6" }`. Error messages
  name riptering (for example "riptering requires at least 2048 bits"), and
  the SoftHSM2 integration test reads `RIPTERING_TEST_SOFTHSM2_MODULE`
  instead of `KRYPTERING_TEST_SOFTHSM2_MODULE`.
- **Breaking (AWS-LC provider):** `Pbkdf2Params::recommended` takes the hash
  algorithm first, `recommended(hash, salt, key_length)`, matching the
  RustCrypto provider, and picks the OWASP iteration count for that hash.
- The non-FIPS AWS-LC provider also builds on macOS x86_64/aarch64. FIPS
  builds stay Linux-only; this is not a claim of FIPS certification.
- Provider parity: the RustCrypto and AWS-LC providers accept the same ECDSA
  signature encodings, reject RSA keys below 2048 bits at import, restrict
  raw key import to symmetric families and check key types for X25519/ECDH.
  AWS-LC implements raw `ecdh_x25519` and verifies the cross curve/digest
  ECDSA pairs XML-DSig produces.
- Package metadata points at <https://github.com/Rhein-Industries/riptering>;
  LICENSE keeps Kushal Das's copyright line and adds Rhein Industries' line
  for the fork's modifications.

### Security

- FIPS (AWS-LC): PBKDF2, HKDF and ConcatKDF use the AWS-LC module
  implementations; PBKDF2 enforces the SP 800-132 minimums (1000
  iterations, 112-bit passwords); AES-128/256-GCM nonces are generated
  inside the module; AES-192-GCM encryption and SHA-224 PBKDF2/HKDF are no
  longer reported as approved.
- RustCrypto: AES-CBC rejects IV-only input, AES-KW enforces RFC 3394
  lengths, the RSA-PSS salt length is bounded, DH group parameters and
  exponents are validated, post-quantum key pairs are checked on import, and
  more secret intermediates are zeroized.
- PKCS#11: concurrent sessions on one token; a session joining an existing
  login must present the PIN riptering logged in with, and three mismatches
  lock further joins until riptering's sessions on the token close; raw-byte
  PINs (`open_session_bytes`); KEK length checks; AES key wrap through
  `C_WrapKey`/`C_UnwrapKey` where the token only offers those; the FIPS ECDH
  curve is read from `CKA_EC_PARAMS`; derived ECDH secrets are session
  objects that are always destroyed.
- Raise the `rustls` minimum to 0.23.45 (RUSTSEC-2026-0285) and the
  `cryptoki` minimum to 0.12.1 (RUSTSEC-2026-0286). `Cargo.lock` moves to
  rustls 0.23.45, rustls-webpki 0.103.15, cryptoki 0.12.1, and — because
  rustls 0.23.45 requires aws-lc-rs 1.18 — aws-lc-rs 1.18.1, aws-lc-sys
  0.45.0 and aws-lc-fips-sys 0.14.2. The lockfile now also records the
  `cryptoki-sys` dev-dependency, so `--locked` builds succeed.
- `.cargo/audit.toml` drops the RUSTSEC-2026-0097 ignore: the locked rand
  0.8.7 is patched. RUSTSEC-2023-0071 (rsa, no fixed release) stays
  ignored with a re-checked justification.

### Testing and CI

- `tests/provider_parity.rs` runs identical cases against every provider,
  including FIPS, where unapproved operations must be refused as
  unsupported. The baseline and parity suites and the unit tests run under
  FIPS with explicit backend initialization.
- `tests/pkcs11_softhsm.rs` exercises the PKCS#11 backend end to end
  against a private SoftHSM2 token.
- GitHub Actions on GitHub-hosted runners: format, clippy and tests for
  every provider on Rust 1.88 (MSRV) and stable, PKCS#11 against SoftHSM2,
  the Linux FIPS build, and macOS for the default and non-FIPS AWS-LC
  providers. Upstream's tag-triggered crates.io publish workflow is removed;
  publishing is manual for now. The weekly `cargo audit` run is kept.
- `clippy -D warnings` is clean on Rust 1.88 (inlined format arguments that
  clippy 1.88 flags), and `cargo doc` is warning-free without the
  `post-quantum` feature (a doc link to the feature-gated
  `export_composite_public` no longer breaks).
- Added `SECURITY.md` and `CONTRIBUTING.md`.

## kryptering history (upstream, up to 0.5.0)

The entries below are kryptering's own changelog, by Kushal Das and the
kryptering contributors, as of the fork point. Headings are demoted one
level; the text is unchanged.

### 0.5.0 - [unreleased]

#### Added

- Compile-time RustCrypto and AWS-LC document providers, with independent
  ring/AWS-LC TLS provider selection.
- Provider identity, initialization, FIPS status, parameterized capability
  reporting, attested TLS configuration, opaque `SoftwareKey`, and structured
  initialization/unsupported-algorithm errors.
- Provider implementations for RNG, digest/HMAC, signatures, AES-CBC/GCM,
  AES-KW, RSA transport, ECDH/X25519, KDFs, and PKCS#12 primitives.
- A provider-wide known-answer/negative baseline, an enumerable capability
  registry, and active AWS-LC document/TLS FIPS attestation on x86_64 and
  aarch64 CI runners.

- ML-KEM (FIPS 203) support behind the `post-quantum` feature:
  `generate_ml_kem` for ML-KEM-512/768/1024 key generation, and
  `SoftwareEncapsulator` / `SoftwareDecapsulator` implementing the new
  `Encapsulator` / `Decapsulator` traits. Keys follow the ML-DSA
  conventions: SPKI DER public key, 64-byte FIPS 203 seed (`d || z`) as
  the stored private key with PKCS#8 DER (LAMPS seed-only form) also
  accepted on load. Encapsulation draws its FIPS 203 message `m` via
  `getrandom::fill` so OS-RNG failure surfaces as `Error::Crypto`
  instead of a panic (ADR 0001). Shared secrets are returned as
  `zeroize::Zeroizing<Vec<u8>>` so they are wiped on drop (DRR03-L-02).
  NIST ACVP known-answer vectors for key generation (all variants) and
  encapsulation (ML-KEM-768) pass byte-for-byte.

#### Changed

- **Breaking:** digest and streaming digest creation are fallible, and software
  signing/key-transport APIs accept opaque provider keys.
- **Breaking:** finite-field DH agreement now accepts an opaque `SoftwareKey`;
  the private exponent is no longer exported to downstream callers.
- Exactly one document provider is required; `--all-features` is intentionally
  invalid. FIPS builds require explicit initialization.
- **Breaking:** `PqAlgorithm` gains an `MlKem` variant (affects
  downstream exhaustive matches).
- MSRV raised from 1.83 to 1.88 for the coordinated provider release and its
  resolved dependency graph.
- FIPS mode currently selects AWS-LC exclusively.

#### Security

- PKCS#11 signing, verification, key transport, key wrap, and cipher
  operations now enforce the FIPS algorithm allowlist via
  `backend::require_fips_approved` before reaching the token. Previously the
  HSM path only checked process initialization, so SHA-1 RSA, Ed25519, and
  SHA-1 OAEP could proceed in `fips` builds.
- Bound PBKDF2 (`PBKDF2_MAX_ITERATIONS = 100_000_000`) and the PKCS#12 KDF
  (`iterations <= 100_000_000`) iteration counts, and capped
  `random_bytes` allocations at 1 MiB (`RANDOM_BYTES_MAX_LEN`), closing
  CPU/memory denial-of-service vectors from attacker-controlled parameters.
- The AWS-LC provider's streaming digest now wraps
  `aws_lc_rs::digest::Context` so input is hashed incrementally in constant
  memory, matching the RustCrypto provider; the previous `BufferedDigest`
  accumulated the entire input before hashing.
- The AWS-LC `SoftwareVerifier` now validates that the key family matches the
  signature algorithm at construction, matching the RustCrypto path and
  failing fast instead of relying on SPKI import to surface mismatches.
- The alternate-provider ECDSA/DSA DER signature parser now enforces DER
  canonicality (minimal length and integer encodings per X.690 §8.1.3.3 /
  §8.3.2), rejecting non-minimal encodings that yield a second, distinct
  byte string for the same r||s — a signature-malleability surface for
  consensus callers.
- The PKCS#12 KDF (`pkcs12::derive`, `decrypt_pbe_sha1_3des`) and the PBES2
  helper (`decrypt_pbes2_aes256cbc`) now take `&str` passwords and encode
  them as RFC 7292 Appendix B.1 BMPString (UTF-16BE + trailing NUL) before
  hashing; the previous `&[u8]` API hashed raw bytes and produced keys
  incompatible with standard `.p12` files.
- The AWS-LC RSA verification path's minimum modulus size is raised from
  1024 to 2048 bits to match the import path's `RSA_PKCS1_2048_8192_*`
  floor, removing an inconsistent threshold between the two code paths.

### 0.4.1 - [2026-07-01]

#### Changed

- Bump the `cipher 0.5` wave to current stable finals: `aes 0.9`,
  `aes-gcm 0.11`, `aes-kw 0.3`, `cbc 0.2`, and `des 0.9` (legacy). Migrate
  the AES-CBC, AES-GCM, AES-KW, and 3DES-CBC/KW code to the new
  `BlockModeEncrypt`/`BlockModeDecrypt` traits, `AesKw`/`wrap_key`/`unwrap_key`
  API, and non-deprecated nonce construction. RFC 3394 / NIST SP 800-38F
  key-wrap known-answer vectors still pass byte-for-byte.
- Refresh compatible dependency versions in `Cargo.lock`.

#### Security

- Update `crypto-bigint` `0.7.3 -> 0.7.5`, clearing a `cargo audit` warning
  for the yanked `0.7.3` release.

#### Notes

- Pin `generic-array` to `0.14.7` (the last release without the
  `from_slice` deprecation) to keep `clippy -D warnings` clean while the
  `digest 0.11` wave remains blocked on stable `rsa 0.10` / `ecdsa 0.17`.
- Keep `rsa` on `0.9.10`; the `digest 0.11` / `signature 3` / `rand_core 0.10`
  wave has no stable finals yet (RSA, ECDSA, the P-curves, and the dalek
  crates are pre-release only). See `docs/ecosystem.md`.

### 0.4.0 - [2026-06-27]

#### Security

- Reject ambiguous PKCS#11 token and object selection instead of silently using
  the first match.
- Add explicit PKCS#11 slot, token, and object-id selection helpers.
- Reject high-level PKCS#11 AES-CBC use; AES-GCM remains supported.
- Reject invalid finite-field DH subgroup order `q = 0`.
- Reject invalid HKDF and ConcatKDF output lengths before allocation or
  derivation.
- Reject 3DES-CBC IV-only ciphertext.

#### Changed

- Refresh compatible dependency versions in `Cargo.lock`.
- Keep `rsa` on `0.9.10`; no stable patched upgrade is available for the tracked RustSec advisory.
