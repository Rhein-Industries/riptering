# Contributing to riptering

riptering is Rhein Industries' maintained fork of
[kryptering](https://github.com/kushaldas/kryptering). Issues and pull
requests are welcome at <https://github.com/Rhein-Industries/riptering>.
Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License of contributions

riptering is licensed under BSD-2-Clause (see [LICENSE](LICENSE)). By
submitting a contribution you agree that it is licensed under the same
terms. No contributor license agreement and no DCO sign-off are required.

## Provider parity

riptering selects exactly one document provider (`rustcrypto` or `aws-lc`)
at compile time. A change to one provider must keep the other behaving the
same: the same inputs are accepted or rejected, and the same outputs are
produced. Add the case to `tests/provider_parity.rs`, which runs against
every provider including FIPS, where operations FIPS does not approve must be
refused as `UnsupportedAlgorithm` rather than skipped. If a provider
genuinely cannot support an operation, report it through the capability
registry and document it in [docs/providers.md](docs/providers.md).

## Checks

CI runs the matrix below (see `.github/workflows/ci.yml`). Please run the
parts your change touches before opening a pull request; `--all-features` is
intentionally invalid because the providers are mutually exclusive.

Linux, macOS and Windows run the complete RustCrypto unit, integration and
documentation test suites on both Rust 1.88 and stable. Each platform tests
default decryption refusal, post-quantum and legacy algorithms, the independent
`legacy-rsa-decryption` opt-in, and that opt-in together with `legacy`. Strict
Clippy and API documentation checks run on the MSRV. Linux and macOS also run
the non-FIPS AWS-LC suites, including the inert RSA opt-in, and TLS provider
tests. AWS-LC is not supported on Windows by this crate.

Linux requires a working SoftHSM2 module and exercises PKCS#11 with both
non-FIPS providers. On macOS and Windows, the PKCS#11 code is compiled and its
ordinary unit tests run, but the SoftHSM2 integration test returns without
testing a token unless its module variable is set. FIPS initialization,
attestation, known-answer, parity and baseline tests run separately on Linux
x86_64 and aarch64; the non-FIPS SoftHSM2 harness is excluded from FIPS builds.
These gates do not replace validation against a deployment's physical HSM.

```bash
cargo fmt --all -- --check

# RustCrypto provider (default: rustcrypto + pkcs11)
cargo clippy --all-targets -- -D warnings
cargo test
cargo clippy --all-targets --features post-quantum,legacy -- -D warnings
cargo test --features post-quantum,legacy
cargo clippy --all-targets --features legacy-rsa-decryption -- -D warnings
cargo test --features legacy-rsa-decryption
cargo clippy --all-targets --features legacy,legacy-rsa-decryption -- -D warnings
cargo test --features legacy,legacy-rsa-decryption

# AWS-LC provider (Linux, or macOS without fips)
cargo clippy --all-targets --no-default-features --features aws-lc,legacy,pkcs11 -- -D warnings
cargo test --no-default-features --features aws-lc
cargo test --no-default-features --features aws-lc,legacy
cargo test --no-default-features --features aws-lc,legacy,legacy-rsa-decryption

# PKCS#11 against SoftHSM2 (mandatory in Linux CI; otherwise skipped unless set)
export RIPTERING_TEST_SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
cargo test --test pkcs11_softhsm -- --nocapture
cargo test --no-default-features --features aws-lc,pkcs11 --test pkcs11_softhsm -- --nocapture

# AWS-LC FIPS provider (Linux only; building the module needs Go and CMake)
cargo clippy --all-targets --no-default-features --features fips,tls-aws-lc,pkcs11 -- -D warnings
cargo test --no-fail-fast --no-default-features --features fips,tls-aws-lc

# API docs
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

The minimum supported Rust version is 1.88 (`rust-version` in `Cargo.toml`).
Keep `Cargo.lock` committed and update dependencies with targeted
`cargo update -p <crate>`; `cargo audit --deny warnings` must stay clean, and
every entry in `.cargo/audit.toml` needs a written justification.

## Changelog and releases

Add a line to `CHANGELOG.md` for user-visible changes. Publishing to
crates.io is manual for now: a Rhein Industries maintainer runs
`cargo publish` from a tagged commit after CI passes.
