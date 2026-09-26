# Local performance measurements

The synthetic harness in [`examples/performance.rs`](../examples/performance.rs)
measures reusable signer/verifier operations, construction around a shared key,
PKCS#8/SPKI/raw key import, and AES-256-GCM / AES-256-KW buffers. No HSM, service,
production key, or credential is used. RSA-2048, P-256 and Ed25519 fixtures are
generated from fixed test seeds outside timed regions; signatures use 256-byte
messages. Buffer workloads use 32, 4096 and 65536 bytes.

## Environment and commands

Measurements were collected on 2026-09-26 using an Apple M4 Max, macOS 26.2,
`aarch64-apple-darwin`, and Rust 1.90.0. The working tree started at `3819951`.
AWS-LC before/after refers to the focused buffer changes in this review;
concurrent KDF and provider-policy hardening did not change these workloads.
RustCrypto measurements include this review's memory-hygiene changes; there is
no RustCrypto before/after claim.

The retained RustCrypto timings predate the later RSA signing-blinding and
GHASH/POLYVAL wiping changes. They are historical measurements of that earlier
working tree, not performance claims for the final hardened implementation.

```sh
# Before AWS-LC buffer changes. --offline also refreshed the lockfile's
# existing dependency feature edges; package versions were unchanged.
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo run --offline --release \
  --no-default-features --features aws-lc --example performance \
  > docs/performance-before.csv

# After AWS-LC buffer changes.
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo run --locked --release \
  --no-default-features --features aws-lc --example performance \
  > docs/performance-after.csv

# Separate default RustCrypto provider measurement.
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo run --locked --release \
  --example performance > docs/performance-rustcrypto.csv
```

`RIPTERING_BENCH_ONLY=buffers` or `signatures` narrows a rerun. Every measurement
warms the operation eight times and reports the median of five timed samples.
Iteration counts are recorded in the CSVs. Allocation measurements run eight
additional operations with counters enabled, separately from timing, and
report the average per operation. Roundtrip checks and altered-message
verification checks run before timed workloads.

## Implemented AWS-LC buffer improvement

GCM encryption now reserves its complete nonce/ciphertext/tag wire buffer and
seals in place with a separate tag. GCM decryption and AES-KW return their
original owned output buffers instead of allocating another copy. Temporary
plaintext-bearing buffers are guarded by `Zeroizing`; the successful return
transfers ownership through the existing `Vec<u8>` API. AES-128/256 GCM still
uses AWS-LC's module-generated randomized nonce API.

| Workload | Bytes | Rust allocation calls, before → after | Requested allocation bytes, before → after | Median ns/op, before → after |
|---|---:|---:|---:|---:|
| GCM encrypt | 32 | 3 → 1 | 156 → 60 | 2467 → 2350 |
| GCM encrypt | 4096 | 3 → 1 | 16412 → 4124 | 2950 → 2824 |
| GCM encrypt | 65536 | 3 → 1 | 262172 → 65564 | 12159 → 11107 |
| GCM decrypt | 32 | 2 → 1 | 80 → 48 | 162 → 149 |
| GCM decrypt | 4096 | 2 → 1 | 8208 → 4112 | 666 → 608 |
| GCM decrypt | 65536 | 2 → 1 | 131088 → 65552 | 9557 → 8498 |
| KW wrap | 32 | 3 → 2 | 112 → 72 | 400 → 389 |
| KW wrap | 4096 | 3 → 2 | 8240 → 4136 | 40996 → 42388 |
| KW wrap | 65536 | 3 → 2 | 131120 → 65576 | 670577 → 656494 |
| KW unwrap | 32 | 3 → 2 | 96 → 64 | 408 → 396 |
| KW unwrap | 4096 | 3 → 2 | 8224 → 4128 | 41274 → 41799 |
| KW unwrap | 65536 | 3 → 2 | 131104 → 65568 | 669050 → 658831 |

The defensible result is the reduced Rust allocation count and copied buffer
volume. GCM timings improved in this run. AES-KW timing differences are small
and mixed; no general AES-KW latency improvement is claimed.

## Reuse and import observations

AWS-LC reparses private PKCS#8 keys on every `sign` and SPKI keys on every
`verify`, even when the operation object is reused. Construction around an
already imported shared key therefore adds little work to each operation.
Before-change medians for reusable versus recreated signers were:

| Algorithm | Reuse ns/op | Recreate ns/op | PKCS#8 import ns/op |
|---|---:|---:|---:|
| RSA-2048 PKCS#1 SHA-256 | 500236 | 500096 | 89685 |
| P-256 SHA-256 | 18110 | 18325 | 7245 |
| Ed25519 | 8427 | 8489 | 4105 |

These measurements support investigating a prepared AWS-LC key pair and
`ParsedPublicKey` per operation object in a separate change. They do not
measure that cache design or establish its eventual speedup. Such a change
must preserve provider capability checks, FIPS policy, thread safety, signature
normalization and secret cleanup, and document changed import-error timing.

The RustCrypto CSV also shows shared handle construction is inexpensive and
key imports should be kept outside per-message work where possible. For
example, P-256 PKCS#8 import took 161938 ns/op and reused signing 100495 ns/op in
this run. RustCrypto RSA operation helpers still clone owned RSA key material
per call; this is a future profiling candidate, not an implemented rewrite.

## Limits

The allocator wrapper forwards unchanged pointers/layouts to `System` and
counts only Rust global-allocator requests. AWS-LC's native allocations are
excluded, so allocation totals must not be interpreted as cross-provider
memory comparisons. Requested byte counts include the entire requested size
of reallocations, not net live bytes or measured peak memory. Randomized
signature paths can have varying allocation counts.

This is one local baseline and one after run for AWS-LC, plus one RustCrypto
run, with no CPU isolation,
confidence intervals, warm/cold cache separation, throughput contention, FIPS
module build, or real HSM. Clock differences of a few percent may be noise;
the after run's unchanged signature workloads illustrate that variability.
The initial AWS-LC release build failed because the shared disk ran out of
space. After cleaning only task-generated build output, the successful runs
completed without changing workloads. Linux/FIPS and HSM performance remain
unmeasured here.

## PKCS#11 preparation and mock contention

```sh
CARGO_INCREMENTAL=0 cargo test --locked --release --lib pkcs11::tests:: \
  -- --ignored --nocapture --test-threads=1 > docs/performance-pkcs11.txt 2>&1
```

The ignored message-preparation benchmark compares the previous
`data.to_vec()` helper with the current borrowed helper in the same process,
using RSA-PSS tags and synthetic messages. It alternates sample ordering and
uses `black_box`; medians of three samples were:

| Message bytes | Iterations/sample | Copy ns/op | Borrow ns/op | Preparation allocations, before → after |
|---|---:|---:|---:|---:|
| 64 | 100000 | 21.272 | 0.799 | 1 → 0 |
| 4096 | 50000 | 57.705 | 0.751 | 1 → 0 |
| 1048576 | 500 | 13092.916 | 0.916 | 1 → 0 |

Borrowed variant and pointer-identity regression checks establish the removed
allocation/copy. The tiny borrowed-helper timings measure pointer/variant
handling only; they are not PKCS#11 signature timings. RSA/Ed25519 token-hashed
signing and verification benefit; ECDSA preprocessing still hashes, and the
separate HMAC signer already borrowed its message.

The mutex-topology mock uses four threads, 64 operations per thread, and a
1 ms sleeping token call. Three samples gave median **321.296 ms** for one
shared session and **79.935 ms** for four independent sessions (256 operations
each). This demonstrates serialization by the existing session mutex, not
hardware throughput or measured changes to locking. No session-pool or login
lock rewrite was made. Real tokens, their concurrency limits, login semantics,
and scheduler effects require separate measurements.
