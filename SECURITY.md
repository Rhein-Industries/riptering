# Security policy

riptering is Rhein Industries' maintained fork of
[kryptering](https://github.com/kushaldas/kryptering). Security problems in
riptering are handled by Rhein Industries. Please do not send riptering
reports to the kryptering author.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting on the repository once it is published:

<https://github.com/Rhein-Industries/riptering/security/advisories/new>

Do not open a public issue, pull request or discussion for a suspected
vulnerability. Please include:

- the affected version or commit, and the enabled features (document
  provider, TLS provider, `fips`, `pkcs11`, `legacy`, `legacy-rsa-decryption`,
  `post-quantum`);
- the platform and, for PKCS#11 issues, the token or HSM module;
- a description of the impact and, if possible, a minimal reproduction.

We acknowledge reports as soon as we can and agree on a disclosure timeline
with the reporter. Fixes are released as a patch release and announced
through a GitHub security advisory; we also request a RustSec advisory where
appropriate.

If the problem also affects upstream kryptering, we notify its author
privately before any public disclosure.

## Supported versions

| Version | Supported |
|---|---|
| 0.6.x (latest) | Yes |
| < 0.6 | No (kryptering releases; see upstream) |

Only the latest 0.6.x release receives security fixes.

## Scope notes

- A `fips` build selects AWS-LC's FIPS module and requires explicit
  initialization. Enabling the feature is not a statement that an
  application or deployment is FIPS certified.
- The RustCrypto provider uses the `rsa` crate, which is affected by
  RUSTSEC-2023-0071 (Marvin timing side channel) with no fixed release. See
  `.cargo/audit.toml` for the rationale and mitigations (the AWS-LC
  provider or a PKCS#11 HSM for RSA private-key operations).
  RSA-OAEP and PKCS#1 v1.5 decryption are refused by default in RustCrypto,
  before key/ciphertext/label use. The independent `legacy-rsa-decryption`
  feature explicitly restores affected operations for compatibility and
  retains the advisory risk; enabling `legacy` alone does not enable them.
  RustCrypto RSA signing now enables exponent blinding, independently of
  PSS salt generation; opted-in decryption also enables exponent blinding.
  This is additional hardening, not evidence that the
  advisory is fixed or that private RSA operations are timing-safe.
- PKCS#11 constructors fail closed when key type, modulus/curve or AES length
  cannot be read and bound to the declared operation. A conforming attribute
  response is not hardware/provider certification. Consumers must independently
  validate their token and its deployment policy.
- Owned PKCS#11 CKA_VALUE templates and retrieved values are wiped on drop;
  cryptoki 0.12.1 still makes an internal retrieval copy outside this library's
  ownership. Caller-owned outputs and native module internals require their
  own secret-memory policy.
