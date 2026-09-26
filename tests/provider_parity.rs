//! Common cases and explicit policy differences under every document provider.
//!
//! Each test runs against whichever provider the build selects, so CI runs
//! this file once per provider feature set. FIPS builds run every case too:
//! approved operations must give the same answers, and operations FIPS does
//! not approve must be refused as unsupported rather than skipped.

use riptering::kdf::{HkdfParams, Pbkdf2Params};
use riptering::{
    AesKeySize, EcCurve, HashAlgorithm, KeyAlgorithm, KeyWrapAlgorithm, Operation,
    SignatureAlgorithm, SoftwareKey, SoftwareSigner, SoftwareVerifier,
};
use riptering::{Signer, Verifier};

fn decode(hex_value: &str) -> Vec<u8> {
    hex::decode(hex_value).expect("valid test vector")
}

/// Assert that `operation` was refused as unsupported, as FIPS builds do for
/// every operation the module does not approve.
fn assert_refused<T>(result: riptering::Result<T>, operation: Operation) {
    match result {
        Err(riptering::Error::UnsupportedAlgorithm {
            operation: actual, ..
        }) if actual == operation => {}
        Err(error) => panic!("{operation:?} failed without being refused: {error}"),
        Ok(_) => panic!("{operation:?} was accepted"),
    }
}

#[test]
fn raw_symmetric_import_rejects_asymmetric_families() {
    riptering::initialize_backend().expect("provider initialization");
    for algorithm in [
        KeyAlgorithm::Rsa,
        KeyAlgorithm::Ec(EcCurve::P256),
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::X25519,
        KeyAlgorithm::Dh,
    ] {
        assert!(
            SoftwareKey::from_symmetric_bytes(algorithm, b"not a raw symmetric key").is_err(),
            "{algorithm:?} accepted raw bytes"
        );
    }
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").is_ok());
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[0; 32]).is_ok());
    assert!(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[0; 20]).is_err());
}

#[test]
fn x25519_agreement_matches_rfc7748_and_checks_key_type() {
    riptering::initialize_backend().expect("provider initialization");
    // RFC 7748 §6.1.
    let alice_private = decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_public = decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let aes = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Aes, &[7; 32]).unwrap();

    if cfg!(feature = "fips") {
        // X25519 is not FIPS approved: every entry point refuses the RFC
        // inputs before inspecting them or the key type.
        assert_refused(
            riptering::keyagreement::ecdh_x25519(&bob_public, &alice_private),
            Operation::X25519Agreement,
        );
        assert_refused(
            SoftwareKey::from_x25519(Some(&alice_private), &alice_public),
            Operation::KeyImport(KeyAlgorithm::X25519),
        );
        assert_refused(
            riptering::keyagreement::agree_x25519(&bob_public, &aes),
            Operation::X25519Agreement,
        );
    } else {
        assert_eq!(
            riptering::keyagreement::ecdh_x25519(&bob_public, &alice_private).unwrap(),
            shared
        );
        let alice = SoftwareKey::from_x25519(Some(&alice_private), &alice_public).unwrap();
        assert_eq!(alice.public_component().unwrap(), alice_public);
        assert!(SoftwareKey::from_x25519(Some(&alice_private), &bob_public).is_err());
        assert!(SoftwareKey::from_x25519(Some(&alice_private), &[0; 32]).is_err());
        assert!(SoftwareKey::from_x25519(None, &bob_public).is_ok());
        assert_eq!(
            riptering::keyagreement::agree_x25519(&bob_public, &alice).unwrap(),
            shared
        );

        assert!(riptering::keyagreement::agree_x25519(&bob_public, &aes).is_err());
        assert!(riptering::keyagreement::ecdh_x25519(&bob_public, &alice_private[..31]).is_err());
    }
}

#[test]
fn signers_reject_keys_of_another_family() {
    riptering::initialize_backend().expect("provider initialization");
    let hmac = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").unwrap();
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
        SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256),
        SignatureAlgorithm::Ed25519,
    ] {
        assert!(SoftwareSigner::new(algorithm, hmac.clone()).is_err());
        assert!(SoftwareVerifier::new(algorithm, hmac.clone()).is_err());
    }
    if cfg!(feature = "fips") {
        // FIPS refuses Ed25519 itself, before the key family is checked.
        assert_refused(
            SoftwareSigner::new(SignatureAlgorithm::Ed25519, hmac.clone()),
            Operation::Sign(SignatureAlgorithm::Ed25519),
        );
        assert_refused(
            SoftwareVerifier::new(SignatureAlgorithm::Ed25519, hmac),
            Operation::Verify(SignatureAlgorithm::Ed25519),
        );
    }
}

#[test]
fn oaep_capabilities_reject_unimplemented_hashes_before_key_use() {
    use riptering::{KeyTransportAlgorithm, OaepConfig};

    riptering::initialize_backend().expect("provider initialization");
    let wrong_key = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").unwrap();
    let registry = riptering::capabilities().unwrap();
    let mut unsupported = Vec::new();
    for hash in [
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
    ] {
        unsupported.push(OaepConfig {
            digest: hash,
            mgf_digest: HashAlgorithm::Sha256,
        });
        unsupported.push(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: hash,
        });
    }
    #[cfg(feature = "legacy")]
    for hash in [HashAlgorithm::Md5, HashAlgorithm::Ripemd160] {
        unsupported.push(OaepConfig {
            digest: HashAlgorithm::Sha256,
            mgf_digest: hash,
        });
    }
    for config in unsupported {
        let algorithm = KeyTransportAlgorithm::RsaOaep(config);
        let encrypt = Operation::TransportEncrypt(algorithm);
        let decrypt = Operation::TransportDecrypt(algorithm);
        for operation in [encrypt, decrypt] {
            assert!(!riptering::supports(operation).unwrap(), "{operation:?}");
            assert!(!registry.iter().any(|entry| entry.operation == operation));
        }
        // A rejected parameter pair must fail before this wrong-family key
        // could produce Error::Key or cause any key material to be used.
        assert_refused(
            riptering::keytransport::kt_encrypt(algorithm, &wrong_key, b"key", None),
            encrypt,
        );
        assert_refused(
            riptering::keytransport::kt_decrypt(algorithm, &wrong_key, b"ciphertext", None),
            decrypt,
        );
    }
}

#[test]
fn oaep_independent_mgf_support_matches_actual_operations() {
    use riptering::{KeyTransportAlgorithm, OaepConfig};

    riptering::initialize_backend().expect("provider initialization");
    let algorithm = KeyTransportAlgorithm::RsaOaep(OaepConfig {
        digest: HashAlgorithm::Sha256,
        mgf_digest: HashAlgorithm::Sha384,
    });
    assert_eq!(
        riptering::supports(Operation::TransportEncrypt(algorithm)).unwrap(),
        cfg!(feature = "rustcrypto")
    );
    assert_eq!(
        riptering::supports(Operation::TransportDecrypt(algorithm)).unwrap(),
        cfg!(all(
            feature = "rustcrypto",
            feature = "legacy-rsa-decryption"
        ))
    );
    #[cfg(feature = "rustcrypto")]
    {
        use rsa::pkcs8::EncodePrivateKey;

        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let key = SoftwareKey::from_pkcs8_der(
            KeyAlgorithm::Rsa,
            private.to_pkcs8_der().unwrap().as_bytes(),
        )
        .unwrap();
        let wrapped =
            riptering::keytransport::kt_encrypt(algorithm, &key, b"synthetic key", None).unwrap();
        let decrypted = riptering::keytransport::kt_decrypt(algorithm, &key, &wrapped, None);
        if cfg!(feature = "legacy-rsa-decryption") {
            assert_eq!(decrypted.unwrap(), b"synthetic key");
        } else {
            assert_refused(decrypted, Operation::TransportDecrypt(algorithm));
        }
    }
    #[cfg(feature = "aws-lc")]
    {
        let wrong_key = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").unwrap();
        assert_refused(
            riptering::keytransport::kt_encrypt(algorithm, &wrong_key, b"key", None),
            Operation::TransportEncrypt(algorithm),
        );
        assert_refused(
            riptering::keytransport::kt_decrypt(algorithm, &wrong_key, b"ciphertext", None),
            Operation::TransportDecrypt(algorithm),
        );
    }
}

#[test]
fn software_rsa_transport_respects_the_fips_module_boundary() {
    use riptering::{KeyTransportAlgorithm, OaepConfig};

    riptering::initialize_backend().expect("provider initialization");
    let algorithm = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
    let registry = riptering::capabilities().unwrap();
    for operation in [
        Operation::TransportEncrypt(algorithm),
        Operation::TransportDecrypt(algorithm),
    ] {
        assert_eq!(
            riptering::supports(operation).unwrap(),
            !cfg!(feature = "fips")
                && (matches!(operation, Operation::TransportEncrypt(_))
                    || !cfg!(feature = "rustcrypto")
                    || cfg!(feature = "legacy-rsa-decryption"))
        );
        if let Some(entry) = registry.iter().find(|entry| entry.operation == operation) {
            assert!(!entry.fips_approved);
        }
    }
    if cfg!(feature = "fips") {
        // The refusal must happen before parsing/using key material, even for
        // the otherwise supported SHA-256 OAEP parameter combination.
        let wrong_key = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"secret").unwrap();
        assert_refused(
            riptering::keytransport::kt_encrypt(algorithm, &wrong_key, b"key", None),
            Operation::TransportEncrypt(algorithm),
        );
        assert_refused(
            riptering::keytransport::kt_decrypt(algorithm, &wrong_key, b"ciphertext", None),
            Operation::TransportDecrypt(algorithm),
        );
    }
}

#[cfg(all(feature = "rustcrypto", not(feature = "legacy-rsa-decryption")))]
#[test]
fn rustcrypto_rsa_decryption_requires_separate_opt_in_before_key_use() {
    use riptering::{KeyTransportAlgorithm, OaepConfig};

    riptering::initialize_backend().unwrap();
    let wrong_key =
        SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"synthetic key").unwrap();
    let mut algorithms = vec![
        KeyTransportAlgorithm::RsaOaep(OaepConfig::default()),
        KeyTransportAlgorithm::RsaOaep(OaepConfig {
            digest: HashAlgorithm::Sha1,
            mgf_digest: HashAlgorithm::Sha256,
        }),
    ];
    #[cfg(feature = "legacy")]
    algorithms.push(KeyTransportAlgorithm::RsaPkcs1v15);
    let registry = riptering::capabilities().unwrap();
    for algorithm in algorithms.drain(..) {
        let operation = Operation::TransportDecrypt(algorithm);
        assert!(!riptering::supports(operation).unwrap());
        assert!(!registry.iter().any(|entry| entry.operation == operation));
        // Both public access paths share the software implementation; refusal
        // precedes wrong key-family, empty ciphertext and invalid label errors.
        for decrypt in [
            riptering::keytransport::kt_decrypt,
            riptering::software::keytransport::kt_decrypt,
        ] {
            let result = decrypt(algorithm, &wrong_key, &[], Some(&[0xff]));
            assert!(result
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("legacy-rsa-decryption"));
            assert_refused(result, operation);
        }
    }
}

#[cfg(feature = "legacy")]
#[test]
fn legacy_pkcs1_transport_preserves_encryption_and_obeys_decryption_policy() {
    use riptering::KeyTransportAlgorithm;
    use rsa::pkcs8::EncodePrivateKey;

    riptering::initialize_backend().unwrap();
    let algorithm = KeyTransportAlgorithm::RsaPkcs1v15;
    let encrypt = Operation::TransportEncrypt(algorithm);
    let decrypt = Operation::TransportDecrypt(algorithm);
    let decryption_enabled = !cfg!(feature = "fips")
        && (cfg!(feature = "aws-lc") || cfg!(feature = "legacy-rsa-decryption"));
    assert_eq!(
        riptering::supports(encrypt).unwrap(),
        !cfg!(feature = "fips")
    );
    assert_eq!(riptering::supports(decrypt).unwrap(), decryption_enabled);
    let registry = riptering::capabilities().unwrap();
    assert_eq!(
        registry.iter().any(|entry| entry.operation == decrypt),
        decryption_enabled
    );
    if cfg!(feature = "fips") {
        let wrong_key =
            SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, b"synthetic key").unwrap();
        assert_refused(
            riptering::keytransport::kt_encrypt(algorithm, &wrong_key, b"key", None),
            encrypt,
        );
        assert_refused(
            riptering::keytransport::kt_decrypt(algorithm, &wrong_key, b"", None),
            decrypt,
        );
        return;
    }
    let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let key = SoftwareKey::from_pkcs8_der(
        KeyAlgorithm::Rsa,
        private.to_pkcs8_der().unwrap().as_bytes(),
    )
    .unwrap();
    let encrypted =
        riptering::keytransport::kt_encrypt(algorithm, &key, b"synthetic key", None).unwrap();
    let decrypted = riptering::keytransport::kt_decrypt(algorithm, &key, &encrypted, None);
    if decryption_enabled {
        assert_eq!(decrypted.unwrap(), b"synthetic key");
    } else {
        assert_refused(decrypted, decrypt);
    }
}

/// Encode a P-256 signature's fixed-width r||s as minimal DER.
fn p256_der(raw: &[u8]) -> Vec<u8> {
    p256::ecdsa::Signature::from_slice(raw)
        .unwrap()
        .to_der()
        .as_bytes()
        .to_vec()
}

#[test]
fn ecdsa_verify_accepts_the_same_encodings() {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

    riptering::initialize_backend().expect("provider initialization");
    let private = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let key = SoftwareKey::from_pkcs8_der(
        KeyAlgorithm::Ec(EcCurve::P256),
        private.to_pkcs8_der().unwrap().as_bytes(),
    )
    .unwrap();
    let public = SoftwareKey::from_spki_der(
        KeyAlgorithm::Ec(EcCurve::P256),
        private.public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .unwrap();
    let algorithm = SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256);
    let raw = SoftwareSigner::new(algorithm, key)
        .unwrap()
        .sign(b"parity")
        .unwrap();
    assert_eq!(raw.len(), 64);
    let verifier = SoftwareVerifier::new(algorithm, public).unwrap();

    let mut padded = vec![0];
    padded.extend_from_slice(&raw[..32]);
    padded.push(0);
    padded.extend_from_slice(&raw[32..]);

    for (name, encoding) in [
        ("raw", raw.clone()),
        ("DER", p256_der(&raw)),
        ("padded", padded),
    ] {
        assert!(verifier.verify(b"parity", &encoding).unwrap(), "{name}");
        assert!(!verifier.verify(b"tampered", &encoding).unwrap(), "{name}");
    }
    assert!(verifier.verify(b"parity", &[0; 64]).is_err());
    assert!(verifier.verify(b"parity", &raw[..63]).is_err());
}

#[test]
fn ecdsa_verifies_cross_curve_digest_pairs() {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::pkcs8::EncodePublicKey;

    riptering::initialize_backend().expect("provider initialization");
    // XML-DSig pairs a P-384 key with whatever digest the URI names.
    let signing = p384::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let public = SoftwareKey::from_spki_der(
        KeyAlgorithm::Ec(EcCurve::P384),
        signing
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let digest = riptering::digest::digest(HashAlgorithm::Sha256, b"cross").unwrap();
    let signature: p384::ecdsa::Signature = signing.sign_prehash(&digest).unwrap();
    let verifier = SoftwareVerifier::new(
        SignatureAlgorithm::Ecdsa(EcCurve::P384, HashAlgorithm::Sha256),
        public,
    )
    .unwrap();
    assert!(verifier.verify(b"cross", &signature.to_bytes()).unwrap());
    assert!(!verifier.verify(b"tampered", &signature.to_bytes()).unwrap());
}

#[test]
fn rsa_keys_below_2048_bits_are_refused_when_used() {
    use riptering::{KeyTransportAlgorithm, OaepConfig};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    riptering::initialize_backend().expect("provider initialization");
    let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
    let spki = private.to_public_key().to_public_key_der().unwrap();
    let pkcs8 = private.to_pkcs8_der().unwrap();
    let public = SoftwareKey::from_spki_der(KeyAlgorithm::Rsa, spki.as_bytes());
    let private = SoftwareKey::from_pkcs8_der(KeyAlgorithm::Rsa, pkcs8.as_bytes());
    if cfg!(feature = "fips") {
        // FIPS builds refuse short RSA keys already at import.
        assert!(public.is_err() && private.is_err());
        return;
    }
    let public = public.unwrap();
    let algorithm = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256);
    // The one intended difference: RustCrypto with `legacy` uses short RSA
    // keys for historical interoperability; AWS-LC never does.
    let usable = cfg!(all(feature = "rustcrypto", feature = "legacy"));
    match private {
        Ok(private) => assert_eq!(SoftwareSigner::new(algorithm, private).is_ok(), usable),
        // AWS-LC's RSA key-pair parser itself refuses short private keys.
        Err(_) => assert!(!usable && cfg!(feature = "aws-lc")),
    }
    let verified = SoftwareVerifier::new(algorithm, public.clone())
        .and_then(|verifier| verifier.verify(b"message", &[0; 128]));
    assert_eq!(verified.is_ok(), usable, "{verified:?}");
    if !usable {
        assert!(verified
            .unwrap_err()
            .to_string()
            .contains("1024-bit RSA key"));
    }
    let oaep = KeyTransportAlgorithm::RsaOaep(OaepConfig::default());
    let transported = riptering::keytransport::kt_encrypt(oaep, &public, &[0x42; 16], None);
    assert_eq!(transported.is_ok(), usable, "{transported:?}");
}

#[test]
fn rsa_odd_modulus_bit_lengths_follow_fips_import_policy() {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    riptering::initialize_backend().expect("provider initialization");
    let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2049).unwrap();
    let public_import = SoftwareKey::from_spki_der(
        KeyAlgorithm::Rsa,
        private
            .to_public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    );
    let private_import = SoftwareKey::from_pkcs8_der(
        KeyAlgorithm::Rsa,
        private.to_pkcs8_der().unwrap().as_bytes(),
    );
    if cfg!(feature = "fips") {
        assert_refused(public_import, Operation::KeyImport(KeyAlgorithm::Rsa));
        assert_refused(private_import, Operation::KeyImport(KeyAlgorithm::Rsa));
    } else {
        assert!(public_import.is_ok());
        assert!(private_import.is_ok());
    }
}

#[test]
fn aes_cbc_rejects_iv_only_input() {
    riptering::initialize_backend().expect("provider initialization");
    for size in [AesKeySize::Aes128, AesKeySize::Aes256] {
        let key = vec![3; size.key_len()];
        assert!(riptering::hazmat::aes_cbc::decrypt(size, &key, &[9; 16]).is_err());
        let sealed = riptering::hazmat::aes_cbc::encrypt(size, &key, b"").unwrap();
        assert_eq!(sealed.len(), 32);
        assert!(riptering::hazmat::aes_cbc::decrypt(size, &key, &sealed)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn aes_key_wrap_matches_rfc3394_and_rejects_short_input() {
    riptering::initialize_backend().expect("provider initialization");
    // RFC 3394 §4.1 and §4.6.
    let kek128 = decode("000102030405060708090A0B0C0D0E0F");
    let kek256 = decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let data = decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    for (size, kek, input, expected) in [
        (
            AesKeySize::Aes128,
            &kek128,
            &data[..16],
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        ),
        (
            AesKeySize::Aes256,
            &kek256,
            &data[..],
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        ),
    ] {
        let algorithm = KeyWrapAlgorithm::AesKw(size);
        let wrapped = riptering::keywrap::wrap(algorithm, kek, input).unwrap();
        assert_eq!(wrapped, decode(expected));
        assert_eq!(
            riptering::keywrap::unwrap(algorithm, kek, &wrapped).unwrap(),
            input
        );
        let mut tampered = wrapped.clone();
        tampered[0] ^= 1;
        assert!(riptering::keywrap::unwrap(algorithm, kek, &tampered).is_err());

        assert!(riptering::keywrap::wrap(algorithm, kek, &[]).is_err());
        assert!(riptering::keywrap::wrap(algorithm, kek, &[1; 8]).is_err());
        assert!(riptering::keywrap::wrap(algorithm, kek, &[1; 20]).is_err());
        assert!(riptering::keywrap::unwrap(algorithm, kek, &wrapped[..16]).is_err());
    }
}

#[test]
fn kdfs_match_rfc_vectors() {
    riptering::initialize_backend().expect("provider initialization");
    // RFC 5869 A.2 (long inputs) and A.3 (no salt, no info).
    let a2 = riptering::kdf::hkdf_derive(
        &(0u8..=0x4f).collect::<Vec<_>>(),
        82,
        &HkdfParams {
            hash: HashAlgorithm::Sha256,
            salt: Some((0x60u8..=0xaf).collect()),
            info: Some((0xb0u8..=0xff).collect()),
            key_length_bits: 0,
        },
    )
    .unwrap();
    assert_eq!(
        a2,
        decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );
    let a3 = riptering::kdf::hkdf_derive(&[0x0b; 22], 42, &HkdfParams::default());
    if cfg!(feature = "fips") {
        // AWS-LC's full HKDF service does not approve empty context info.
        assert_refused(a3, Operation::Hkdf(HashAlgorithm::Sha256));
    } else {
        assert_eq!(
            a3.unwrap(),
            decode(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8"
            )
        );
    }
    assert!(riptering::kdf::hkdf_derive(&[1], 255 * 32 + 1, &HkdfParams::default()).is_err());

    // Cross-checked against Python's hashlib.pbkdf2_hmac. The 8-byte salt and
    // password are below the SP 800-132 minimums FIPS builds enforce.
    for (hash, len, expected) in [
        (HashAlgorithm::Sha256, 64, "2ecc2dfd549e0925a0e4a0b860368e7492b6e65339188d3e1e9e43799b90ff64cf800fb11ff3602b51ed7c8c766643c32be8af72829b3146642d9ddbdf8d7d6d"),
        (HashAlgorithm::Sha512, 40, "fee75217fa12304834340c9e672f9aaa9cc4bb229a9fd37edcdcd6ae57b42ad8ca5ea636c777c33c"),
    ] {
        let output = riptering::kdf::pbkdf2_derive(
            b"Password",
            &Pbkdf2Params {
                hash,
                salt: b"NaCl1234".to_vec(),
                iteration_count: 1000,
                key_length: len,
            },
        );
        if cfg!(feature = "fips") {
            assert!(
                matches!(
                    output,
                    Err(riptering::Error::Crypto(ref message))
                        if message.contains("SP 800-132")
                ),
                "{hash:?}: {output:?}"
            );
        } else {
            assert_eq!(output.unwrap(), decode(expected), "{hash:?}");
        }
    }

    // The same shapes with SP 800-132 compliant parameters (128-bit salt and
    // password, 1000 iterations), which every provider including FIPS must
    // derive identically. Cross-checked against Python's hashlib.pbkdf2_hmac.
    for (hash, len, expected) in [
        (HashAlgorithm::Sha256, 64, "1e30cde84a0370317564c82ece78efb738195387129590d2fd3d7b48714a40c874de73f494b275b7147b58171cc17101b3cba6a0bd0a3766c839dd7e98f71aed"),
        (HashAlgorithm::Sha512, 40, "20ae6a68e7f944784e186fa29c12c6ae0926c736f4cdb5f025becc9c70a0e12cf39145acd1ad6113"),
    ] {
        let output = riptering::kdf::pbkdf2_derive(
            b"PasswordPassword",
            &Pbkdf2Params {
                hash,
                salt: b"NaCl1234NaCl1234".to_vec(),
                iteration_count: 1000,
                key_length: len,
            },
        )
        .unwrap();
        assert_eq!(output, decode(expected), "{hash:?}");
    }

    let recommended = Pbkdf2Params::recommended(HashAlgorithm::Sha512, b"salt".to_vec(), 32);
    assert_eq!(recommended.hash, HashAlgorithm::Sha512);
    assert_eq!(recommended.iteration_count, 210_000);
}

#[test]
fn hkdf_empty_parameters_follow_provider_approval_policy() {
    riptering::initialize_backend().expect("provider initialization");
    for (salt, info) in [
        (None, None),
        (None, Some(Vec::new())),
        (Some(Vec::new()), Some(b"context".to_vec())),
        (Some(vec![0; 32]), None),
        (Some(vec![0; 32]), Some(Vec::new())),
    ] {
        let output = riptering::kdf::hkdf_derive(
            b"synthetic-secret",
            42,
            &HkdfParams {
                salt,
                info,
                ..HkdfParams::default()
            },
        );
        if cfg!(feature = "fips") {
            assert_refused(output, Operation::Hkdf(HashAlgorithm::Sha256));
        } else {
            assert_eq!(output.unwrap().len(), 42);
        }
    }

    // Absent salt becomes hash-length zeros, so both approved forms produce
    // the same result with nonempty context under every provider.
    let params = HkdfParams {
        info: Some(b"context".to_vec()),
        ..HkdfParams::default()
    };
    let without_salt = riptering::kdf::hkdf_derive(b"synthetic-secret", 42, &params).unwrap();
    let zero_salt = riptering::kdf::hkdf_derive(
        b"synthetic-secret",
        42,
        &HkdfParams {
            salt: Some(vec![0; 32]),
            ..params
        },
    )
    .unwrap();
    assert_eq!(without_salt, zero_salt);
}

#[test]
fn portable_kdfs_preserve_partial_final_blocks() {
    use riptering::kdf::ConcatKdfParams;

    riptering::initialize_backend().expect("provider initialization");
    // Independently calculated with Python hashlib/hmac. These 65-byte
    // outputs exercise multiple rounds and a partial final block in the
    // AWS-LC portable compositions, and the same inputs under RustCrypto.
    let pbkdf2 = riptering::kdf::pbkdf2_derive(
        b"PasswordPassword",
        &Pbkdf2Params {
            hash: HashAlgorithm::Sha224,
            salt: b"NaCl1234NaCl1234".to_vec(),
            iteration_count: 7,
            key_length: 65,
        },
    );
    let hkdf = riptering::kdf::hkdf_derive(
        &[0x0b; 22],
        65,
        &HkdfParams {
            hash: HashAlgorithm::Sha224,
            salt: Some((0u8..16).collect()),
            info: Some(b"synthetic-info".to_vec()),
            key_length_bits: 0,
        },
    );
    let concat = riptering::kdf::concat_kdf(
        b"synthetic-secret",
        65,
        &ConcatKdfParams {
            hash: HashAlgorithm::Sha3_256,
            algorithm_id: Some(b"algorithm".to_vec()),
            party_u_info: Some(b"Alice".to_vec()),
            party_v_info: Some(b"Bob".to_vec()),
        },
    );
    if cfg!(feature = "fips") {
        assert_refused(pbkdf2, Operation::Pbkdf2(HashAlgorithm::Sha224));
        assert_refused(hkdf, Operation::Hkdf(HashAlgorithm::Sha224));
        assert_refused(concat, Operation::ConcatKdf(HashAlgorithm::Sha3_256));
    } else {
        assert_eq!(pbkdf2.unwrap(), decode("ebf0ffa9b27ffa4798db3e73f93ffcddf2ec09679a3842e853d566e1538f107776b660d2fae7360823d23e1f57bf10d7ec39703de7059a5f6fcf9bc88de734f77e"));
        assert_eq!(hkdf.unwrap(), decode("3ca6bb916d24e5cd28540092a45e4607edaa9e1eb6140c001102f4071ee5455992ea2e1bda814c5eb1efb18f5bd421806d9be61aeeb11d450fae42661782bd89c2"));
        assert_eq!(concat.unwrap(), decode("beee14c349ba559e081ded223cea30fa5b98b448782643d4e6b051caf14a62e662fbd9bde23692815601de93c269b12904f78f7250452073a21a576fed83200aac"));
    }
}

#[test]
fn aes_gcm_framing_authentication_and_empty_messages_match() {
    use riptering::CipherAlgorithm;

    riptering::initialize_backend().expect("provider initialization");
    for size in [AesKeySize::Aes128, AesKeySize::Aes192, AesKeySize::Aes256] {
        let algorithm = CipherAlgorithm::AesGcm(size);
        let key = vec![0x17; size.key_len()];
        for length in [0, 1, 16, 4096] {
            let message = vec![0x42; length];
            let ciphertext = riptering::cipher::encrypt(algorithm, &key, &message);
            if cfg!(feature = "fips") && size == AesKeySize::Aes192 {
                assert_refused(ciphertext, Operation::Encrypt(algorithm));
                assert_refused(
                    riptering::cipher::decrypt(algorithm, &key, &[0; 28]),
                    Operation::Decrypt(algorithm),
                );
                continue;
            }
            let mut ciphertext = ciphertext.unwrap();
            assert_eq!(ciphertext.len(), 12 + length + 16);
            assert_eq!(
                riptering::cipher::decrypt(algorithm, &key, &ciphertext).unwrap(),
                message
            );
            *ciphertext.last_mut().unwrap() ^= 1;
            assert!(riptering::cipher::decrypt(algorithm, &key, &ciphertext).is_err());
            assert!(riptering::cipher::decrypt(algorithm, &key, &ciphertext[..27]).is_err());
        }
    }
}

#[cfg(feature = "legacy")]
#[test]
fn pbkdf2_capabilities_reject_unimplemented_legacy_hashes() {
    riptering::initialize_backend().expect("provider initialization");
    for hash in [HashAlgorithm::Md5, HashAlgorithm::Ripemd160] {
        let operation = Operation::Pbkdf2(hash);
        assert!(!riptering::supports(operation).unwrap());
        assert_refused(
            riptering::kdf::pbkdf2_derive(
                b"synthetic-password",
                &Pbkdf2Params {
                    hash,
                    salt: b"synthetic-salt-16".to_vec(),
                    iteration_count: 1000,
                    key_length: 32,
                },
            ),
            operation,
        );
    }
}
