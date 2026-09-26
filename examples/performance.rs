//! Local synthetic microbenchmarks; no real keys, services, or HSMs.
//!
//! Run with `cargo run --release --example performance` and repeat for each
//! valid provider. `RIPTERING_BENCH_ONLY=buffers` or `signatures` narrows the
//! workload. Timings are medians of five warmed samples. Allocation counters
//! cover Rust's global allocator only, excluding AWS-LC's native allocations.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use rand::SeedableRng;
use riptering::{
    AesKeySize, CipherAlgorithm, EcCurve, HashAlgorithm, KeyAlgorithm, KeyWrapAlgorithm,
    SignatureAlgorithm, Signer, SoftwareKey, SoftwareSigner, SoftwareVerifier, Verifier,
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

struct CountingAllocator;
static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);

fn record(size: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }
}

// The wrapper forwards each pointer and its exact original layout to System.
// Counters do not allocate, inspect memory, or change allocation lifetimes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure(name: &str, bytes: usize, iterations: usize, mut operation: impl FnMut()) {
    for _ in 0..8 {
        operation();
    }
    let mut samples = [0u128; 5];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        *sample = start.elapsed().as_nanos() / iterations as u128;
    }
    samples.sort_unstable();
    ALLOCATIONS.store(0, Ordering::Relaxed);
    REQUESTED_BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for _ in 0..8 {
        operation();
    }
    COUNTING.store(false, Ordering::Relaxed);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) as f64 / 8.0;
    let requested_bytes = REQUESTED_BYTES.load(Ordering::Relaxed) as f64 / 8.0;
    println!(
        "{name},{bytes},{iterations},{},{allocations:.3},{requested_bytes:.3}",
        samples[2]
    );
}

fn signature_workload(
    label: &str,
    algorithm: SignatureAlgorithm,
    key_algorithm: KeyAlgorithm,
    private_der: &[u8],
    public_der: &[u8],
    sign_iterations: usize,
) {
    let private = SoftwareKey::from_pkcs8_der(key_algorithm, private_der).unwrap();
    let public = SoftwareKey::from_spki_der(key_algorithm, public_der).unwrap();
    let signer = SoftwareSigner::new(algorithm, private.clone()).unwrap();
    let verifier = SoftwareVerifier::new(algorithm, public.clone()).unwrap();
    let message = [0x42; 256];
    let signature = signer.sign(&message).unwrap();
    assert!(verifier.verify(&message, &signature).unwrap());
    let mut altered = message;
    altered[0] ^= 1;
    assert!(!verifier.verify(&altered, &signature).unwrap());
    measure(&format!("{label}_sign_reuse"), 256, sign_iterations, || {
        black_box(signer.sign(black_box(&message)).unwrap());
    });
    measure(
        &format!("{label}_sign_recreate"),
        256,
        sign_iterations,
        || {
            let signer = SoftwareSigner::new(algorithm, private.clone()).unwrap();
            black_box(signer.sign(black_box(&message)).unwrap());
        },
    );
    measure(&format!("{label}_verify_reuse"), 256, 1_000, || {
        assert!(black_box(
            verifier
                .verify(black_box(&message), black_box(&signature))
                .unwrap()
        ));
    });
    measure(&format!("{label}_verify_recreate"), 256, 1_000, || {
        let verifier = SoftwareVerifier::new(algorithm, public.clone()).unwrap();
        assert!(black_box(verifier.verify(&message, &signature).unwrap()));
    });
    measure(
        &format!("{label}_import_pkcs8"),
        private_der.len(),
        50,
        || {
            black_box(SoftwareKey::from_pkcs8_der(key_algorithm, black_box(private_der)).unwrap());
        },
    );
    measure(
        &format!("{label}_import_spki"),
        public_der.len(),
        500,
        || {
            black_box(SoftwareKey::from_spki_der(key_algorithm, black_box(public_der)).unwrap());
        },
    );
}

fn signatures() {
    // Predictable fixture seeds deliberately generate public synthetic keys.
    // Fixture generation and serialization are outside every timed region.
    let mut fixture_rng = rand::rngs::StdRng::from_seed([0x61; 32]);
    let rsa = rsa::RsaPrivateKey::new(&mut fixture_rng, 2048).unwrap();
    let rsa_private = rsa.to_pkcs8_der().unwrap();
    let rsa_public = rsa.to_public_key().to_public_key_der().unwrap();
    signature_workload(
        "rsa2048_pkcs1_sha256",
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
        KeyAlgorithm::Rsa,
        rsa_private.as_bytes(),
        rsa_public.as_bytes(),
        100,
    );
    signature_workload(
        "rsa2048_pss_sha256",
        SignatureAlgorithm::RsaPss(HashAlgorithm::Sha256),
        KeyAlgorithm::Rsa,
        rsa_private.as_bytes(),
        rsa_public.as_bytes(),
        100,
    );
    let p256 = p256::SecretKey::from_slice(&[0x33; 32]).unwrap();
    signature_workload(
        "p256_sha256",
        SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256),
        KeyAlgorithm::Ec(EcCurve::P256),
        p256.to_pkcs8_der().unwrap().as_bytes(),
        p256.public_key().to_public_key_der().unwrap().as_bytes(),
        1_000,
    );
    if !cfg!(feature = "fips") {
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]);
        signature_workload(
            "ed25519",
            SignatureAlgorithm::Ed25519,
            KeyAlgorithm::Ed25519,
            ed25519.to_pkcs8_der().unwrap().as_bytes(),
            ed25519
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
            1_000,
        );
    }
    let key = SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, &[0x17; 32]).unwrap();
    let algorithm = SignatureAlgorithm::Hmac(HashAlgorithm::Sha256);
    let signer = SoftwareSigner::new(algorithm, key.clone()).unwrap();
    let verifier = SoftwareVerifier::new(algorithm, key.clone()).unwrap();
    let message = [0x42; 256];
    let signature = signer.sign(&message).unwrap();
    measure("hmac_sha256_sign_reuse", 256, 10_000, || {
        black_box(signer.sign(black_box(&message)).unwrap());
    });
    measure("hmac_sha256_verify_reuse", 256, 10_000, || {
        assert!(black_box(verifier.verify(&message, &signature).unwrap()));
    });
    measure("hmac_import_raw", 32, 10_000, || {
        black_box(SoftwareKey::from_symmetric_bytes(KeyAlgorithm::Hmac, &[0x17; 32]).unwrap());
    });
}

fn buffers() {
    let key = [0x17; 32];
    let cipher = CipherAlgorithm::AesGcm(AesKeySize::Aes256);
    let wrapper = KeyWrapAlgorithm::AesKw(AesKeySize::Aes256);
    for (bytes, iterations) in [(32, 3_000), (4_096, 1_000), (65_536, 100)] {
        let plaintext = vec![0x42; bytes];
        let ciphertext = riptering::cipher::encrypt(cipher, &key, &plaintext).unwrap();
        assert_eq!(
            riptering::cipher::decrypt(cipher, &key, &ciphertext).unwrap(),
            plaintext
        );
        let wrapped = riptering::keywrap::wrap(wrapper, &key, &plaintext).unwrap();
        assert_eq!(
            riptering::keywrap::unwrap(wrapper, &key, &wrapped).unwrap(),
            plaintext
        );
        measure("aes256_gcm_encrypt", bytes, iterations, || {
            black_box(riptering::cipher::encrypt(cipher, &key, black_box(&plaintext)).unwrap());
        });
        measure("aes256_gcm_decrypt", bytes, iterations, || {
            black_box(riptering::cipher::decrypt(cipher, &key, black_box(&ciphertext)).unwrap());
        });
        measure("aes256_kw_wrap", bytes, iterations, || {
            black_box(riptering::keywrap::wrap(wrapper, &key, black_box(&plaintext)).unwrap());
        });
        measure("aes256_kw_unwrap", bytes, iterations, || {
            black_box(riptering::keywrap::unwrap(wrapper, &key, black_box(&wrapped)).unwrap());
        });
    }
}

fn main() {
    riptering::initialize_backend().unwrap();
    println!("workload,payload_bytes,iterations,median_ns_per_op,rust_alloc_calls_per_op,rust_requested_bytes_per_op");
    let only = std::env::var("RIPTERING_BENCH_ONLY").unwrap_or_default();
    if only != "buffers" {
        signatures();
    }
    if only != "signatures" {
        buffers();
    }
}
