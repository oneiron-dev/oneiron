//! The seed expansion's stack wipe (RustCrypto/meta#38): building a key from its seed
//! reaches below its caller with the expanded seeds and the constructors' by-value copies
//! of them, and `from_seed` wipes that reach. The key `from_seed` returns is moved out by
//! value, so copies of its own halves sit above the wipe, in the frames that hold the key.
//! The check is the wipe's own: it ran below `from_seed` as deep as its constant, which
//! covers the build's reach, and no secret is left below the frames that hold the key.
//! Run in a release build, this is also the check that `from_seed_inner` stays out of
//! line.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{HybridSecretKey, SEED_KEY_STACK_WIPE, expand_seed, from_seed_inner};
use crate::stack_probe;

#[test]
fn building_a_key_from_its_seed_stays_within_the_wipe() {
    let seed: [u8; 32] = core::array::from_fn(|i| (i * 29 + 11) as u8);
    let label: &[u8] = b"stack probe";
    let span = SEED_KEY_STACK_WIPE + 64 * 1024;

    let bare = stack_probe::run(span, &mut || {
        drop(from_seed_inner(&seed, label).expect("seed"));
    });
    let wiped = stack_probe::run(span, &mut || {
        drop(HybridSecretKey::from_seed(&seed, label).expect("seed"));
    });

    let (prk, _) = Hkdf::<Sha256>::extract(None, &seed);
    let mut mlkem_seed = Zeroizing::new([0u8; 64]);
    let mut x25519 = Zeroizing::new([0u8; 32]);
    expand_seed(&seed, label, &mut mlkem_seed, &mut x25519).expect("hkdf");
    let secrets = [
        ("seed", seed.to_vec()),
        ("prk", prk.to_vec()),
        ("ml-kem d", mlkem_seed[..32].to_vec()),
        ("ml-kem z", mlkem_seed[32..].to_vec()),
        ("x25519 secret", x25519.to_vec()),
    ];
    eprintln!(
        "seed key: the build reached {} bytes below its caller; the wipe covers {}",
        bare.depth(),
        SEED_KEY_STACK_WIPE
    );
    for (name, bytes) in &secrets {
        eprintln!(
            "seed key: {name}: bare {:?}, wiped {:?}",
            bare.depth_of(bytes),
            wiped.depth_of(bytes)
        );
    }

    assert!(bare.depth() < span, "the probe must see the whole build");
    assert!(bare.depth() <= SEED_KEY_STACK_WIPE);
    assert!(
        secrets
            .iter()
            .any(|(_, bytes)| bare.depth_of(bytes).is_some()),
        "the probe must see what the bare build leaves"
    );
    // Without the wipe, or with the expansion's alone, nothing reaches this deep but
    // the build, which stays above the constant (Sol code-R4 S4-F2).
    assert!(
        wiped.depth() >= SEED_KEY_STACK_WIPE,
        "the wipe must run below from_seed"
    );
    let above = wiped.depth() - SEED_KEY_STACK_WIPE;
    for (name, bytes) in &secrets {
        assert!(
            wiped.depth_of(bytes).is_none_or(|depth| depth <= above),
            "{name} left below the frames that hold the key"
        );
    }
}
