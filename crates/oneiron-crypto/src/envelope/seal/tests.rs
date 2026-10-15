//! The HKDF key schedule's stack wipe (RustCrypto/meta#38): the bare schedule leaves
//! its secrets below its caller, and `aead_key` leaves none. Run in a release build, this
//! is also the check that `aead_key_inner` stays out of line.

use hkdf::Hkdf;
use sha2::Sha256;
use sha2::block_api::compress256;
use zeroize::Zeroizing;

use super::{AEAD_KEY_STACK_WIPE, KEY_LABEL, aead_key, aead_key_inner};
use crate::stack_probe;

/// The SHA-256 initial hash value (FIPS 180-4, 5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The SHA-256 state, as it sits in memory, after absorbing `key` XOR `pad` (one
/// block): what an HMAC keyed by `key` holds, and enough to compute it.
fn hmac_midstate(key: &[u8; 32], pad: u8) -> Vec<u8> {
    let mut block = [pad; 64];
    for (b, k) in block.iter_mut().zip(key) {
        *b ^= k;
    }
    let mut state = SHA256_IV;
    compress256(&mut state, &[block]);
    state.into_iter().flat_map(u32::to_ne_bytes).collect()
}

#[test]
fn the_hkdf_key_schedule_leaves_no_secret_below_its_caller() {
    let secret: [u8; 32] = core::array::from_fn(|i| (i * 29 + 11) as u8);
    let salt = [0x42; 32];
    let header: &[u8] = b"canonical header bytes";
    let span = AEAD_KEY_STACK_WIPE + 64 * 1024;

    let bare = stack_probe::run(span, &mut || {
        let mut key = Zeroizing::new([0u8; 32]);
        aead_key_inner(&secret, &salt, header, &mut key).expect("hkdf");
    });
    let wiped = stack_probe::run(span, &mut || {
        let mut key = Zeroizing::new([0u8; 32]);
        aead_key(&secret, &salt, header, &mut key).expect("hkdf");
    });

    let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &secret);
    let prk: [u8; 32] = prk.as_slice().try_into().expect("32-byte prk");
    let mut key = [0u8; 32];
    hkdf.expand_multi_info(&[KEY_LABEL, header], &mut key)
        .expect("hkdf");
    let secrets = [
        ("wrap secret", secret.to_vec()),
        ("prk", prk.to_vec()),
        ("prk ^ ipad", prk.map(|b| b ^ 0x36).to_vec()),
        ("prk ^ opad", prk.map(|b| b ^ 0x5c).to_vec()),
        ("hmac(prk) inner state", hmac_midstate(&prk, 0x36)),
        ("hmac(prk) outer state", hmac_midstate(&prk, 0x5c)),
        ("payload key", key.to_vec()),
    ];

    eprintln!(
        "hkdf: the key schedule reached {} bytes below its caller; the wipe covers {}",
        bare.depth(),
        AEAD_KEY_STACK_WIPE
    );
    for (name, bytes) in &secrets {
        eprintln!(
            "hkdf: {name}: bare {:?}, wiped {:?}",
            bare.depth_of(bytes),
            wiped.depth_of(bytes)
        );
    }
    assert!(bare.depth() <= AEAD_KEY_STACK_WIPE);
    assert!(
        secrets
            .iter()
            .any(|(_, bytes)| bare.depth_of(bytes).is_some()),
        "the probe must see what the bare key schedule leaves"
    );
    for (name, bytes) in &secrets {
        assert_eq!(wiped.depth_of(bytes), None, "{name} left on the stack");
    }
}
