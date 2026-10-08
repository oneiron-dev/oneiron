//! Record signing's stack wipe (RustCrypto/meta#38): the bare SLH-DSA signer leaves its
//! secrets below its caller, and `sign_message` leaves none. Run in a release build, this
//! is also the check that `sign_message_inner` stays out of line: inlined, its frame (and
//! the randomizer in it) would be `sign_message`'s own, above the wipe.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use sha2::block_api::compress512;
use slh_dsa::Sha2_256s;

use super::{ED25519_STACK_WIPE, SLHDSA_STACK_WIPE, SigningKey};
use crate::stack_probe;

/// The SHA-512 initial hash value (FIPS 180-4, 5.3.5).
const SHA512_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// The SHA-512 state, as it sits in memory, after absorbing `key` XOR `pad` (one
/// block): what an HMAC keyed by `key` holds, and enough to compute it.
fn hmac_midstate(key: &[u8; 32], pad: u8) -> Vec<u8> {
    let mut block = [pad; 128];
    for (b, k) in block.iter_mut().zip(key) {
        *b ^= k;
    }
    let mut state = SHA512_IV;
    compress512(&mut state, &[block]);
    state.into_iter().flat_map(u64::to_ne_bytes).collect()
}

fn ladder(start: usize) -> [u8; 32] {
    core::array::from_fn(|i| (start + i * 37) as u8)
}

/// Fills every request with the same ladder, so the SLH-DSA randomizer is known.
struct LadderRng;
impl TryRng for LadderRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes([17, 70, 123, 176]))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes([17, 70, 123, 176, 229, 26, 79, 132]))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for (i, byte) in dst.iter_mut().enumerate() {
            *byte = (17 + i * 53) as u8;
        }
        Ok(())
    }
}
impl TryCryptoRng for LadderRng {}

#[test]
fn record_signing_leaves_no_signing_secret_below_its_caller() {
    let (sk_seed, sk_prf, pk_seed) = (ladder(3), ladder(101), ladder(199));
    let slh = SigningKey::SlhDsaSha2_256s(Box::new(
        slh_dsa::SigningKey::<Sha2_256s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed),
    ));
    let mut randomizer = [0u8; 32];
    LadderRng.try_fill_bytes(&mut randomizer).expect("ladder");
    let span = SLHDSA_STACK_WIPE + 64 * 1024;

    let bare = stack_probe::run(span, &mut || {
        slh.sign_message_inner(b"record transcript", &mut LadderRng)
            .expect("sign");
    });
    let wiped = stack_probe::run(span, &mut || {
        slh.sign_message(b"record transcript", &mut LadderRng)
            .expect("sign");
    });
    let secrets = [
        ("sk.seed", sk_seed.to_vec()),
        ("sk.prf", sk_prf.to_vec()),
        ("sk.prf ^ ipad", sk_prf.map(|b| b ^ 0x36).to_vec()),
        ("sk.prf ^ opad", sk_prf.map(|b| b ^ 0x5c).to_vec()),
        ("hmac(sk.prf) inner state", hmac_midstate(&sk_prf, 0x36)),
        ("hmac(sk.prf) outer state", hmac_midstate(&sk_prf, 0x5c)),
        ("randomizer", randomizer.to_vec()),
    ];
    eprintln!(
        "slh-dsa: signing reached {} bytes below its caller; the wipe covers {}",
        bare.depth(),
        SLHDSA_STACK_WIPE
    );
    for (name, bytes) in &secrets {
        eprintln!(
            "slh-dsa: {name}: bare {:?}, wiped {:?}",
            bare.depth_of(bytes),
            wiped.depth_of(bytes)
        );
    }

    // ed25519-dalek wipes its expanded key itself, so only the reach is checked: the
    // wipe must cover what the signer touched.
    let ed = SigningKey::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(&ladder(57))));
    let ed_bare = stack_probe::run(ED25519_STACK_WIPE + 64 * 1024, &mut || {
        ed.sign_message_inner(b"record transcript", &mut LadderRng)
            .expect("sign");
    });
    eprintln!(
        "ed25519: signing reached {} bytes below its caller; the wipe covers {}",
        ed_bare.depth(),
        ED25519_STACK_WIPE
    );

    assert!(bare.depth() <= SLHDSA_STACK_WIPE);
    assert!(ed_bare.depth() <= ED25519_STACK_WIPE);
    assert!(
        secrets
            .iter()
            .any(|(_, bytes)| bare.depth_of(bytes).is_some()),
        "the probe must see what the bare signer leaves"
    );
    for (name, bytes) in &secrets {
        assert_eq!(wiped.depth_of(bytes), None, "{name} left on the stack");
    }
}
