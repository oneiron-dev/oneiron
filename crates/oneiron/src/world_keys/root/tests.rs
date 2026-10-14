//! The owner anchor's stack (RustCrypto/meta#38; Wonder code-R4 W4-F1, Sol code-R5 S5-F1,
//! Wonder W5-F1), painted on this crate's own ed25519-dalek in dev and release builds.
//! Building the anchor key from the root seed leaves the anchor's secret below its caller
//! in a release build, so `anchor` wipes the build's reach: the wipe runs as deep as its
//! constant, which covers the reach, and no secret is left below the frames that hold the
//! returned key. Signing with the anchor leaves none of the seed, the anchor's secret or
//! its SHA-512 expansion below its caller, so it wipes nothing. A control copy shows the
//! painter sees a secret left on the stack.

use oneiron_crypto::stack_probe;
use sha2::{Digest, Sha512};

use super::{ANCHOR_CONTEXT, ANCHOR_STACK_WIPE, RecoveryRootSeed, anchor_key};

const SPAN: usize = ANCHOR_STACK_WIPE + 64 * 1024;

#[test]
fn the_anchor_build_stays_within_its_wipe_and_signing_leaves_no_secret() {
    let seed = RecoveryRootSeed::generate().expect("os entropy");
    let secret = blake3::derive_key(ANCHOR_CONTEXT, &seed.bytes[..]);
    let expanded = Sha512::digest(secret);
    let secrets = [
        ("root seed", seed.bytes.to_vec()),
        ("anchor secret", secret.to_vec()),
        ("expanded scalar half", expanded[..32].to_vec()),
        ("expanded hash prefix", expanded[32..].to_vec()),
    ];
    let control = stack_probe::run(SPAN, &mut || {
        let mut copy = [0u8; 32];
        copy.copy_from_slice(&secret);
        std::hint::black_box(&copy);
    });
    assert!(
        control.depth_of(&secret).is_some(),
        "the probe must see a secret left on the stack"
    );

    let bare = stack_probe::run(SPAN, &mut || drop(anchor_key(&seed.bytes)));
    let wiped = stack_probe::run(SPAN, &mut || drop(seed.anchor()));
    let anchor = seed.anchor();
    let message: &[u8] = b"stack probe transcript";
    let signing = stack_probe::run(SPAN, &mut || {
        drop(ed25519_dalek::Signer::sign(&anchor, message));
    });
    for (name, run) in [("bare build", &bare), ("signature", &signing)] {
        eprintln!(
            "anchor {name}: reached {} bytes below its caller; the wipe covers {ANCHOR_STACK_WIPE}",
            run.depth()
        );
    }
    for (secret, bytes) in &secrets {
        eprintln!(
            "anchor {secret}: bare build {:?}, wiped build {:?}, signature {:?}",
            bare.depth_of(bytes),
            wiped.depth_of(bytes),
            signing.depth_of(bytes)
        );
    }

    assert!(bare.depth() < SPAN, "the probe must see the whole build");
    assert!(
        bare.depth() <= ANCHOR_STACK_WIPE,
        "the build outgrows the wipe"
    );
    assert!(
        wiped.depth() >= ANCHOR_STACK_WIPE,
        "the wipe must run below the build"
    );
    let above = wiped.depth() - ANCHOR_STACK_WIPE;
    assert!(
        signing.depth() < SPAN,
        "the probe must see the whole signature"
    );
    for (secret, bytes) in &secrets {
        assert!(
            wiped.depth_of(bytes).is_none_or(|depth| depth <= above),
            "{secret} left below the frames that hold the anchor key"
        );
        assert_eq!(
            signing.depth_of(bytes),
            None,
            "{secret} left below the signer"
        );
    }
}
