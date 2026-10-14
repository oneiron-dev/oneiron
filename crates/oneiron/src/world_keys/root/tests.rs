//! The owner anchor's stack wipes (RustCrypto/meta#38; Wonder code-R4 W4-F1, Sol code-R5
//! S5-F1): building the anchor key and signing with it reach below their callers, on this
//! crate's own ed25519-dalek, and `anchor` and `sign_as_anchor` wipe that reach. Each
//! wipe ran below its caller as deep as the constant, which covers the bare reach, and no
//! anchor secret is left below the frames that hold the result. The key `anchor` returns
//! moves out by value, so copies of its own secret sit above the wipe.

use oneiron_crypto::stack_probe::{self, Below};
use sha2::{Digest, Sha512};

use super::{
    ANCHOR_CONTEXT, ANCHOR_STACK_WIPE, RecoveryRootSeed, anchor_key, anchor_signature,
    sign_as_anchor,
};

/// Checks one bare run against its wiped twin, and returns whether the bare run left any
/// of `secrets` below its caller.
fn within_the_wipe(name: &str, bare: &Below, wiped: &Below, secrets: &[(&str, Vec<u8>)]) -> bool {
    let span = ANCHOR_STACK_WIPE + 64 * 1024;
    eprintln!(
        "anchor {name}: reached {} bytes below its caller; the wipe covers {ANCHOR_STACK_WIPE}",
        bare.depth()
    );
    for (secret, bytes) in secrets {
        eprintln!(
            "anchor {name}: {secret}: bare {:?}, wiped {:?}",
            bare.depth_of(bytes),
            wiped.depth_of(bytes)
        );
    }
    assert!(bare.depth() < span, "the probe must see the whole {name}");
    assert!(
        bare.depth() <= ANCHOR_STACK_WIPE,
        "the {name} outgrows the wipe"
    );
    assert!(
        wiped.depth() >= ANCHOR_STACK_WIPE,
        "the wipe must run below the {name}"
    );
    let above = wiped.depth() - ANCHOR_STACK_WIPE;
    for (secret, bytes) in secrets {
        assert!(
            wiped.depth_of(bytes).is_none_or(|depth| depth <= above),
            "{secret} left below the frames that hold the {name}"
        );
    }
    secrets
        .iter()
        .any(|(_, bytes)| bare.depth_of(bytes).is_some())
}

#[test]
fn the_anchor_key_and_its_signatures_stay_within_the_wipe() {
    let seed = RecoveryRootSeed::generate().expect("os entropy");
    let secret = blake3::derive_key(ANCHOR_CONTEXT, &seed.bytes[..]);
    let expanded = Sha512::digest(secret);
    let secrets = [
        ("anchor secret", secret.to_vec()),
        ("expanded scalar half", expanded[..32].to_vec()),
        ("expanded hash prefix", expanded[32..].to_vec()),
    ];
    let span = ANCHOR_STACK_WIPE + 64 * 1024;
    let message: &[u8] = b"stack probe transcript";

    let bare = stack_probe::run(span, &mut || drop(anchor_key(&seed.bytes)));
    let wiped = stack_probe::run(span, &mut || drop(seed.anchor()));
    let key_left = within_the_wipe("key build", &bare, &wiped, &secrets);

    let anchor = seed.anchor();
    let bare = stack_probe::run(span, &mut || drop(anchor_signature(&anchor, message)));
    let wiped = stack_probe::run(span, &mut || drop(sign_as_anchor(&anchor, message)));
    let signature_left = within_the_wipe("signature", &bare, &wiped, &secrets);

    assert!(
        key_left || signature_left,
        "the probe must see what the bare anchor paths leave"
    );
}
