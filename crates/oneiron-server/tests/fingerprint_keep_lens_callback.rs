//! K-proof (oracle) for PLAN-UC-04 stage 5c: a lens card press's dedupe key keeps its bytes.
//!
//! The key (`purposes::ai_host::LENS_CALLBACK_DEDUPE_KEY`) now starts its BLAKE3 through the
//! fingerprint crate's K door, and its hex comes from `oneiron_hex::encode` in place of
//! BLAKE3's `to_hex`. The dreamer attempt row stores it, and a repeated press finds its queued
//! callback by it, so it must give main's text for every press. The `base_lens` module holds
//! main's lines at e8ab7831950c, copied by range (the range is named above its copy; the generator
//! is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them
//! only in indentation, with a wrapper that carries main's private fn to the tests.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test fingerprint_keep_lens_callback`.
#![cfg(oneiron_test_support)]

use oneiron::lens::LensRenderId;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_server::test_doors::fingerprint_keep_lens_callback as door;

// Not formatted, so the copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_lens {
    use oneiron::lens::LensRenderId;

    // main e8ab7831950c: crates/oneiron-server/src/ai_host/lens_callbacks.rs:136-143
    fn dedupe_key(credential: &str, card: &LensRenderId, idempotency_key: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        for part in [credential, card.as_str(), idempotency_key] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        format!("lens-callback:{}", hasher.finalize().to_hex())
    }

    /// Main's lens callback dedupe key, which is private there.
    pub(crate) fn main_lens_callback_dedupe_key(credential: &str, card: &LensRenderId, idempotency_key: &str) -> String {
        dedupe_key(credential, card, idempotency_key)
    }
}

/// Free text with the edge rows: empty, one byte, a NUL, non-ASCII, a run that is a prefix
/// of another row's, a separator and a long run.
fn texts() -> Vec<String> {
    let mut rows: Vec<String> = [
        "",
        "a",
        "\0",
        "\u{ff}\u{1F600}",
        "key",
        "key:1",
        "lens-callback:",
    ]
    .iter()
    .map(|row| (*row).to_string())
    .collect();
    rows.push("k".repeat(4_096));
    rows
}

/// Render ids at the token rules' edges: one character, each allowed punctuation, and the
/// longest (128 bytes).
fn cards() -> Vec<LensRenderId> {
    let longest = "A".repeat(128);
    ["c", "card-1", "card.v2_x", longest.as_str()]
        .into_iter()
        .map(|card| LensRenderId::new(card).expect("a valid render id"))
        .collect()
}

#[test]
fn the_lens_callback_purpose_writes_no_tag() {
    let purpose = purposes::ai_host::LENS_CALLBACK_DEDUPE_KEY;
    assert_eq!(
        (purpose.hash(), purpose.tag_mode()),
        (LegacyHash::Blake3, TagMode::NotHashed)
    );
}

#[test]
fn the_lens_callback_dedupe_key_keeps_its_bytes() {
    let texts = texts();
    let mut rows = 0;
    for credential in &texts {
        for card in cards() {
            for idempotency_key in &texts {
                let key = door::lens_callback_dedupe_key(credential, &card, idempotency_key);
                assert_eq!(
                    key,
                    base_lens::main_lens_callback_dedupe_key(credential, &card, idempotency_key),
                    "credential {credential:?}, card {card:?}, key {idempotency_key:?}"
                );
                assert_eq!(key.len(), "lens-callback:".len() + 64);
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 256);
}
