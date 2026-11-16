//! K-proof (oracle) for PLAN-UC-04 stage 6.2a: the web fetch content hash keeps its bytes.
//!
//! A fetch result's content hash (`purposes::web_fetch::CONTENT_HASH`) now starts through
//! the fingerprint crate's K door. A web import stores it in the source's ASSET row,
//! compares it with that row when the same revision comes again and derives the import's
//! ids from it, and the result's decode door takes it again over the Markdown beside it.
//! So it must give main's bytes for every Markdown. The `base` module holds main's lines
//! at 709cd244c3eb, copied by range (each range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them
//! only in indentation. The head's hash is private, so each test reaches it through the
//! public decode door: a result decodes only when its hash equals the head's hash of its
//! Markdown, and the door keeps the hash it was given.
//!
//! `cargo test --locked -p oneiron-web-fetch --test fingerprint_keep_web_fetch`.

use oneiron_fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_web_fetch::web_acquisition::{FetchResult, WEB_FETCH_CONTENT_HASH_DOMAIN};
use serde_json::json;

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base {
    // main 709cd244c3eb: crates/oneiron-web-fetch/src/web_acquisition/mod.rs:16-17
    /// Domain prefix for the OF-444 content identity.
    pub const WEB_FETCH_CONTENT_HASH_DOMAIN: &[u8] = b"oneiron.web_fetch.content.v1\0";

    // main 709cd244c3eb: crates/oneiron-web-fetch/src/web_acquisition/mod.rs:426-431
    pub(crate) fn content_hash(markdown: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(WEB_FETCH_CONTENT_HASH_DOMAIN);
        hasher.update(markdown.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

/// Main's pinned value: `web_fetch/tests.rs` `HASH_FIXTURE_HEX` of `HASH_FIXTURE_MARKDOWN`.
const HASH_FIXTURE_MARKDOWN: &str = "# OF-444\n\nAcquisition body.\n";
const HASH_FIXTURE_HEX: &str = "b6e7636db6a7953a1ed178035555d3d873c222d23517200062ab986348fe5da8";

/// Decodes a result whose hash is `hash` through the head's decode door.
fn decode(markdown: &str, hash: &str) -> Result<FetchResult, serde_json::Error> {
    serde_json::from_value(json!({
        "markdown": markdown,
        "title": "Title",
        "canonical_url": "https://identity.test/page",
        "fetched_at": 1_700_000_042_u64,
        "content_hash": hash,
        "renderer": "readability",
    }))
}

/// Markdown of every shape a page gives: empty, ASCII, multi-byte, NUL and CR bytes, and
/// lengths on each side of BLAKE3's 64-byte block and 1024-byte chunk.
fn markdowns() -> Vec<String> {
    let mut out: Vec<String> = [
        "",
        HASH_FIXTURE_MARKDOWN,
        "# Heading\n\nBody.",
        "# Überschrift\n\n日本語のテキスト — 🦀\n",
        "nul \0 inside",
        "line one\r\nline two\r\n",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for len in [1, 63, 64, 65, 1023, 1024, 1025, 2048, 65_537] {
        out.push("m".repeat(len));
    }
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for len in 0..200_usize {
        let mut text = String::new();
        for _ in 0..len * 7 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let pick = (state >> 33) % 100;
            text.push(match pick {
                0..=79 => char::from(b' ' + u8::try_from(pick % 95).expect("below 95")),
                80..=89 => '\n',
                90..=94 => 'é',
                _ => '語',
            });
        }
        out.push(text);
    }
    out
}

#[test]
fn the_web_fetch_purpose_keeps_main_s_tag() {
    let purpose = purposes::web_fetch::CONTENT_HASH;
    assert_eq!(
        purpose.tag().as_bytes(),
        base::WEB_FETCH_CONTENT_HASH_DOMAIN
    );
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
    assert_eq!(
        WEB_FETCH_CONTENT_HASH_DOMAIN,
        base::WEB_FETCH_CONTENT_HASH_DOMAIN
    );
}

#[test]
fn the_content_hash_keeps_its_bytes() {
    let markdowns = markdowns();
    assert_eq!(markdowns.len(), 215);
    for markdown in &markdowns {
        let main = base::content_hash(markdown);
        let decoded = decode(markdown, &main).unwrap_or_else(|error| {
            panic!(
                "the head refuses main's hash of {} bytes: {error}",
                markdown.len()
            )
        });
        assert_eq!(decoded.content_hash(), main);
        assert_eq!(decoded.markdown(), markdown);
    }
}

#[test]
fn the_decode_door_refuses_another_markdown_s_hash() {
    for markdown in markdowns() {
        let other = base::content_hash(&format!("{markdown}!"));
        assert!(
            decode(&markdown, &other).is_err(),
            "the door took another Markdown's hash for {} bytes",
            markdown.len()
        );
    }
}

#[test]
fn the_pinned_fixture_keeps_its_value() {
    assert_eq!(base::content_hash(HASH_FIXTURE_MARKDOWN), HASH_FIXTURE_HEX);
    let decoded = decode(HASH_FIXTURE_MARKDOWN, HASH_FIXTURE_HEX).expect("the head takes the pin");
    assert_eq!(decoded.content_hash(), HASH_FIXTURE_HEX);
}
