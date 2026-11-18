//! K-proof for the extraction read digests at 35406ef709a7: the equality tokens, the
//! facts pin and the policy pin keep main's bytes through the fingerprint K door.
//!
//! An observations page sends four equality tokens with its fact rows, the facts pin (on
//! the page and inside each cursor, which the next page's read compares) and the policy
//! pin; an inputs page sends the same policy pin. The extraction job compares the tokens
//! of two rows, and the pins across its pages, its config and its selection.
//!
//! Each base function copies main's hash lines. Its header is hand-written, and it takes
//! the encoded bytes that main's lines hash.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_extraction_read_digests`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::fingerprint_keep_extraction_read_digests as door;

// main 35406ef709a7: crates/oneiron/src/snapshot_read/extraction_observations/tokens.rs:42-45
const IDENTITY_DOMAIN: &[u8] = b"oneiron:extraction:identity-token:v1";
const TOPIC_DOMAIN: &[u8] = b"oneiron:extraction:topic-token:v1";
const VALUE_DOMAIN: &[u8] = b"oneiron:extraction:value-token:v1";
const SLICE_DOMAIN: &[u8] = b"oneiron:extraction:slice-token:v1";

// main 35406ef709a7: crates/oneiron/src/snapshot_read/extraction_observations/tokens.rs:50-56
fn base_equality_token(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(&[0]);
    hash.update(bytes);
    hash.finalize().to_hex().to_string()
}

// main 35406ef709a7: crates/oneiron/src/snapshot_read/extraction_observations/paging.rs:74-78
fn base_observation_facts_pin(encoded: &[u8]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:extraction:observations-facts:v1");
    hash.update(&[0]);
    hash.update(encoded);
    hash.finalize().to_hex().to_string()
}

// main 35406ef709a7: crates/oneiron/src/snapshot_read/extraction_inputs.rs:395-398
fn base_extraction_policy_pin(encoded: &[u8]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.dreamer.extraction.policy.v1");
    hash.update(encoded);
    hash.finalize().to_hex().to_string()
}

/// Bodies that would show a change of framing: no bytes, one zero byte, a zero byte
/// inside, an encoded identity array, and one longer than a BLAKE3 chunk.
fn bodies() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0],
        b"a\0b".to_vec(),
        br#"["00112233445566778899aabbccddeeff","likes",null,null,null,"ffeeddccbbaa99887766554433221100","tea"]"#
            .to_vec(),
        (0..=255_u8).cycle().take(4097).collect(),
    ]
}

#[test]
fn each_equality_token_keeps_mains_bytes_under_its_own_tag() {
    let bodies = bodies();
    for first in 0..bodies.len() {
        let identity = &bodies[first];
        let topic = &bodies[(first + 1) % bodies.len()];
        let value = &bodies[(first + 2) % bodies.len()];
        let slice = &bodies[(first + 3) % bodies.len()];
        assert_eq!(
            door::equality_tokens(identity, topic, value, slice),
            [
                base_equality_token(IDENTITY_DOMAIN, identity),
                base_equality_token(TOPIC_DOMAIN, topic),
                base_equality_token(VALUE_DOMAIN, value),
                base_equality_token(SLICE_DOMAIN, slice),
            ],
        );
    }
}

#[test]
fn one_key_has_four_different_tokens() {
    let key = b"one key under four tags";
    let tokens = door::equality_tokens(key, key, key, key);
    for (at, token) in tokens.iter().enumerate() {
        assert!(!tokens[at + 1..].contains(token));
    }
}

#[test]
fn the_facts_pin_keeps_mains_bytes() {
    for body in bodies() {
        assert_eq!(
            door::observation_facts_pin(&body),
            base_observation_facts_pin(&body),
        );
    }
}

#[test]
fn the_policy_pin_keeps_mains_bytes() {
    for body in bodies() {
        assert_eq!(
            door::extraction_policy_pin(&body),
            base_extraction_policy_pin(&body),
        );
    }
}
