//! K-proof for the extraction read digests at 35406ef709a7: the equality tokens, the
//! facts pin and the policy pin keep main's bytes through the fingerprint K door.
//!
//! An observations page sends equality tokens with its rows (a candidate row carries the
//! identity, topic, value and slice tokens; a prior or replay row the first three), the
//! facts pin (on the page and inside each cursor, which the next page's read compares)
//! and the policy pin; an inputs page sends the same policy pin. The extraction job
//! compares two rows' tokens, both pins across its pages and with its selection, and the
//! policy pin with its config.
//!
//! What each test covers. The token test runs the read's own token function over native
//! keys, so it covers the encoding of the keys, which tag each key takes, the framing and
//! the hex. The two pin tests start at the encoded bytes: they cover the tag, the framing
//! and the hex, and not the line that encodes the request and fact set or the policy,
//! which the change to the K door does not touch.
//!
//! The base functions copy main's lines. Headers and returns are hand-written, and where
//! main returns a bad request for a key that does not encode, the base panics.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_extraction_read_digests`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::dreamer_consolidation::ConflictIdentity;
use oneiron::dreamer_consolidation::routing::CandidateKeys;
use oneiron::test_doors::fingerprint_keep_extraction_read_digests as door;

// main 35406ef709a7: crates/oneiron/src/snapshot_read/extraction_observations/tokens.rs:19-47
fn base_observation_key_tokens(keys: &CandidateKeys) -> [String; 4] {
    let identity = &keys.identity;
    let subject = identity.subject.to_hex();
    let world = identity.world.map(|id| id.to_hex());
    let facet = identity.facet.map(|id| id.to_hex());
    let relationships = identity
        .rel
        .as_ref()
        .map(|ids| ids.iter().map(|id| id.to_hex()).collect::<Vec<_>>());
    let project = identity.project.to_hex();
    let encoded_identity = serde_json::to_vec(&(
        &subject,
        &identity.predicate,
        &world,
        &facet,
        &relationships,
        &project,
        &identity.topic,
    ))
    .unwrap_or_else(|error| panic!("the identity encodes: {error}"));
    let encoded_slice = serde_json::to_vec(&(&subject, &world, &facet, &relationships, &project))
        .unwrap_or_else(|error| panic!("the slice encodes: {error}"));
    [
        base_equality_token(b"oneiron:extraction:identity-token:v1", &encoded_identity),
        base_equality_token(b"oneiron:extraction:topic-token:v1", &keys.topic_key),
        base_equality_token(b"oneiron:extraction:value-token:v1", &keys.value_key),
        base_equality_token(b"oneiron:extraction:slice-token:v1", &encoded_slice),
    ]
}

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

fn id(hex: &str) -> EntityId {
    EntityId::from_hex(hex).unwrap_or_else(|_| panic!("{hex} is an entity id"))
}

/// Two key triples that differ in every part: one with no world, facet, relationship or
/// topic, and one with all four, an empty topic key and a zero byte as its value key.
fn key_samples() -> Vec<CandidateKeys> {
    let subject = id("00112233445566778899aabbccddeeff");
    let project = id("ffeeddccbbaa99887766554433221100");
    let other = id("0123456789abcdef0123456789abcdef");
    vec![
        CandidateKeys {
            identity: ConflictIdentity {
                subject,
                predicate: "likes".to_owned(),
                world: None,
                facet: None,
                rel: None,
                project,
                topic: None,
            },
            topic_key: b"drink".to_vec(),
            value_key: b"tea".to_vec(),
        },
        CandidateKeys {
            identity: ConflictIdentity {
                subject: other,
                predicate: "lives_in".to_owned(),
                world: Some(project),
                facet: Some(subject),
                rel: Some([other, subject].into_iter().collect()),
                project,
                topic: Some(b"home\0city".to_vec()),
            },
            topic_key: Vec::new(),
            value_key: vec![0],
        },
    ]
}

/// Encoded bodies that would show a change of framing: no bytes, one zero byte, a zero
/// byte inside, a JSON array, and one longer than a BLAKE3 chunk.
fn encoded_samples() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0],
        b"a\0b".to_vec(),
        br#"["4f1c",1700000000000,[],"9a3e",{"candidates":[]}]"#.to_vec(),
        (0..=255_u8).cycle().take(4097).collect(),
    ]
}

#[test]
fn a_rows_equality_tokens_keep_mains_bytes() {
    for keys in key_samples() {
        assert_eq!(
            door::equality_tokens(&keys),
            Some(base_observation_key_tokens(&keys)),
        );
    }
}

#[test]
fn the_facts_pin_keeps_mains_bytes() {
    for encoded in encoded_samples() {
        assert_eq!(
            door::observation_facts_pin(&encoded),
            base_observation_facts_pin(&encoded),
        );
    }
}

#[test]
fn the_policy_pin_keeps_mains_bytes() {
    for encoded in encoded_samples() {
        assert_eq!(
            door::extraction_policy_pin(&encoded),
            base_extraction_policy_pin(&encoded),
        );
    }
}
