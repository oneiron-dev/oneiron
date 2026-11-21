//! The predicted residence acts (census L7-46 + L10-14; ARCH-0023b
//! #predicted-residence). The owner's `sync_predicted` directive carries
//! the owner's budget, with no ceiling (Engine ruling L7-46-BUDGET B). The
//! home's `predicted` directive names its set by digest and counts, so the
//! authority entry every replica stores does not grow with the set; only the
//! named machine fetches the set's body, and refuses one that is not the
//! body of that digest (Engine ruling L7-46-BUDGET-CEILING, 14 Nov 11:28).

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron_authority::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthoritySignatureSuite, PredictedResidenceSet, ResidenceAct, ResidenceDirective,
    authority_transcript, decode_authority_log_entry_body, encode_authority_log_entry_body,
};
use oneiron_contracts::EntityId;

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a fixture id")
}

fn signature(transcript: &[u8]) -> AuthoritySignature {
    let signing = SigningKey::from_bytes(&[7; 32]);
    AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
        signature: signing.sign(transcript).to_bytes().to_vec(),
    }
}

/// `act` as a host-signed residence directive's whole entry body.
fn directive_entry(act: ResidenceAct) -> Vec<u8> {
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some([4; 32]),
        seq: 2,
        parent_hashes: vec![[8; 32]],
        op: AuthorityOp::ResidenceDirective(ResidenceDirective {
            id: id(0x11),
            machine: id(0x22),
            owner: id(0x33),
            issued_at: 1_794_000_000,
            act,
        }),
        signer: signature(b"placeholder"),
        cosigns: Vec::new(),
        ts: 10,
    };
    entry.signer = signature(&authority_transcript(&entry).expect("a transcript"));
    encode_authority_log_entry_body(&entry).expect("an encoded entry")
}

/// A set of `windows` window keys and `documents` entity documents.
fn set(windows: u32, documents: u32) -> PredictedResidenceSet {
    PredictedResidenceSet {
        windows: (0..windows)
            .map(|window| format!("2026-11@w{window:05}"))
            .collect(),
        documents: (0..documents)
            .map(|document| {
                let mut bytes = [0x10; 16];
                bytes[12..].copy_from_slice(&document.to_be_bytes());
                EntityId::from_bytes(bytes).expect("a document id")
            })
            .collect(),
    }
}

/// The home's prediction naming `set` under the owner's directive `parent`.
fn prediction(set: &PredictedResidenceSet) -> ResidenceAct {
    let (window_count, document_count) = set.counts().expect("counts that fit");
    ResidenceAct::Predicted {
        parent: id(0x44),
        set_digest: set.digest().expect("a digest"),
        window_count,
        document_count,
    }
}

fn decoded_act(body: &[u8]) -> ResidenceAct {
    match decode_authority_log_entry_body(body)
        .expect("the entry decodes")
        .op
    {
        AuthorityOp::ResidenceDirective(directive) => directive.act,
        other => panic!("not a residence directive: {other:?}"),
    }
}

#[test]
fn a_prediction_entry_does_not_grow_with_its_set() {
    let default_set = set(32, 128);
    let large_set = set(32, 100_000);
    let default_entry = directive_entry(prediction(&default_set));
    let large_entry = directive_entry(prediction(&large_set));

    // The large set's body is megabytes; its entry is the default's but for
    // the width of one count (MessagePack writes 128 in 2 bytes, 100000 in 5).
    let large_body = large_set.encode().expect("the large body");
    assert!(
        large_body.len() > 3_000_000,
        "the set itself: {}",
        large_body.len()
    );
    assert!(
        default_entry.len() < 1_024,
        "a fixed-size entry under a kilobyte: {}",
        default_entry.len()
    );
    assert_eq!(
        large_entry.len(),
        default_entry.len() + 3,
        "only the document count's integer widens",
    );
    assert_eq!(decoded_act(&large_entry), prediction(&large_set));
}

#[test]
fn a_tampered_prediction_body_is_refused_on_its_digest() {
    let named = set(3, 5);
    let body = named.encode().expect("the body");
    let digest = named.digest().expect("the digest");
    assert_eq!(
        PredictedResidenceSet::decode_verified(&body, &digest).expect("the named body"),
        named,
    );

    let mut tampered = body.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        PredictedResidenceSet::decode_verified(&tampered, &digest).is_err(),
        "a changed byte is refused",
    );
    let other = set(3, 6).encode().expect("another body");
    assert!(
        PredictedResidenceSet::decode_verified(&other, &digest).is_err(),
        "another set's body is refused under this digest",
    );

    // A body whose digest matches but which is not canonical (its documents
    // out of order) is refused too: one set has one body.
    let mut documents: Vec<_> = named.documents.iter().map(|id| id.to_hex()).collect();
    documents.reverse();
    let reordered = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("windows"),
            rmpv::Value::Array(
                named
                    .windows
                    .iter()
                    .map(|window| rmpv::Value::from(window.as_str()))
                    .collect(),
            ),
        ),
        (
            rmpv::Value::from("documents"),
            rmpv::Value::Array(documents.into_iter().map(rmpv::Value::from).collect()),
        ),
    ]);
    let mut noncanonical = Vec::new();
    rmpv::encode::write_value(&mut noncanonical, &reordered).expect("a reordered body");
    let noncanonical_digest = PredictedResidenceSet::body_digest(&noncanonical);
    assert!(
        PredictedResidenceSet::decode_verified(&noncanonical, &noncanonical_digest).is_err(),
        "a non-canonical body is refused",
    );
}

#[test]
fn a_sync_predicted_budget_round_trips_without_a_ceiling() {
    let act = ResidenceAct::SyncPredicted {
        window_budget: u32::MAX,
        document_budget: 100_000,
    };
    assert_eq!(decoded_act(&directive_entry(act.clone())), act);
    let empty: BTreeSet<String> = BTreeSet::new();
    assert!(
        PredictedResidenceSet {
            windows: empty,
            documents: BTreeSet::new(),
        }
        .digest()
        .is_ok(),
        "an empty prediction has a digest",
    );
}
