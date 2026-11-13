//! An extraction candidate never holds wider than its words' relationship
//! label (S63E-RULED, live leak 1). On an unbound branch, a TURN whose words
//! are a MESSAGE scoped to relationship R yields a claim scoped to R even when
//! the model names no relationship, and a member outside R does not read it.
//! On main the claim was stamped `rel: all`.
//!
//! Needs the consolidation door:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test extraction_relationship_label`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::claim::{PointRead, ScopedReadActorKey};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};

const READER: &str = "reader";
const WORDS: &str = "call me Owen";

/// The model's reply: one new person, named in T1, and its name, with no
/// relationship.
fn reply() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

#[test]
fn a_claim_from_a_relationship_limited_message_stays_inside_the_relationship() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 1, end: 1 },
            1,
            b"relationship",
        )
        .expect("a relationship");
    let outsider = EntityId::now();
    vault
        .put_entity(
            &outsider,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"outsider",
        )
        .expect("a member outside the relationship");

    let pass = consolidate_unbound_turn(
        &vault,
        WORDS,
        Some(serde_json::json!({"rel": relationship.to_hex()})),
        Some(relationship),
        &reply(),
    )
    .expect("one unbound consolidation pass");

    // The extraction call was bound to the words' relationship.
    assert!(!pass.call_relationships.is_empty(), "the model was called");
    assert_eq!(
        pass.call_relationships[0],
        Some(BTreeSet::from([relationship])),
        "the unbound branch's call binds to its words' label"
    );

    // The landed claim carries the relationship, never `all`.
    let [claim] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    let body = vault
        .get_claim(claim)
        .expect("claim")
        .expect("landed claim");
    assert_eq!(
        body.rel
            .as_ref()
            .map(|rel| rel.iter().copied().collect::<Vec<_>>()),
        Some(vec![relationship]),
        "the claim inherits its words' relationship label"
    );

    // A member outside the relationship reads nothing of it.
    let outside = vault.scoped_read(
        ScopedReadActorKey::new(READER)
            .expect("reader key")
            .require_access_grants(Some(outsider)),
    );
    assert_eq!(
        outside
            .read(&[PointRead::id(*claim)], None)
            .expect("outsider read")
            .value,
        vec![None],
        "a member outside the relationship does not read the claim"
    );
}
