//! A TURN's non-projected children narrow nothing: on an unbound branch, a
//! TURN whose shown words are a MESSAGE scoped to relationship R1 beside a
//! `System` row scoped to R2 binds its extraction call to R1 alone, and the
//! claim lands in R1 (review round 1 of #6903; the `System` row stands in
//! for the hidden MESSAGE the witness gate refuses).
//!
//! Needs the consolidation door:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test word_bound_nonprojected_door`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::registry::ENTITY_TYPE_RELATIONSHIP;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::{
    consolidate_unbound_turn_with_system, open_dreamer_vault,
};

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

/// A `System` row of the same TURN is pinned but not read: its label does
/// not narrow the bound. The visible words are scoped to R1, the `System`
/// row to R2, and the Dreamer may read both; the call binds to R1 and the
/// claim lands in R1, not in the empty set.
#[test]
fn a_system_row_does_not_narrow_the_claims_label() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let [shown, system] = [b"shown".as_slice(), b"system".as_slice()].map(|body| {
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_RELATIONSHIP,
                TimeRange { start: 1, end: 1 },
                1,
                body,
            )
            .expect("a relationship");
        id
    });

    let pass = consolidate_unbound_turn_with_system(
        &vault,
        WORDS,
        Some(serde_json::json!({"rel": shown.to_hex()})),
        Some(serde_json::json!({"rel": system.to_hex()})),
        &[shown, system],
        &reply(),
    )
    .expect("one unbound consolidation pass");

    assert!(!pass.call_relationships.is_empty(), "the model was called");
    assert_eq!(
        pass.call_relationships[0],
        Some(BTreeSet::from([shown])),
        "the call binds to the words it shows, not to a System row's label"
    );
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
        Some(vec![shown]),
        "the claim lands in the shown words' relationship"
    );
}
