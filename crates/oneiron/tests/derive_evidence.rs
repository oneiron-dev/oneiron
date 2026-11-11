//! Evidence items of a derivation batch (untangle 6.7a): a TURN or an
//! admissible claim the actor reads supports a stored claim it reads. The
//! assertion is gated over the head's own scope and lands a `supports` edge;
//! the head's bytes stay as they are.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_evidence`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::{Derived, Evidence, Named, commit, supports, witness_turn};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault};

const READER: &str = "reader";

/// The model's reply: one new person, named in T1, and its name.
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

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    dreamer: EntityId,
    claim: EntityId,
}

/// A vault whose Dreamer landed one claim in a consolidation pass.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let [claim] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        claim: *claim,
    }
}

fn attach(fixture: &Fixture, head: EntityId, source: EntityId) -> (bool, Vec<String>) {
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-evidence",
        &[Derived::Evidence(Evidence {
            local: "evidence",
            head: Named::Stored(head),
            sources: vec![Named::Stored(source)],
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    (item.landed, item.reasons.clone())
}

#[test]
fn the_dreamer_attaches_a_turn_it_reads_to_its_claim() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "my name is Owen").expect("a TURN");
    let before = fixture.vault.get(&fixture.claim).expect("read");
    let (landed, reasons) = attach(&fixture, fixture.claim, turn);
    assert!(landed, "the evidence lands: {reasons:?}");
    assert!(
        supports(&fixture.vault, turn, fixture.claim).expect("read"),
        "the TURN supports the claim"
    );
    assert_eq!(
        fixture.vault.get(&fixture.claim).expect("read"),
        before,
        "the head's bytes stay as they are"
    );
}

#[test]
fn evidence_from_a_row_the_actor_does_not_read_is_refused() {
    let fixture = fixture();
    let missing = EntityId::now();
    assert_eq!(
        attach(&fixture, fixture.claim, missing),
        (
            false,
            vec!["gate.deny.derive.evidence_unverified".to_owned()]
        )
    );
    assert!(!supports(&fixture.vault, missing, fixture.claim).expect("read"));
}

#[test]
fn evidence_for_a_row_that_is_no_claim_is_refused() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "my name is Owen").expect("a TURN");
    let other = witness_turn(&fixture.vault, "I live in Tokyo").expect("a TURN");
    assert_eq!(
        attach(&fixture, turn, other),
        (
            false,
            vec!["gate.deny.derive.evidence_head_not_a_claim".to_owned()]
        )
    );
}
