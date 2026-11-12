//! A reverted evidence attachment ends now, in Unix seconds (FIX-LIST
//! PROVENANCE-RETRACT-MS-AS-SECONDS). The derive batch revert and the
//! owner's revert of a Dreamer change both take an evidence (`edge.provenance`)
//! claim back through the provenance retract, which takes Unix seconds and
//! writes them as the claim's end time. Both reverts hold milliseconds, so
//! each divides by 1 000, as their other inverses do.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test evidence_revert_end_time`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::ClaimLifecycleStatus;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::{Derived, Evidence, Named, commit, revert, witness_turn};
use oneiron::test_doors::steward::dreamer;
use oneiron::test_support::{bind_host_owner, test_host_issuer};
use oneiron::{EdgeActorClass, EntityId, Vault};

const READER: &str = "reader";

/// Slack around the window the revert ran in. A millisecond end time lies
/// about 1.7e12 past the epoch, far outside it.
const SLACK_SECS: u64 = 86_400;

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
    /// The Dreamer's batch that attached the evidence.
    batch: EntityId,
    /// The evidence (`edge.provenance`) claim it landed.
    record: EntityId,
}

/// A vault whose Dreamer landed one claim, then attached a TURN it reads to
/// that claim as evidence in one derive batch.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let [claim] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    let turn = witness_turn(&vault, "my name is Owen").expect("a TURN");
    let committed = commit(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-evidence",
        &[Derived::Evidence(Evidence {
            local: "evidence",
            head: Named::Stored(*claim),
            sources: vec![Named::Stored(turn)],
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the evidence lands: {:?}", item.reasons);
    let [record] = item.rows.as_slice() else {
        panic!("one support record: {item:?}");
    };
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        batch: committed.batch,
        record: *record,
    }
}

/// The retracted evidence claim's end time, checked against the window
/// `[before, after]` (Unix seconds) the revert ran in.
fn assert_ended_in_seconds(fixture: &Fixture, before: u64, after: u64) {
    let body = fixture
        .vault
        .get_claim(&fixture.record)
        .expect("read")
        .expect("the evidence claim");
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Retracted);
    let end = body
        .valid_to
        .expect("a retracted evidence claim has an end");
    assert!(
        end + SLACK_SECS >= before && end <= after + SLACK_SECS,
        "the end time {end} is not Unix seconds near the revert ({before}..={after})"
    );
}

#[test]
fn a_derive_revert_ends_the_evidence_claim_now_in_seconds() {
    let fixture = fixture();
    let before = fixture.vault.now_recorded_at();
    let (reverted, left) = revert(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        fixture.batch,
    )
    .expect("revert")
    .expect("the Dreamer may revert its own batch");
    let after = fixture.vault.now_recorded_at();
    assert_eq!(reverted, vec!["evidence".to_owned()]);
    assert!(left.is_empty(), "{left:?}");
    assert_ended_in_seconds(&fixture, before, after);
}

#[test]
fn an_owner_revert_of_the_dreamers_evidence_ends_it_now_in_seconds() {
    let fixture = fixture();
    let vault = &fixture.vault;
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    bind_host_owner(vault, &test_host_issuer(), owner_id).expect("the owner's root binding");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    let before = vault.now_recorded_at();
    let receipt = vault
        .memory(owner_id, EdgeActorClass::Human)
        .revert_dreamer_change(&owner, fixture.record, vault.now_recorded_ms())
        .expect("the owner reverts the Dreamer's evidence");
    let after = vault.now_recorded_at();
    assert_eq!(receipt.reverted.retracted, vec![fixture.record]);
    assert_ended_in_seconds(&fixture, before, after);
}
