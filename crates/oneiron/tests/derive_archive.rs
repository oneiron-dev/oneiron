//! Archive items of a derivation batch (untangle 6.7a): an agent archives
//! its own weak claim, reversibly, under its live Steward `archive` grant,
//! the strength archive's own fence and the owner's strength policy row.
//! The nightly strength archive and the archive item share that fence and
//! that write.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_archive`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::test_doors::consolidation::{
    UnboundPass, consolidate_unbound_turn, open_dreamer_vault,
};
use oneiron::test_doors::derive::{
    Archive, Derived, Named, commit, commit_in_attempt, revert, row_live, set_strength_policy,
};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, archive_every_quiet_claim, dreamer, stand_steward_grant,
};
use oneiron::{EdgeActorClass, EntityId, Vault};

const READER: &str = "reader";
const CHANGED_SINCE: &str = "derive.revert.changed_since";

/// Sets a strength policy under which every landed claim is quiet and weak,
/// and lets the vault's second-grained clock pass the policy's 1 ms window.
fn quiet_policy(vault: &Vault) {
    archive_every_quiet_claim(vault).expect("strength policy");
    std::thread::sleep(std::time::Duration::from_millis(2_100));
}

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
    pass: UnboundPass,
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
    let claim = *claim;
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        pass,
        claim,
    }
}

fn archive(fixture: &Fixture, attempt: bool, score: f64) -> (bool, Vec<String>) {
    let items = [Derived::Archive(Archive {
        local: "archive",
        claim: Named::Stored(fixture.claim),
        score,
    })];
    let committed = if attempt {
        commit_in_attempt(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            "run-archive",
            Some(fixture.pass.attempt),
            &items,
        )
    } else {
        commit(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            "run-archive",
            &items,
        )
    }
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    (item.landed, item.reasons.clone())
}

#[test]
fn the_dreamer_archives_its_own_quiet_weak_claim() {
    let fixture = fixture();
    quiet_policy(&fixture.vault);
    assert!(row_live(&fixture.vault, fixture.claim).expect("read"));

    let (landed, reasons) = archive(&fixture, true, 0.1);
    assert!(landed, "the archive lands: {reasons:?}");
    assert!(
        !row_live(&fixture.vault, fixture.claim).expect("read"),
        "the archived claim is no longer live"
    );
    assert_eq!(
        fixture
            .vault
            .consolidation_strength_snapshots(&fixture.claim)
            .expect("snapshots")
            .len(),
        1,
        "the archive keeps its strength snapshot"
    );
}

#[test]
fn an_archive_needs_the_archive_grant() {
    let fixture = fixture();
    quiet_policy(&fixture.vault);
    stand_steward_grant(
        &fixture.vault,
        fixture.dreamer,
        &[STEWARD_READ_VERB, "derive"],
    )
    .expect("a grant without archive");
    assert_eq!(
        archive(&fixture, true, 0.1),
        (
            false,
            vec!["gate.deny.derive.grant_lacks_archive".to_owned()]
        )
    );
    assert!(row_live(&fixture.vault, fixture.claim).expect("read"));
}

#[test]
fn an_archive_meets_the_owners_strength_policy() {
    let fixture = fixture();
    // A policy whose quiet window no claim has passed yet.
    set_strength_policy(&fixture.vault, 1.0, u64::MAX).expect("strength policy");
    assert_eq!(
        archive(&fixture, true, 0.1),
        (false, vec!["gate.deny.derive.archive_not_quiet".to_owned()])
    );
    quiet_policy(&fixture.vault);
    // The policy archives only below 1.0.
    assert_eq!(
        archive(&fixture, true, 1.0),
        (
            false,
            vec!["gate.deny.derive.archive_score_not_below_policy".to_owned()]
        )
    );
    assert!(row_live(&fixture.vault, fixture.claim).expect("read"));
}

#[test]
fn an_archive_names_its_attempt() {
    let fixture = fixture();
    quiet_policy(&fixture.vault);
    assert_eq!(
        archive(&fixture, false, 0.1),
        (
            false,
            vec!["gate.deny.derive.archive_needs_attempt".to_owned()]
        )
    );
}

#[test]
fn reverting_an_archive_leaves_a_later_archive_of_the_same_claim() {
    let fixture = fixture();
    quiet_policy(&fixture.vault);
    let archive_as = |run: &str, local: &'static str| {
        commit_in_attempt(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            run,
            Some(fixture.pass.attempt),
            &[Derived::Archive(Archive {
                local,
                claim: Named::Stored(fixture.claim),
                score: 0.1,
            })],
        )
        .expect("commit")
    };
    let first = archive_as("run-archive-first", "first");
    assert!(
        first.items[0].landed,
        "the first archive lands: {:?}",
        first.items
    );
    fixture
        .vault
        .restore_archived(&fixture.claim)
        .expect("the owner's restore");
    assert!(
        row_live(&fixture.vault, fixture.claim).expect("read"),
        "the restored claim is live"
    );

    // The vault's second-grained clock passes the quiet window again.
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let later = archive_as("run-archive-later", "later");
    assert!(
        later.items[0].landed,
        "the later archive lands: {:?}",
        later.items
    );

    let (reverted, left) = revert(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        first.batch,
    )
    .expect("revert")
    .expect("the Dreamer may revert its own batch");
    assert!(
        reverted.is_empty(),
        "the first archive no longer stands: {reverted:?}"
    );
    assert_eq!(left, vec![("first".to_owned(), CHANGED_SINCE.to_owned())]);
    assert!(
        !row_live(&fixture.vault, fixture.claim).expect("read"),
        "the later archive still stands"
    );
}
