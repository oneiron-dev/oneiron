//! Artifact items of a derivation batch (untangle 6.7a, X03): a person's
//! `about` lines and a PsychProfile snapshot land only through their
//! validated publish, under the actor's live `derive` grant, with a receipt.
//! The Dreamer's own `about` landing goes through the same item.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_artifact`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::{
    About, Derived, Named, Profile, about_facts, claim_subject, commit, profile_stored,
    wake_reads_about_facts,
};
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, dreamer, stand_steward_grant,
};
use oneiron::{EdgeActorClass, EntityId, Vault};

const READER: &str = "reader";
const LINE: &str = "Owen is a person on the roster.";

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
    person: EntityId,
}

/// A vault whose Dreamer landed one fact about a new person, and whose wake
/// pass has read that person's facts since.
fn fixture() -> Fixture {
    let fixture = fixture_before_any_wake();
    wake_reads_about_facts(&fixture.vault).expect("the wake pass reads the person's facts");
    fixture
}

/// A vault whose Dreamer landed one fact about a new person, before any wake
/// pass has read that person's facts: the person has no `about` row yet.
fn fixture_before_any_wake() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let [claim] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    let person = claim_subject(&vault, *claim)
        .expect("read")
        .expect("the fact is about the person");
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
    }
}

/// Commits one item as the Dreamer: whether it landed, and its reasons.
fn commit_one(fixture: &Fixture, item: Derived) -> (bool, Vec<String>) {
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-artifact",
        &[item],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    (item.landed, item.reasons.clone())
}

/// The `about` item for the fixture's person, written from `written_from`
/// with one line for each band in `bands`.
fn about(fixture: &Fixture, written_from: [u8; 32], bands: &[u8]) -> Derived {
    Derived::About(About {
        local: "about",
        person: Named::Stored(fixture.person),
        written_from,
        lines: bands.iter().map(|band| (*band, LINE)).collect(),
    })
}

fn facts(fixture: &Fixture) -> ([u8; 32], Vec<u8>) {
    about_facts(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        fixture.person,
    )
    .expect("facts")
}

fn about_line(fixture: &Fixture) -> Option<String> {
    fixture
        .vault
        .person_about(fixture.person, Some(3))
        .expect("read")
}

#[test]
fn about_lines_published_before_any_wake_pass_read_back_at_once() {
    let fixture = fixture_before_any_wake();
    let (digest, bands) = facts(&fixture);
    assert!(!bands.is_empty(), "the person has a fact");
    let (landed, reasons) = commit_one(&fixture, about(&fixture, digest, &bands));
    assert!(landed, "the lines land: {reasons:?}");
    assert_eq!(
        about_line(&fixture).as_deref(),
        Some(LINE),
        "the publish read the facts it was written from in its own write"
    );
}

#[test]
fn a_batch_holds_one_about_item_for_a_person() {
    let fixture = fixture();
    let (digest, bands) = facts(&fixture);
    assert!(!bands.is_empty(), "the person has a fact");
    let again = Derived::About(About {
        local: "about_again",
        person: Named::Stored(fixture.person),
        written_from: digest,
        lines: bands.iter().map(|band| (*band, LINE)).collect(),
    });
    commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-two-abouts",
        &[about(&fixture, digest, &bands), again],
    )
    .expect_err("two about items for one person are a malformed batch");
    assert_eq!(
        about_line(&fixture),
        None,
        "the malformed batch lands nothing"
    );
}

#[test]
fn an_about_item_never_names_a_person_by_another_about_items_name() {
    let fixture = fixture();
    let (digest, bands) = facts(&fixture);
    assert!(!bands.is_empty(), "the person has a fact");
    // An `about` item creates no row: the row it lands on is the PERSON,
    // which stood before the batch. So its name stands for nothing, and a
    // second `about` item cannot reach the same person through it.
    let through_the_first = Derived::About(About {
        local: "about_again",
        person: Named::Local("about"),
        written_from: digest,
        lines: bands.iter().map(|band| (*band, LINE)).collect(),
    });
    commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-about-by-name",
        &[about(&fixture, digest, &bands), through_the_first],
    )
    .expect_err("a name of an item that creates no row is a malformed reference");
    assert_eq!(
        about_line(&fixture),
        None,
        "the malformed batch lands nothing"
    );
}

#[test]
fn the_dreamer_publishes_a_persons_about_lines() {
    let fixture = fixture();
    let (digest, bands) = facts(&fixture);
    assert!(!bands.is_empty(), "the person has a fact");
    let (landed, reasons) = commit_one(&fixture, about(&fixture, digest, &bands));
    assert!(landed, "the lines land: {reasons:?}");
    assert_eq!(about_line(&fixture).as_deref(), Some(LINE));
}

#[test]
fn an_about_landing_needs_the_derive_grant() {
    let fixture = fixture();
    let (digest, bands) = facts(&fixture);
    stand_steward_grant(
        &fixture.vault,
        fixture.dreamer,
        &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB],
    )
    .expect("a grant without derive");
    assert_eq!(
        commit_one(&fixture, about(&fixture, digest, &bands)),
        (
            false,
            vec!["gate.deny.derive.grant_lacks_derive".to_owned()]
        )
    );
    assert_eq!(about_line(&fixture), None, "nothing is written");
}

#[test]
fn an_about_written_from_moved_facts_writes_nothing() {
    let fixture = fixture();
    let (_, bands) = facts(&fixture);
    assert_eq!(
        commit_one(&fixture, about(&fixture, [7; 32], &bands)),
        (false, vec!["gate.deny.derive.about_facts_moved".to_owned()])
    );
    assert_eq!(about_line(&fixture), None);
}

#[test]
fn an_about_has_one_line_for_each_band_with_facts() {
    let fixture = fixture();
    let (digest, bands) = facts(&fixture);
    let short = &bands[..bands.len() - 1];
    assert_eq!(
        commit_one(&fixture, about(&fixture, digest, short)),
        (false, vec!["gate.deny.derive.about_malformed".to_owned()])
    );
    assert_eq!(about_line(&fixture), None);
}

fn turn(vault: &Vault) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("a TURN");
    id
}

#[test]
fn the_dreamer_publishes_a_profile_from_a_record_it_reads() {
    let fixture = fixture();
    let document = turn(&fixture.vault);
    let (landed, reasons) = commit_one(
        &fixture,
        Derived::Profile(Profile {
            local: "profile",
            subject: fixture.person,
            document,
        }),
    );
    assert!(landed, "the profile lands: {reasons:?}");
    assert!(profile_stored(&fixture.vault, fixture.person).expect("read"));
}

#[test]
fn a_profile_from_a_record_the_actor_does_not_read_is_refused() {
    let fixture = fixture();
    assert_eq!(
        commit_one(
            &fixture,
            Derived::Profile(Profile {
                local: "profile",
                subject: fixture.person,
                document: EntityId::now(),
            }),
        ),
        (
            false,
            vec!["gate.deny.derive.profile_source_unread".to_owned()]
        )
    );
    assert!(!profile_stored(&fixture.vault, fixture.person).expect("read"));
}
