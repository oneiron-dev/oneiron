//! The derivation commit's source recheck (untangle 6.7a, from 6.4a's
//! primitive A): every stored source an item cites names the version the
//! caller's read served, and the commit judges each again in its own write.
//! A source that moved or is withheld since aborts the whole batch.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_sources`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Named, Supersede, batches_of, claim_lifecycle, commit, commit_with_sources,
    source_version,
};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const READER: &str = "reader";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    dreamer: EntityId,
    person: EntityId,
    turn: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        turn,
    }
}

fn claim(fixture: &Fixture) -> Derived {
    Derived::Claim(Claim {
        local: "coffee",
        predicate: "preference.coffee",
        subject: Named::Stored(fixture.person),
        value: json!("an oat milk flat white"),
        evidence: vec![Named::Stored(fixture.turn)],
    })
}

fn version(fixture: &Fixture) -> oneiron::snapshot_read::SourceVersion {
    source_version(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        fixture.turn,
    )
    .expect("read")
    .expect("the Dreamer reads the TURN")
}

#[test]
fn a_batch_citing_its_sources_at_the_versions_read_lands() {
    let fixture = fixture();
    let committed = commit_with_sources(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-current",
        &[claim(&fixture)],
        vec![version(&fixture)],
    )
    .expect("commit");
    assert!(committed.is_ok(), "{committed:?}");
}

#[test]
fn a_batch_citing_a_source_that_moved_lands_nothing() {
    let fixture = fixture();
    let mut moved = version(&fixture);
    moved.revision = format!("blake3:{}", "1".repeat(64));
    assert_eq!(
        commit_with_sources(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            "run-moved",
            &[claim(&fixture)],
            vec![moved],
        )
        .expect("commit"),
        Err(vec!["gate.deny.derive.source_moved".to_owned()])
    );
    assert!(
        batches_of(&fixture.vault, fixture.dreamer)
            .expect("read")
            .is_empty(),
        "no batch is recorded"
    );
}

#[test]
fn a_batch_citing_a_source_without_its_version_is_malformed() {
    let fixture = fixture();
    commit_with_sources(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-unversioned",
        &[claim(&fixture)],
        Vec::new(),
    )
    .expect_err("a cited source with no version is a malformed batch");
}

#[test]
fn a_local_name_never_stands_for_a_row_its_item_did_not_create() {
    let fixture = fixture();
    let seeded = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-seed",
        &[
            claim(&fixture),
            Derived::Claim(Claim {
                local: "older",
                predicate: "preference.coffee",
                subject: Named::Stored(fixture.person),
                value: json!("a black filter coffee"),
                evidence: vec![Named::Stored(fixture.turn)],
            }),
        ],
    )
    .expect("commit");
    assert!(
        seeded.items.iter().all(|item| item.landed),
        "both seed claims land: {:?}",
        seeded.items
    );
    let stored = seeded.items[0].rows[0];
    let older = seeded.items[1].rows[0];
    let before = batches_of(&fixture.vault, fixture.dreamer).expect("read");

    // The supersession creates no row: its name would stand for `stored`, a
    // row that was there before the batch, cited with no version.
    commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-alias",
        &[
            Derived::Supersede(Supersede {
                local: "replace_older",
                new: Named::Stored(stored),
                old: Named::Stored(older),
            }),
            Derived::Claim(Claim {
                local: "built_on_the_alias",
                predicate: "preference.tea",
                subject: Named::Stored(fixture.person),
                value: json!("a green tea"),
                evidence: vec![Named::Local("replace_older")],
            }),
        ],
    )
    .expect_err("a name of an item that creates no row is a malformed reference");
    assert_eq!(
        claim_lifecycle(&fixture.vault, older).expect("read"),
        Some("active".to_owned()),
        "the malformed batch lands nothing"
    );
    assert_eq!(
        batches_of(&fixture.vault, fixture.dreamer).expect("read"),
        before,
        "no batch is recorded"
    );
}
