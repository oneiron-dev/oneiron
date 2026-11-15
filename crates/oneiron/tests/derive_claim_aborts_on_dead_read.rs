//! A derivation commit by an actor whose read credential is not live
//! (untangle 6.7): a base agent whose Steward grant lacks `read` reads
//! nothing, so the claim and evidence items refuse with
//! `gate.deny.derive.read_not_live` and the batch still commits, and the
//! source recheck denies the commit with the same token.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_claim_aborts_on_dead_read`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Evidence, Named, batch_items, batches_of, claim_lifecycle, commit,
    commit_claims, commit_with_sources, refusal_receipt, source_version,
};
use oneiron::test_doors::steward::{STEWARD_ARCHIVE_VERB, dreamer, stand_steward_grant};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const READER: &str = "reader";
const READ_NOT_LIVE: &str = "gate.deny.derive.read_not_live";
const DEPENDENCY_REFUSED: &str = "gate.deny.derive.dependency_refused";

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

/// The Dreamer's Steward grant without `read`: its read credential is not
/// live, so its scoped read serves nothing.
fn kill_read(fixture: &Fixture) {
    stand_steward_grant(
        &fixture.vault,
        fixture.dreamer,
        &["derive", STEWARD_ARCHIVE_VERB],
    )
    .expect("a grant without read");
}

#[test]
fn a_claim_item_with_a_dead_read_is_refused_and_the_batch_commits() {
    let fixture = fixture();
    kill_read(&fixture);
    let committed = commit_claims(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-dead-read",
        &[
            Claim {
                local: "unread",
                predicate: "preference.coffee",
                subject: Named::Stored(fixture.person),
                value: json!("an oat milk flat white"),
                evidence: Vec::new(),
            },
            Claim {
                local: "built_on_unread",
                predicate: "preference.tea",
                subject: Named::Stored(fixture.person),
                value: json!("a green tea"),
                evidence: vec![Named::Local("unread")],
            },
        ],
    )
    .expect("the batch commits: a dead read refuses the item, not the batch");
    let [unread, dependent] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(
        !unread.landed,
        "the item with a dead read is refused: {unread:?}"
    );
    assert_eq!(unread.reasons, vec![READ_NOT_LIVE.to_owned()]);
    assert_eq!(
        refusal_receipt(&fixture.vault, committed.batch, "unread").expect("read"),
        Some(vec![READ_NOT_LIVE.to_owned()]),
        "the refusal is receipted"
    );
    assert!(
        !dependent.landed,
        "a claim citing a refused item is refused"
    );
    assert_eq!(dependent.reasons, vec![DEPENDENCY_REFUSED.to_owned()]);
    assert_eq!(
        batch_items(&fixture.vault, committed.batch).expect("read"),
        Some(committed.items.clone()),
        "the batch record keeps every outcome"
    );
}

#[test]
fn an_evidence_item_with_a_dead_read_is_refused_and_the_batch_commits() {
    let fixture = fixture();
    // The head lands while the Dreamer's read is live.
    let seeded = commit_claims(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-seed-head",
        &[Claim {
            local: "head",
            predicate: "preference.coffee",
            subject: Named::Stored(fixture.person),
            value: json!("an oat milk flat white"),
            evidence: vec![Named::Stored(fixture.turn)],
        }],
    )
    .expect("commit");
    assert!(
        seeded.items[0].landed,
        "the head lands: {:?}",
        seeded.items
    );
    let head = seeded.items[0].rows[0];
    kill_read(&fixture);
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-dead-read-evidence",
        &[Derived::Evidence(Evidence {
            local: "evidence",
            head: Named::Stored(head),
            sources: Vec::new(),
        })],
    )
    .expect("the batch commits: a dead read refuses the item, not the batch");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(!item.landed, "the item with a dead read is refused: {item:?}");
    assert_eq!(item.reasons, vec![READ_NOT_LIVE.to_owned()]);
    assert_eq!(
        refusal_receipt(&fixture.vault, committed.batch, "evidence").expect("read"),
        Some(vec![READ_NOT_LIVE.to_owned()]),
        "the refusal is receipted"
    );
    assert_eq!(
        batch_items(&fixture.vault, committed.batch).expect("read"),
        Some(committed.items.clone()),
        "the batch record keeps every outcome"
    );
    assert_eq!(
        claim_lifecycle(&fixture.vault, head).expect("read"),
        Some("active".to_owned()),
        "the head stands"
    );
}

#[test]
fn the_source_recheck_denies_a_commit_whose_read_is_dead() {
    let fixture = fixture();
    let version = source_version(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        fixture.turn,
    )
    .expect("read")
    .expect("the Dreamer reads the TURN");
    kill_read(&fixture);
    assert_eq!(
        commit_with_sources(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            "run-dead-read-recheck",
            &[Derived::Claim(Claim {
                local: "coffee",
                predicate: "preference.coffee",
                subject: Named::Stored(fixture.person),
                value: json!("an oat milk flat white"),
                evidence: vec![Named::Stored(fixture.turn)],
            })],
            vec![version],
        )
        .expect("commit"),
        Err(vec![READ_NOT_LIVE.to_owned()])
    );
    assert!(
        batches_of(&fixture.vault, fixture.dreamer)
            .expect("read")
            .is_empty(),
        "no batch is recorded"
    );
}
