//! The vault's memory timeline (L3-39, PLAN-L3-39 PR 1): every move of a
//! row's live revision is numbered in store order, so a memory frontier, a
//! position in that order, names the revision each row held there. The
//! graph-FS memory fork reads rows at such a frontier.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test memory_frontier_timeline`.
#![cfg(oneiron_test_support)]

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::claim_value_redaction::redact_claim_value_fields;
use oneiron::test_doors::memory_frontier::{frontier_now, raw_at, revision_at};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use rmpv::Value;

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn put_person(vault: &Vault, id: &EntityId, body: &[u8]) {
    vault
        .put_entity(id, ENTITY_TYPE_PERSON, range(1), 1, body)
        .expect("put a PERSON");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn an_edit_after_a_frontier_keeps_that_revision_readable() {
    let (_dir, vault) = open();
    let id = EntityId::now();
    put_person(&vault, &id, b"before");
    let frontier = frontier_now(&vault).expect("frontier");
    put_person(&vault, &id, b"after");

    let then = revision_at(&vault, &id, frontier)
        .expect("timeline read")
        .expect("the row held a revision at the frontier");
    let bytes = raw_at(&vault, &id, then)
        .expect("pinned read")
        .expect("the revision at the frontier is retained");
    assert!(
        bytes.ends_with(b"before"),
        "the frontier names the body the row held then: {bytes:?}"
    );
    let live = vault.get_raw(&id).expect("live read").expect("live row");
    assert!(live.ends_with(b"after"), "the live row moved on: {live:?}");
    let now = revision_at(&vault, &id, frontier_now(&vault).expect("frontier"))
        .expect("timeline read")
        .expect("the row holds a revision now");
    assert_ne!(now, then, "the edit is a later move");
    let bytes = raw_at(&vault, &id, now)
        .expect("pinned read")
        .expect("the live revision reads");
    assert!(bytes.ends_with(b"after"), "{bytes:?}");
}

#[test]
fn a_row_born_after_a_frontier_has_no_revision_there() {
    let (_dir, vault) = open();
    put_person(&vault, &EntityId::now(), b"older row");
    let frontier = frontier_now(&vault).expect("frontier");
    let id = EntityId::now();
    put_person(&vault, &id, b"newer row");

    assert_eq!(
        revision_at(&vault, &id, frontier).expect("timeline read"),
        None,
        "a row born after the frontier held nothing there"
    );
    let later = frontier_now(&vault).expect("frontier");
    assert!(later.sequence > frontier.sequence, "the birth is a move");
    assert!(
        revision_at(&vault, &id, later)
            .expect("timeline read")
            .is_some(),
        "a frontier taken after the birth names its revision"
    );
}

#[test]
fn an_index_publication_moves_no_frontier() {
    let (_dir, vault) = open();
    let id = EntityId::now();
    put_person(&vault, &id, b"before");
    put_person(&vault, &id, b"after");
    let staged = frontier_now(&vault).expect("frontier");
    assert!(staged.sequence > 0, "the puts moved the timeline");

    // The edit left the row's indexed revision behind its live one; the idle
    // pass publishes it, moving `indexed` alone (no vector in this vault).
    vault.set_indexed_idle_delay_ms(0).expect("idle delay row");
    let report = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publication");
    assert!(
        report.refreshed.iter().any(|(entity, _)| *entity == id),
        "the idle pass published the edit: {report:?}"
    );
    let published = frontier_now(&vault).expect("frontier");
    assert_eq!(
        published.sequence, staged.sequence,
        "a publication moves no live revision, so no frontier"
    );
}

#[test]
fn an_erased_row_leaves_no_timeline() {
    let (_dir, vault) = open();
    let id = EntityId::now();
    put_person(&vault, &id, b"before");
    let frontier = frontier_now(&vault).expect("frontier");
    put_person(&vault, &id, b"after");
    assert!(
        revision_at(&vault, &id, frontier)
            .expect("timeline read")
            .is_some(),
        "the row held a revision at the frontier"
    );

    assert!(vault.delete_entity(&id).expect("delete"), "the row existed");
    assert_eq!(
        revision_at(&vault, &id, frontier).expect("timeline read"),
        None,
        "the erase took the row's timeline with its revisions"
    );
}

#[test]
fn a_redaction_rewrites_the_revision_a_frontier_names() {
    let (_dir, vault) = open();
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let subject = EntityId::now();
    put_person(&vault, &subject, b"person");
    let claim = EntityId::now();
    let value = Value::Map(vec![
        (Value::from("secret_note"), Value::from("the door code")),
        (Value::from("public_note"), Value::from("likes tea")),
    ]);
    // `profile.` is the prefix the default policy manifest rates normal.
    let body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        value,
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    vault
        .put_claim(&claim, &body, range(100), 100)
        .expect("put the claim");
    let frontier = frontier_now(&vault).expect("frontier");

    let redaction = redact_claim_value_fields(&vault, claim, &["secret_note".to_owned()], owner)
        .expect("redact the value field");
    assert_eq!(redaction.record, claim);
    assert!(
        redaction.changed_history_rows > 0,
        "the redaction rewrote the claim's retained history"
    );

    let then = revision_at(&vault, &claim, frontier)
        .expect("timeline read")
        .expect("the claim held a revision at the frontier");
    let bytes = raw_at(&vault, &claim, then)
        .expect("pinned read")
        .expect("the frontier names a revision the redaction kept");
    assert!(
        !contains(&bytes, b"the door code"),
        "the redacted words never read at the frontier"
    );
    assert!(
        contains(&bytes, b"likes tea"),
        "the rest of the row reads as it stood: {bytes:?}"
    );
}
