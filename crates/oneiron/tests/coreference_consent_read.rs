//! A coreference share-consent claim is read only beside both its ends
//! (COREFERENCE-CONSENT-READ = A): the two-ends rule that guarded
//! `core.coreference.status` now guards `core.coreference.share_consent`
//! too. A non-owner lane that reads one PERSON end but not the other does
//! not read the consent claim; a lane that reads both does.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coreference_consent_read`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{
    COREFERENCE_SHARE_CONSENT_PACT_KEY, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus,
    ClaimSubject, PREDICATE_COREFERENCE_SHARE_CONSENT,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    define_auto_agent, grant_core_read_beside_derive_rows, reader_claim_rows, reader_reads_row,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault};

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
    reader: EntityId,
    person_a: EntityId,
    person_b: EntityId,
    consent: EntityId,
}

/// Two PERSON rows joined by a `same_as` link and consented for one pact,
/// as the owning door writes them; with `second_person_unreadable`, the
/// second PERSON is then cleanup-archived, so no lane reads it.
fn fixture(second_person_unreadable: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let proposer = define_auto_agent(&vault).expect("a proposer");
    let reader = define_auto_agent(&vault).expect("a reader");
    grant_core_read_beside_derive_rows(&vault, reader, proposer)
        .expect("the reader's read grant beside the proposer's rows");
    let person_a = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let person_b = put(&vault, ENTITY_TYPE_PERSON, b"someone else");
    vault
        .put_edge(&person_a, EdgeKind::SameAs, &person_b, 0.0)
        .expect("the same_as link");
    let body = ClaimBody::new(
        PREDICATE_COREFERENCE_SHARE_CONSENT,
        ClaimSubject::Edge {
            source: person_a,
            kind: EdgeKind::SameAs,
            target: person_b,
        },
        rmpv::Value::Map(vec![(
            rmpv::Value::from(COREFERENCE_SHARE_CONSENT_PACT_KEY),
            rmpv::Value::from("a".repeat(64)),
        )]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a consent body");
    let consent = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_claim(&consent, &body, TimeRange { start: at, end: at }, at)
        .expect("the consent claim");
    if second_person_unreadable {
        archive_as_cleanup(&vault, &person_b).expect("archive the second person");
    }
    Fixture {
        _dir: dir,
        vault,
        reader,
        person_a,
        person_b,
        consent,
    }
}

#[test]
fn a_consent_claim_is_withheld_from_a_reader_of_one_end_only() {
    let fixture = fixture(true);
    let reads = |row| {
        reader_reads_row(&fixture.vault, fixture.reader, EdgeActorClass::Agent, row)
            .expect("the recorded point read")
    };
    assert!(reads(fixture.person_a));
    assert!(!reads(fixture.person_b));
    assert!(!reads(fixture.consent));
    let listed = reader_claim_rows(&fixture.vault, fixture.reader, EdgeActorClass::Agent)
        .expect("the reader's recorded claim listing");
    assert!(!listed.contains(&fixture.consent));
}

#[test]
fn a_consent_claim_is_served_to_a_reader_of_both_ends() {
    let fixture = fixture(false);
    let reads = |row| {
        reader_reads_row(&fixture.vault, fixture.reader, EdgeActorClass::Agent, row)
            .expect("the recorded point read")
    };
    assert!(reads(fixture.person_a));
    assert!(reads(fixture.person_b));
    assert!(reads(fixture.consent));
    let listed = reader_claim_rows(&fixture.vault, fixture.reader, EdgeActorClass::Agent)
        .expect("the reader's recorded claim listing");
    assert!(listed.contains(&fixture.consent));
}

/// A consent claim whose end is another consent claim naming it back is
/// judged once through the shared worklist, as a status cycle is: the read
/// ends and serves the pair to a reader of every end (green on main, where
/// the consent claim is not walked at all).
#[test]
fn a_consent_claim_cycle_is_judged_once() {
    let fixture = fixture(false);
    let vault = &fixture.vault;
    let first = EntityId::now();
    let second = EntityId::now();
    for (from, to) in [(first, second), (second, first)] {
        let body = ClaimBody::new(
            PREDICATE_COREFERENCE_SHARE_CONSENT,
            ClaimSubject::Edge {
                source: to,
                kind: EdgeKind::SameAs,
                target: fixture.person_a,
            },
            rmpv::Value::Map(vec![(
                rmpv::Value::from(COREFERENCE_SHARE_CONSENT_PACT_KEY),
                rmpv::Value::from("b".repeat(64)),
            )]),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("a consent body");
        let at = vault.now_recorded_at();
        vault
            .put_claim(&from, &body, TimeRange { start: at, end: at }, at)
            .expect("a consent claim naming the other");
    }
    let reads = |row| {
        reader_reads_row(vault, fixture.reader, EdgeActorClass::Agent, row)
            .expect("the recorded point read")
    };
    assert!(reads(first));
    assert!(reads(second));
}
