//! Fable design pass 31, step L-S5 (oracle case 18; FIX
//! [FLOOR-PENDING-NOT-COUNTED-BY-DOCTOR]; FLOOR-OLD-FACT-ERASED-INPUT = A):
//! doctor counts the facts this vault does not read as whole by their
//! verdict, in three counts. A sealed fact is one of "N facts hidden: source
//! unknown". A fact that waits for good on an input deleted before floors
//! were written, itself or through a fact it was learnt from, is one of "N
//! facts whose source was deleted before tagging". Every other fact that
//! waits is one of "N facts waiting for a source to arrive". Before L-S5
//! doctor counted sealed facts only, and a fact that waits was counted
//! nowhere.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test read_lineage_doctor`.
#![cfg(oneiron_test_support)]

use oneiron::deletion::TombstoneReason;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::SafeDeleteReason;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::test_doors::claim_refinement_erase::apply_replayed_tombstone;
use oneiron::test_doors::house_link::{put_claim_made_by, stamp_stated_birth};
use oneiron::test_doors::read_lineage_floor::{floor_waits, forget_floor_state};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

const AT: u64 = 1_769_947_200;

struct Mailbox {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    reader: EntityId,
    row: EntityId,
}

/// A vault holding one mail CONVERSATION bound to a policy read by its
/// owner and by a member: the owner reads every source the vault holds.
fn owners_mailbox() -> Mailbox {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: open the vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let reader = EntityId::now();
    let row = EntityId::now();
    bound_row_read_by(&vault, row, &[owner, reader]).expect("FIXTURE: the owner's mailbox");
    Mailbox {
        _dir: dir,
        vault,
        owner,
        reader,
        row,
    }
}

/// An open CLAIM body about the owner under `predicate`, stated by the user.
fn claim_body(mailbox: &Mailbox, predicate: &str, value: &str) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(mailbox.owner),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: an open CLAIM body");
    body.source = Some(ClaimSource::UserStated);
    body
}

/// A stated birth by the owner naming `inputs` as its evidence.
fn made_by(mailbox: &Mailbox, inputs: &[EntityId]) -> MadeBy {
    MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: mailbox.owner,
            class: MadeByClass::Stated,
            identity: "read_lineage_doctor.fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "0".repeat(64),
        },
        at: AT,
        trigger: None,
    }
}

/// An open CLAIM under `predicate` whose birth names `inputs`, stamped in a
/// local write that judges its links; no edge names them.
fn claim_born_from(mailbox: &Mailbox, inputs: &[EntityId], predicate: &str) -> EntityId {
    let id = EntityId::now();
    put_claim_made_by(
        &mailbox.vault,
        id,
        &claim_body(mailbox, predicate, "learnt"),
        made_by(mailbox, inputs),
    )
    .expect("FIXTURE: the CLAIM and its birth");
    id
}

/// A CLAIM under `predicate` as a vault wrote it before floors were: the
/// CLAIM, then its birth naming `inputs`, stamped with no floor raised.
fn claim_born_before_floors(mailbox: &Mailbox, inputs: &[EntityId], predicate: &str) -> EntityId {
    let id = EntityId::now();
    mailbox
        .vault
        .put_claim(
            &id,
            &claim_body(mailbox, predicate, "held before floors"),
            TimeRange { start: AT, end: AT },
            AT,
        )
        .expect("FIXTURE: the CLAIM");
    stamp_stated_birth(&mailbox.vault, id, made_by(mailbox, inputs))
        .expect("FIXTURE: its birth, with no floor raised");
    id
}

/// The owner deletes `row`.
fn erase(mailbox: &Mailbox, row: EntityId) {
    mailbox
        .vault
        .memory(mailbox.owner, EdgeActorClass::Human)
        .safe_delete(&row.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes the row");
}

/// A housekeeping pass, which runs the floor sweep (and, in a vault written
/// before floors, the migration).
fn housekeeping_pass(mailbox: &Mailbox) {
    mailbox
        .vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("a housekeeping pass runs the floor sweep");
}

/// Doctor's three counts of the facts this vault does not read as whole.
#[derive(Debug, PartialEq, Eq)]
struct Counts {
    hidden_source_unknown: u64,
    source_deleted_before_tagging: u64,
    waiting_for_source: u64,
}

fn counts(mailbox: &Mailbox) -> Counts {
    let doctor = mailbox.vault.doctor().expect("doctor");
    Counts {
        hidden_source_unknown: doctor.facts_hidden_source_unknown,
        source_deleted_before_tagging: doctor.facts_source_deleted_before_tagging,
        waiting_for_source: doctor.facts_waiting_for_source,
    }
}

/// A vault written before floors that holds `fact`, learnt from `input`, a
/// fact learnt from the mailbox's row, which the owner deleted before the
/// migration judged `fact`; the migration has run. Returns `input`, then
/// `fact`.
fn fact_whose_input_was_deleted_before_tagging(mailbox: &Mailbox) -> (EntityId, EntityId) {
    let input = claim_born_before_floors(mailbox, &[mailbox.row], "fact.erased_input");
    let fact = claim_born_before_floors(mailbox, &[input], "fact.held_from_input");
    erase(mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    housekeeping_pass(mailbox);
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact whose input was erased before the migration waits for good",
    );
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "precondition: the owner, who reads every source here, reads a fact that waits for good",
    );
    (input, fact)
}

/// Oracle case 18 (FLOOR-OLD-FACT-ERASED-INPUT = A): a fact held before
/// floors whose birth input was deleted before the migration judged it
/// waits for good, and only the owner reads it. Doctor counts it as a fact
/// whose source was deleted before tagging: not as hidden, and not as
/// waiting for a source to arrive.
#[test]
fn a_fact_whose_input_was_deleted_before_tagging_is_counted_as_such() {
    let mailbox = owners_mailbox();
    let (_, fact) = fact_whose_input_was_deleted_before_tagging(&mailbox);
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.reader]).expect("the reader's read"),
        "the mailbox's reader reads a fact that waits for good",
    );
    assert_eq!(
        counts(&mailbox),
        Counts {
            hidden_source_unknown: 0,
            source_deleted_before_tagging: 1,
            waiting_for_source: 0,
        },
        "doctor counts the fact that waits for good as one whose source was deleted before tagging",
    );
}

/// A fact learnt now from a fact that waits for good waits for good too:
/// the input it waits on never becomes whole. Doctor counts both as facts
/// whose source was deleted before tagging, not the later one as waiting
/// for a source to arrive.
#[test]
fn a_fact_learnt_from_a_fact_waiting_for_good_is_counted_with_it() {
    let mailbox = owners_mailbox();
    let (_, fact) = fact_whose_input_was_deleted_before_tagging(&mailbox);
    let learnt = claim_born_from(&mailbox, &[fact], "fact.learnt_from_old_fact");
    assert!(
        floor_waits(&mailbox.vault, learnt).expect("the floor's state"),
        "precondition: a fact learnt from a fact that waits for good waits",
    );
    assert_eq!(
        counts(&mailbox),
        Counts {
            hidden_source_unknown: 0,
            source_deleted_before_tagging: 2,
            waiting_for_source: 0,
        },
        "doctor counts the fact learnt from a fact that waits for good with it",
    );
}

/// A fact learnt from a row this vault does not hold yet waits for it:
/// doctor counts it as waiting for a source to arrive, and once the row
/// lands bound to its mailbox the fact is whole and leaves every count.
#[test]
fn a_fact_waiting_for_a_row_on_its_way_is_counted_until_the_row_lands() {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let learnt = claim_born_from(&mailbox, &[late], "fact.learnt_from_a_row_on_its_way");
    assert!(
        floor_waits(&mailbox.vault, learnt).expect("the floor's state"),
        "precondition: a fact born from a row not held here waits for it",
    );
    assert_eq!(
        counts(&mailbox),
        Counts {
            hidden_source_unknown: 0,
            source_deleted_before_tagging: 0,
            waiting_for_source: 1,
        },
        "doctor counts the fact as waiting for a source to arrive",
    );
    bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("the row lands, bound to its mailbox");
    assert!(
        !floor_waits(&mailbox.vault, learnt).expect("the floor's state"),
        "precondition: the fact is whole once its source landed",
    );
    assert_eq!(
        counts(&mailbox),
        Counts {
            hidden_source_unknown: 0,
            source_deleted_before_tagging: 0,
            waiting_for_source: 0,
        },
        "doctor still counts a fact whose source landed",
    );
}

/// The lead's ruling A ("if the owner wants such facts gone, the erase of
/// the source does it through the erase path"): a later hard erase of the
/// input a fact waits on for good seals the fact. Doctor then counts it as
/// hidden and no longer as a fact whose source was deleted before tagging.
#[test]
fn a_hard_erase_of_an_input_deleted_before_tagging_moves_its_fact_to_the_hidden_count() {
    let mailbox = owners_mailbox();
    let (input, fact) = fact_whose_input_was_deleted_before_tagging(&mailbox);
    apply_replayed_tombstone(&mailbox.vault, &input, TombstoneReason::UserHardDelete, AT)
        .expect("a peer's hard tombstone of the deleted input replays");
    housekeeping_pass(&mailbox);
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "precondition: the hard erase of its input sealed the fact that waited on it for good",
    );
    assert_eq!(
        counts(&mailbox),
        Counts {
            hidden_source_unknown: 1,
            source_deleted_before_tagging: 0,
            waiting_for_source: 0,
        },
        "doctor counts the sealed fact as hidden, and nothing else",
    );
}
