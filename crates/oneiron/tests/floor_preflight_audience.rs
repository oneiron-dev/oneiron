//! FIX [FLOOR-PREFLIGHT-AUDIENCE-IGNORES-WAIT]: a row whose floor waits
//! (READ-LINEAGE L1) reads only to an owner who reads every source policy
//! the vault holds, so `vault.policy.preflight` names every one of them as
//! the audience of the owner's read of it, the policies its floor names
//! once whole among them. Before the fix the preflight named only the
//! policies along the row's word lineage, which reaches no birth input:
//! none for a fact learnt from a mailbox's row.
//!
//! Fable design pass 31, oracle case 23 (step L-S5): the preflight answers
//! by the row's verdict. A fact that waits, for good on an input deleted
//! before floors were written as for a row on its way, names every source
//! policy; a sealed fact reads to no one, the owner included, so the
//! preflight withholds it.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test floor_preflight_audience`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::{Memory, SafeDeleteReason};
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::snapshot_read::{PolicyPreflightAct, PolicyPreflightRef, PolicyPreflightRequest};
use oneiron::test_doors::house_link::{put_claim_made_by, stamp_stated_birth};
use oneiron::test_doors::read_lineage_floor::{floor_of, floor_waits, forget_floor_state};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

const AT: u64 = 1_769_947_200;

/// A vault holding two mail CONVERSATIONs: `row`, bound to `policy`, read
/// by the owner and by a member, and another bound to `other_policy`, read
/// by the owner alone. The owner reads every source the vault holds.
struct Mailboxes {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    row: EntityId,
    policy: EntityId,
    other_policy: EntityId,
}

fn mailboxes() -> Mailboxes {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: open the vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let row = EntityId::now();
    let policy = bound_row_read_by(&vault, row, &[owner, EntityId::now()])
        .expect("FIXTURE: a mailbox read by the owner and a member");
    let other_policy = bound_row_read_by(&vault, EntityId::now(), &[owner])
        .expect("FIXTURE: a mailbox read by the owner alone");
    Mailboxes {
        _dir: dir,
        vault,
        owner,
        row,
        policy,
        other_policy,
    }
}

/// An open CLAIM body about the owner under `predicate`, stated by the user.
fn claim_body(mailboxes: &Mailboxes, predicate: &str, value: &str) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(mailboxes.owner),
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
fn made_by(mailboxes: &Mailboxes, inputs: &[EntityId]) -> MadeBy {
    MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: mailboxes.owner,
            class: MadeByClass::Stated,
            identity: "floor_preflight_audience.fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "0".repeat(64),
        },
        at: AT,
        trigger: None,
    }
}

/// An open CLAIM whose birth names `inputs`, stamped in a local write that
/// raises its floor; no edge names them.
fn claim_born_from(mailboxes: &Mailboxes, inputs: &[EntityId], predicate: &str) -> EntityId {
    let id = EntityId::now();
    put_claim_made_by(
        &mailboxes.vault,
        id,
        &claim_body(mailboxes, predicate, "learnt"),
        made_by(mailboxes, inputs),
    )
    .expect("FIXTURE: the CLAIM and its birth");
    id
}

/// A CLAIM as a vault wrote it before floors were: the CLAIM, then its
/// birth naming `inputs`, stamped with no floor raised.
fn claim_born_before_floors(
    mailboxes: &Mailboxes,
    inputs: &[EntityId],
    predicate: &str,
) -> EntityId {
    let id = EntityId::now();
    mailboxes
        .vault
        .put_claim(
            &id,
            &claim_body(mailboxes, predicate, "held before floors"),
            TimeRange { start: AT, end: AT },
            AT,
        )
        .expect("FIXTURE: the CLAIM");
    stamp_stated_birth(&mailboxes.vault, id, made_by(mailboxes, inputs))
        .expect("FIXTURE: its birth, with no floor raised");
    id
}

/// What `vault.policy.preflight` answers for the owner's read of `row`.
fn owners_preflight(mailboxes: &Mailboxes, row: EntityId) -> Vec<PolicyPreflightRef> {
    let memory: Memory<'_> = mailboxes
        .vault
        .memory(mailboxes.owner, EdgeActorClass::Human);
    oneiron::verbs::vault_policy_preflight(
        &memory,
        PolicyPreflightRequest {
            refs: vec![row],
            act: PolicyPreflightAct::Read,
        },
    )
    .expect("the owner's preflight")
    .value
    .refs
}

/// The audience `vault.policy.preflight` names for the owner's read of
/// `row`, which the owner reads.
fn owners_preflight_audience(mailboxes: &Mailboxes, row: EntityId) -> BTreeSet<EntityId> {
    match owners_preflight(mailboxes, row).as_slice() {
        [
            PolicyPreflightRef::Readable {
                entity, audience, ..
            },
        ] if *entity == row => audience.iter().copied().collect(),
        refs => panic!("the owner reads the row; the preflight answered {refs:?}"),
    }
}

/// A fact the vault held before floors, learnt from a mailbox's row: the
/// backfill has not raised it, so its floor waits and only the owner, who
/// reads every source here, reads it. The owner's preflight names every
/// source policy the vault holds, so it names the mailbox's policy, which
/// the floor names once the backfill raised it; then it names the floor.
#[test]
fn a_fact_held_before_floors_names_every_source_while_its_floor_waits() {
    let mailboxes = mailboxes();
    let fact = claim_born_before_floors(&mailboxes, &[mailboxes.row], "fact.held_before_floors");
    forget_floor_state(&mailboxes.vault).expect("FIXTURE: a vault written before floors");
    assert!(
        floor_waits(&mailboxes.vault, fact).expect("the floor's state"),
        "precondition: a fact the backfill has not raised waits",
    );
    assert!(
        reads(&mailboxes.vault, fact, &[mailboxes.owner]).expect("the owner's read"),
        "precondition: the owner, who reads every source here, reads the waiting fact",
    );
    let waiting = owners_preflight_audience(&mailboxes, fact);
    assert_eq!(
        waiting,
        BTreeSet::from([mailboxes.policy, mailboxes.other_policy]),
        "the preflight of a fact whose floor waits names every source policy the owner's read met",
    );

    mailboxes
        .vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("a housekeeping pass runs the floor backfill");
    assert!(
        !floor_waits(&mailboxes.vault, fact).expect("the floor's state"),
        "the backfill raised the fact",
    );
    let floor = floor_of(&mailboxes.vault, fact).expect("the floor");
    assert!(
        floor.contains(&mailboxes.policy),
        "the raised fact holds its mailbox's policy",
    );
    assert!(
        floor.is_subset(&waiting),
        "the waiting preflight {waiting:?} named every source of the whole floor {floor:?}",
    );
    assert_eq!(
        owners_preflight_audience(&mailboxes, fact),
        BTreeSet::from([mailboxes.policy]),
        "once the floor is whole the preflight names the policies the floor names",
    );
}

/// A fact learnt from a row not yet here waits for it, and only the owner
/// reads it. The owner's preflight names every source policy the vault
/// holds while it waits; once the row lands bound to its mailbox, it names
/// that mailbox's policy, which the floor now holds.
#[test]
fn a_fact_born_from_a_row_not_yet_here_names_every_source_while_it_waits() {
    let mailboxes = mailboxes();
    let late = EntityId::now();
    let fact = claim_born_from(&mailboxes, &[late], "fact.learnt_from_a_late_row");
    assert!(
        floor_waits(&mailboxes.vault, fact).expect("the floor's state"),
        "precondition: a fact born from a row not held here waits for it",
    );
    assert!(
        reads(&mailboxes.vault, fact, &[mailboxes.owner]).expect("the owner's read"),
        "precondition: the owner, who reads every source here, reads the waiting fact",
    );
    assert_eq!(
        owners_preflight_audience(&mailboxes, fact),
        BTreeSet::from([mailboxes.policy, mailboxes.other_policy]),
        "the preflight of a fact whose floor waits names every source policy the owner's read met",
    );

    let landed = bound_row_read_by(&mailboxes.vault, late, &[mailboxes.owner])
        .expect("the row lands, bound to its mailbox");
    assert!(
        !floor_waits(&mailboxes.vault, fact).expect("the floor's state"),
        "the fact's floor is whole once its source landed",
    );
    let audience = owners_preflight_audience(&mailboxes, fact);
    assert!(
        audience.contains(&landed),
        "once the row landed the preflight names its mailbox's policy: {audience:?}",
    );
    assert!(
        !audience.contains(&mailboxes.other_policy),
        "a whole floor's preflight names no policy its lineage misses: {audience:?}",
    );
}

/// The owner deletes `row`.
fn erase(mailboxes: &Mailboxes, row: EntityId) {
    mailboxes
        .vault
        .memory(mailboxes.owner, EdgeActorClass::Human)
        .safe_delete(&row.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes the row");
}

/// Case 23 for a fact that waits for good (FLOOR-OLD-FACT-ERASED-INPUT =
/// A): a fact held before floors whose birth input the owner deleted before
/// the migration judged it reads only to the owner, who reads every source
/// here, so the owner's preflight names every source policy the vault holds.
#[test]
fn a_fact_waiting_for_good_on_an_input_deleted_before_tagging_names_every_source() {
    let mailboxes = mailboxes();
    let input = claim_born_before_floors(&mailboxes, &[mailboxes.row], "fact.erased_input");
    let fact = claim_born_before_floors(&mailboxes, &[input], "fact.held_from_input");
    erase(&mailboxes, input);
    forget_floor_state(&mailboxes.vault).expect("FIXTURE: a vault written before floors");
    mailboxes
        .vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("the migration judges the fact");
    assert!(
        floor_waits(&mailboxes.vault, fact).expect("the floor's state"),
        "precondition: a fact whose input was erased before the migration waits for good",
    );
    assert!(
        reads(&mailboxes.vault, fact, &[mailboxes.owner]).expect("the owner's read"),
        "precondition: the owner reads a fact that waits for good",
    );
    assert_eq!(
        owners_preflight_audience(&mailboxes, fact),
        BTreeSet::from([mailboxes.policy, mailboxes.other_policy]),
        "the preflight of a fact that waits for good names every source policy the owner's read met",
    );
}

/// Case 23 for a sealed fact (READ-LINEAGE-L3 = A): a fact learnt from a
/// row the owner deleted first is sealed at its birth and reads to no one,
/// the owner included, so the owner's preflight withholds it and names no
/// audience.
#[test]
fn a_sealed_fact_is_withheld_from_the_owners_preflight() {
    let mailboxes = mailboxes();
    let middle = claim_born_from(&mailboxes, &[mailboxes.row], "fact.middle");
    erase(&mailboxes, middle);
    let sealed = claim_born_from(&mailboxes, &[middle], "fact.learnt_from_an_erased_row");
    assert!(
        !reads(&mailboxes.vault, sealed, &[mailboxes.owner]).expect("the owner's read"),
        "precondition: a fact born from an erased row reads to no one",
    );
    match owners_preflight(&mailboxes, sealed).as_slice() {
        [PolicyPreflightRef::Withheld { entity }] if *entity == sealed => {}
        refs => panic!("the owner's preflight of a sealed fact answered {refs:?}"),
    }
}
