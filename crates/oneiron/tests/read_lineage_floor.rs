//! READ-LINEAGE step L1 (Fable design pass 30, section 4; FIX
//! [VOICE-PHONE-DERIVED-ROW-GENERIC-READ], mail half): a row written from a
//! mailbox's rows carries that mailbox's source on its floor, written in the
//! write that gives it its words, so it reads only to the mailbox's readers
//! however it names them: by an edge, or only by its birth's inputs. A floor
//! holds every policy the source-audience walk meets. A floor that names a
//! source this vault cannot read hides its row, and doctor counts it.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test read_lineage_floor`.
#![cfg(oneiron_test_support)]

use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::SafeDeleteReason;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::house_link::{put_claim_made_by, stamp_stated_birth};
use oneiron::test_doors::read_lineage_floor::{
    floor_of, floor_waits, forget_floor_state, travels_restricted, walked_policies_of,
};
use oneiron::test_doors::source_audience_binding::{
    bound_row, bound_row_read_by, reads, remove_policy_row,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig,
};

#[path = "read_lineage_floor/archived_rows.rs"]
mod archived_rows;
#[path = "read_lineage_floor/erased_sources.rs"]
mod erased_sources;
#[path = "read_lineage_floor/source_states.rs"]
mod source_states;

const AT: u64 = 1_769_947_200;

struct Mailbox {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    reader: EntityId,
    stranger: EntityId,
    row: EntityId,
    policy: EntityId,
}

/// A vault holding one mail CONVERSATION bound to a policy read by `reader`
/// alone.
fn mailbox() -> Mailbox {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: open the vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let reader = EntityId::now();
    let (row, policy) = bound_row(&vault, reader).expect("FIXTURE: a mailbox's bound row");
    Mailbox {
        _dir: dir,
        vault,
        owner,
        reader,
        stranger: EntityId::now(),
        row,
        policy,
    }
}

/// A vault holding one mail CONVERSATION bound to a policy read by its
/// owner and by `reader`: the owner reads every source the vault holds.
fn owners_mailbox() -> Mailbox {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: open the vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let reader = EntityId::now();
    let row = EntityId::now();
    let policy =
        bound_row_read_by(&vault, row, &[owner, reader]).expect("FIXTURE: the owner's mailbox");
    Mailbox {
        _dir: dir,
        vault,
        owner,
        reader,
        stranger: EntityId::now(),
        row,
        policy,
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

/// A stated birth by the owner naming `inputs` as `role`.
fn made_by(mailbox: &Mailbox, inputs: &[EntityId], role: MadeByInputRole) -> MadeBy {
    MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput { row: *row, role })
            .collect(),
        process: MadeByProcess {
            actor: mailbox.owner,
            class: MadeByClass::Stated,
            identity: "read_lineage_floor.fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "0".repeat(64),
        },
        at: AT,
        trigger: None,
    }
}

/// An open CLAIM about the owner whose birth names `inputs` as its
/// evidence (`Input`), stamped in a local write; no edge names them.
fn claim_born_from(mailbox: &Mailbox, inputs: &[EntityId], value: &str) -> EntityId {
    claim_born_with(mailbox, inputs, MadeByInputRole::Input, value)
}

/// [`claim_born_from`], naming `inputs` in the birth as `role`.
fn claim_born_with(
    mailbox: &Mailbox,
    inputs: &[EntityId],
    role: MadeByInputRole,
    value: &str,
) -> EntityId {
    claim_of_predicate_born_with(mailbox, inputs, role, "profile.preference", value)
}

/// [`claim_born_with`] under `predicate`, so CLAIMs of distinct predicates
/// never supersede one another.
fn claim_of_predicate_born_with(
    mailbox: &Mailbox,
    inputs: &[EntityId],
    role: MadeByInputRole,
    predicate: &str,
    value: &str,
) -> EntityId {
    let id = EntityId::now();
    put_claim_made_by(
        &mailbox.vault,
        id,
        &claim_body(mailbox, predicate, value),
        made_by(mailbox, inputs, role),
    )
    .expect("FIXTURE: the CLAIM and its birth");
    id
}

/// A CLAIM under `predicate` as a vault wrote it before floors were: the
/// CLAIM, then its birth naming `inputs`, stamped with no floor raised. Its
/// floor stays empty; [`forget_floor_state`] then makes the vault read as
/// one written before floors.
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
    stamp_stated_birth(
        &mailbox.vault,
        id,
        made_by(mailbox, inputs, MadeByInputRole::Input),
    )
    .expect("FIXTURE: its birth, with no floor raised");
    id
}

/// How many of `rows` `viewer` reads.
fn read_count(mailbox: &Mailbox, rows: &[EntityId], viewer: EntityId) -> usize {
    rows.iter()
        .filter(|row| reads(&mailbox.vault, **row, &[viewer]).expect("the read"))
        .count()
}

/// The mail half of the held row: a CLAIM whose birth alone names a
/// mailbox's row reads only to that mailbox's readers. Before L1 the walk
/// read no birth input, so a stranger read it.
#[test]
fn a_claim_born_from_a_mailbox_row_reads_only_to_the_mailboxs_readers() {
    let mailbox = mailbox();
    let learnt = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    let control = claim_born_from(&mailbox, &[], "stated with no evidence");
    assert!(
        reads(&mailbox.vault, control, &[mailbox.stranger]).expect("the stranger reads control"),
        "precondition: a CLAIM with no source reads to anyone the walk asks",
    );
    assert!(
        reads(&mailbox.vault, learnt, &[mailbox.reader]).expect("the reader reads the CLAIM"),
        "the mailbox's reader reads a CLAIM learnt from it",
    );
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.stranger]).expect("the stranger reads it"),
        "LEAK: a stranger reads a CLAIM whose birth names a mailbox's row",
    );
}

/// The measured case (OPUS-LINEAGE-MEASURE set C3, 21 Nov 04:22): under the
/// walk alone, a reader named by no policy read every one of 5,000 CLAIMs
/// born from a mailbox's rows by their birth's inputs alone. With the floor
/// it reads none of them, and the mailbox's reader reads every one.
#[test]
fn a_reader_named_by_no_policy_reads_none_of_the_claims_learnt_from_a_mailbox() {
    let mailbox = mailbox();
    let learnt: Vec<EntityId> = (0..50)
        .map(|n| {
            claim_of_predicate_born_with(
                &mailbox,
                &[mailbox.row],
                MadeByInputRole::Input,
                &format!("fact.mailbox_n{n}"),
                "learnt from the mailbox",
            )
        })
        .collect();
    let read_by = |viewer: EntityId| {
        learnt
            .iter()
            .filter(|claim| reads(&mailbox.vault, **claim, &[viewer]).expect("the walk reads"))
            .count()
    };
    assert_eq!(
        read_by(mailbox.stranger),
        0,
        "LEAK: a reader named by no policy reads CLAIMs learnt from the mailbox",
    );
    assert_eq!(
        read_by(mailbox.reader),
        learnt.len(),
        "the mailbox's reader reads every CLAIM learnt from it",
    );
}

/// #9289 review r1 P1: an erase takes a row's stored floor with its row, so
/// a row born from it after the erase has no source left to inherit. The
/// CLAIM `middle`, learnt from the mailbox's row, holds the mailbox's policy
/// on its floor; the owner deletes it; a CLAIM whose prompt then names
/// `middle` is born sealed (READ-LINEAGE-L3 = A) and reads to no one, the
/// mailbox's reader included. A CLAIM born from `middle` while it stood
/// keeps the mailbox's policy after the delete: only the birth's own write
/// seals.
#[test]
fn a_claim_born_from_an_erased_row_is_sealed() {
    let mailbox = mailbox();
    let middle = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    let before = claim_born_from(&mailbox, &[middle], "learnt while middle stood");
    mailbox
        .vault
        .memory(mailbox.owner, EdgeActorClass::Human)
        .safe_delete(&middle.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes the CLAIM middle");
    let after = claim_born_with(
        &mailbox,
        &[middle],
        MadeByInputRole::Prompt,
        "learnt from middle after its delete",
    );
    assert!(
        reads(&mailbox.vault, before, &[mailbox.reader]).expect("the reader reads before"),
        "a CLAIM born while middle stood keeps the mailbox's policy after the delete",
    );
    assert!(
        !reads(&mailbox.vault, before, &[mailbox.stranger]).expect("the stranger reads before"),
        "LEAK: a stranger reads a CLAIM born from middle while it stood",
    );
    for (who, label) in [
        (mailbox.stranger, "a stranger"),
        (mailbox.reader, "the mailbox's reader"),
    ] {
        assert!(
            !reads(&mailbox.vault, after, &[who]).expect("the read of after"),
            "{label} reads a CLAIM born from the deleted middle: it is not sealed, though \
             nothing here says any more whose words middle held",
        );
    }
}

/// A row written from that CLAIM by an edge carries the CLAIM's floor in
/// turn (one level per write; the source row already holds its own), and
/// each floor holds every policy the walk meets on a read of its row.
#[test]
fn a_floor_holds_every_policy_the_walk_meets() {
    let mailbox = mailbox();
    let learnt = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    let derived = claim_born_from(&mailbox, &[], "derived from the learnt fact");
    mailbox
        .vault
        .put_edge(&derived, EdgeKind::DerivedFrom, &learnt, 1.0)
        .expect("FIXTURE: the derived row names its source");
    let twice = claim_born_from(&mailbox, &[derived], "born from the derived row");
    for (row, label) in [
        (mailbox.row, "the bound row"),
        (learnt, "the CLAIM born from it"),
        (derived, "the row DerivedFrom that CLAIM"),
        (twice, "the CLAIM born from that row"),
    ] {
        let floor = floor_of(&mailbox.vault, row).expect("the floor");
        assert!(
            floor.contains(&mailbox.policy),
            "{label}'s floor names the mailbox's policy",
        );
        let walked = walked_policies_of(&mailbox.vault, row, &[mailbox.reader]).expect("the walk");
        assert!(
            walked.is_subset(&floor),
            "{label}'s floor {floor:?} holds every policy the walk meets {walked:?}",
        );
        assert!(
            !reads(&mailbox.vault, row, &[mailbox.stranger]).expect("the stranger's read"),
            "LEAK: a stranger reads {label}",
        );
    }
}

/// READ-LINEAGE-L3 = A, design section 4.7: a CLAIM whose floor names a
/// source this vault can no longer read reads to no one, and doctor counts
/// it as "N facts hidden: source unknown", naming nothing else.
#[test]
fn doctor_counts_the_facts_a_source_unknown_hides() {
    let mailbox = mailbox();
    let learnt = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    assert_eq!(
        mailbox
            .vault
            .doctor()
            .expect("doctor")
            .facts_hidden_source_unknown,
        0,
        "precondition: every source on every floor resolves",
    );
    remove_policy_row(&mailbox.vault, mailbox.policy).expect("FIXTURE: remove the policy row");
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.reader]).expect("the former reader's read"),
        "a CLAIM whose source no longer resolves reads to no one",
    );
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.owner]).expect("the owner's read"),
        "the owner does not read a CLAIM whose source no longer resolves",
    );
    assert_eq!(
        mailbox
            .vault
            .doctor()
            .expect("doctor")
            .facts_hidden_source_unknown,
        1,
        "doctor counts the one CLAIM its unknown source hides",
    );
}

/// READ-LINEAGE L1-B (design pass 30, section 4.7): a sealed CLAIM a later
/// CLAIM closed is history, so doctor no longer counts it as a fact hidden,
/// though it still reads to no one. Before L1-B every stored floor naming an
/// unknown source counted, so the count never fell.
#[test]
fn a_superseded_sealed_claim_leaves_the_doctor_count() {
    let mailbox = mailbox();
    let middle = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    mailbox
        .vault
        .memory(mailbox.owner, EdgeActorClass::Human)
        .safe_delete(&middle.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes the CLAIM middle");
    let sealed = claim_born_with(&mailbox, &[middle], MadeByInputRole::Prompt, "the fact");
    let restated = claim_born_from(&mailbox, &[mailbox.row], "the fact");
    let hidden = |vault: &Vault| vault.doctor().expect("doctor").facts_hidden_source_unknown;
    assert_eq!(
        hidden(&mailbox.vault),
        1,
        "precondition: doctor counts the sealed CLAIM",
    );
    let owner = mailbox
        .vault
        .authenticate_owner(
            mailbox.owner,
            &mailbox.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("FIXTURE: the owner's proof");
    mailbox
        .vault
        .supersede_claim_as_owner(&owner, &restated, &sealed, mailbox.vault.now_recorded_at())
        .expect("the owner closes the sealed CLAIM by its restatement");
    assert!(
        !reads(&mailbox.vault, sealed, &[mailbox.reader]).expect("the reader's read"),
        "a closed sealed CLAIM still reads to no one",
    );
    assert_eq!(
        hidden(&mailbox.vault),
        0,
        "doctor counts a sealed CLAIM a later CLAIM closed as a fact hidden",
    );
}

/// #9289 review 2 P1-1 (the order a sync can land rows in): a CLAIM born
/// from a row this vault does not hold yet waits for it, never sealed. While
/// the row is missing the CLAIM reads to no one but the owner, who reads
/// every source here; once the row lands bound to its mailbox, the CLAIM
/// holds that mailbox's policy and reads to its readers, and to no stranger.
#[test]
fn a_claim_born_from_a_row_not_yet_here_reads_once_the_row_lands() {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let learnt = claim_born_from(&mailbox, &[late], "learnt from a row still on its way");
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads a CLAIM whose source has not landed",
    );
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.reader]).expect("the reader's read"),
        "a reader reads a CLAIM whose source has not landed",
    );
    assert!(
        reads(&mailbox.vault, learnt, &[mailbox.owner]).expect("the owner's read"),
        "the owner, who reads every source here, reads a CLAIM whose source has not landed",
    );
    assert!(
        floor_waits(&mailbox.vault, learnt).expect("the floor's state"),
        "a CLAIM born from a row not held here waits for it",
    );
    assert_eq!(
        mailbox
            .vault
            .doctor()
            .expect("doctor")
            .facts_hidden_source_unknown,
        0,
        "a CLAIM waiting for its source is not sealed",
    );
    let policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("the row lands, bound to its mailbox");
    assert!(
        !floor_waits(&mailbox.vault, learnt).expect("the floor's state"),
        "the CLAIM's floor is whole once its source landed",
    );
    assert!(
        floor_of(&mailbox.vault, learnt)
            .expect("the floor")
            .contains(&policy),
        "the CLAIM holds the landed row's policy",
    );
    assert!(
        reads(&mailbox.vault, learnt, &[mailbox.reader]).expect("the reader's read"),
        "the mailbox's reader reads the CLAIM once its source landed: it was never sealed",
    );
    assert!(
        reads(&mailbox.vault, learnt, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads the CLAIM throughout",
    );
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads the CLAIM once its source landed",
    );
}

/// #9289 review 2 P1-2 (Fable design pass 31, case 2): facts a vault held
/// before floors were written (a CLAIM whose birth names a mailbox's row,
/// with no floor) read to no stranger the moment the vault runs this build.
/// A read judges a fact the migration has not reached one level, so the
/// mailbox's reader reads them at once, and once the migration (a
/// housekeeping sweep) has judged them each holds the mailbox's policy; the
/// owner reads them throughout.
#[test]
fn facts_held_before_floors_read_only_to_the_mailboxs_readers_before_and_after_the_migration() {
    const N: usize = 5;
    let mailbox = owners_mailbox();
    let facts: Vec<EntityId> = (0..N)
        .map(|n| claim_born_before_floors(&mailbox, &[mailbox.row], &format!("fact.held_n{n}")))
        .collect();
    assert_eq!(
        read_count(&mailbox, &facts, mailbox.stranger),
        N,
        "precondition: a fact whose floor was never raised reads to a stranger as before floors",
    );
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    assert_eq!(
        read_count(&mailbox, &facts, mailbox.stranger),
        0,
        "LEAK: a stranger reads facts held before floors before the backfill ran",
    );
    assert_eq!(
        read_count(&mailbox, &facts, mailbox.reader),
        N,
        "the mailbox's reader does not read facts the migration has not judged yet",
    );
    assert_eq!(
        read_count(&mailbox, &facts, mailbox.owner),
        N,
        "the owner reads every fact before the backfill",
    );
    mailbox
        .vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("a housekeeping pass runs the floor backfill");
    for fact in &facts {
        assert!(
            !floor_waits(&mailbox.vault, *fact).expect("the floor's state"),
            "the backfill raised every fact",
        );
        assert!(
            floor_of(&mailbox.vault, *fact)
                .expect("the floor")
                .contains(&mailbox.policy),
            "a raised fact holds its mailbox's policy",
        );
    }
    assert_eq!(
        read_count(&mailbox, &facts, mailbox.stranger),
        0,
        "LEAK: a stranger reads facts after the backfill",
    );
    assert_eq!(
        read_count(&mailbox, &facts, mailbox.reader),
        N,
        "the mailbox's reader reads every fact after the backfill",
    );
    assert_eq!(
        read_count(&mailbox, &facts, mailbox.owner),
        N,
        "the owner reads every fact after the backfill",
    );
}

/// #9289 review 2 P1-2, a fact born from a fact held before floors: its
/// write raises the old fact's floor first, so the new fact holds the
/// mailbox's policy at once, before any backfill ran.
#[test]
fn a_fact_born_from_a_fact_held_before_floors_holds_its_floor_at_once() {
    let mailbox = owners_mailbox();
    let old = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.held_old");
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    let new = claim_born_from(&mailbox, &[old], "learnt from the old fact");
    for (row, label) in [(old, "the old fact"), (new, "the fact born from it")] {
        assert!(
            !floor_waits(&mailbox.vault, row).expect("the floor's state"),
            "{label}'s floor is whole",
        );
        assert!(
            floor_of(&mailbox.vault, row)
                .expect("the floor")
                .contains(&mailbox.policy),
            "{label} holds the mailbox's policy",
        );
        assert!(
            reads(&mailbox.vault, row, &[mailbox.reader]).expect("the reader's read"),
            "the mailbox's reader reads {label}",
        );
        assert!(
            !reads(&mailbox.vault, row, &[mailbox.stranger]).expect("the stranger's read"),
            "LEAK: a stranger reads {label}",
        );
    }
}

/// READ-LINEAGE-L3 as the lead reads it (21 Nov 06:28): the vault owner
/// reads the sources that are his, never a member's own mailbox, whose
/// audience is that member. A fact learnt from it reads to the member and
/// not to the owner, whether its floor is whole or waits.
#[test]
fn a_members_own_mailbox_fact_does_not_read_to_the_vault_owner() {
    let mailbox = mailbox();
    let member = mailbox.reader;
    let fact = claim_born_from(&mailbox, &[mailbox.row], "learnt from the member's mailbox");
    assert!(
        reads(&mailbox.vault, fact, &[member]).expect("the member's read"),
        "the member reads a fact learnt from the member's own mailbox",
    );
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the vault owner reads a fact learnt from a member's own mailbox",
    );
    let held = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.held_member");
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    assert!(
        !reads(&mailbox.vault, held, &[mailbox.owner]).expect("the owner's read"),
        "the vault owner reads a fact held before floors in a vault holding a member's own mailbox",
    );
    assert!(
        floor_waits(&mailbox.vault, held).expect("the floor's state"),
        "the fact's floor waits for the backfill",
    );
}

/// #9289 review 3 P1-3: a CLAIM whose floor waits does not travel on a
/// restricted lane, which carries no audience: its source may land later
/// bound to a mailbox the lane's vault never sees.
#[test]
fn a_claim_waiting_for_its_source_does_not_travel_on_a_restricted_lane() {
    let mailbox = owners_mailbox();
    let control = claim_born_from(&mailbox, &[], "stated with no evidence");
    assert!(
        travels_restricted(&mailbox.vault, control).expect("control's travel"),
        "precondition: a CLAIM with no source travels on a restricted lane",
    );
    let learnt = claim_born_from(&mailbox, &[EntityId::now()], "learnt from a row on its way");
    assert!(
        floor_waits(&mailbox.vault, learnt).expect("the floor's state"),
        "precondition: a CLAIM born from a row not held here waits for it",
    );
    assert!(
        !travels_restricted(&mailbox.vault, learnt).expect("the waiting CLAIM's travel"),
        "LEAK: a CLAIM whose floor waits travels on a restricted lane",
    );
}
