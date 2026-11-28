//! #9289 Opus review 3: a source a floor waits on that is then erased. What
//! it would have added to the floor can no longer be known here, so the
//! floor never settles without it: the erase seals the rows that waited on
//! it (P1-A), no later landing frees them (P1-B), and a row that arrives
//! born from an input this vault erased is sealed as a local birth is
//! (P2-4). A fact whose input was erased before the floor backfill raised it
//! waits for good (FLOOR-OLD-FACT-ERASED-INPUT = A).
//!
//! #10108 reviews (Sol round 1; Opus): a peer's tombstone of a row never
//! held here seals what waits for that row, whichever comes first; a row
//! that settled without a source it once waited on is not sealed by that
//! source's erase; a soft tombstone replayed over a soft delete applied here
//! leaves a fact that waits for good on it waiting, and an erase of that
//! input seals it; and a row whose delete is published but not purged keeps
//! what waits on it waiting until the purge seals it.

use oneiron::deletion::TombstoneReason;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::SafeDeleteReason;
use oneiron::provenance::made_by::MadeByInputRole;
use oneiron::test_doors::claim_refinement_erase::apply_replayed_tombstone;
use oneiron::test_doors::coach::fence_row_for_hard_delete;
use oneiron::test_doors::read_lineage_floor::{
    binding_lands, floor_sealed, floor_waits, forget_floor_state,
};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};
use oneiron::{EdgeActorClass, EdgeKind, EntityId};

use super::{Mailbox, claim_born_before_floors, claim_born_from, owners_mailbox};

/// The owner deletes `row`.
pub(super) fn erase(mailbox: &Mailbox, row: EntityId) {
    mailbox
        .vault
        .memory(mailbox.owner, EdgeActorClass::Human)
        .safe_delete(&row.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes the row");
}

/// A peer's tombstone of `row` with `reason` replays here, as a sync pass
/// applies it.
fn replay(mailbox: &Mailbox, row: EntityId, reason: TombstoneReason) {
    apply_replayed_tombstone(&mailbox.vault, &row, reason, super::AT)
        .expect("the peer's tombstone replays");
}

/// A housekeeping pass, which runs the floor sweep.
pub(super) fn housekeeping_pass(mailbox: &Mailbox) {
    mailbox
        .vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("a housekeeping pass runs the floor sweep");
}

/// How many facts doctor counts as hidden by a source it cannot name.
pub(super) fn hidden_source_unknown(mailbox: &Mailbox) -> u64 {
    mailbox
        .vault
        .doctor()
        .expect("doctor")
        .facts_hidden_source_unknown
}

/// `row` reads to neither a stranger nor the mailbox's reader (`when`
/// names the moment).
pub(super) fn assert_no_stranger_or_reader_reads(mailbox: &Mailbox, row: EntityId, when: &str) {
    assert!(
        !reads(&mailbox.vault, row, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads the row {when}",
    );
    assert!(
        !reads(&mailbox.vault, row, &[mailbox.reader]).expect("the reader's read"),
        "the mailbox's reader reads the row {when}, though its floor never held the source",
    );
}

/// P1-A: a row that waits on a source the owner then erases is sealed by
/// that erase. It reads to no one, the owner included (READ-LINEAGE-L3 = A),
/// at once and after the next housekeeping pass, which settles it sealed;
/// doctor counts it. Before the fix the pass settled it with an empty floor,
/// and a stranger read it.
#[test]
fn a_row_whose_awaited_source_was_erased_is_sealed() {
    let mailbox = owners_mailbox();
    let middle = claim_born_from(&mailbox, &[EntityId::now()], "learnt from a row on its way");
    let derived = claim_born_from(&mailbox, &[], "derived from middle");
    mailbox
        .vault
        .put_edge(&derived, EdgeKind::DerivedFrom, &middle, 1.0)
        .expect("FIXTURE: the derived row names middle");
    assert!(
        floor_waits(&mailbox.vault, derived).expect("the floor's state"),
        "precondition: a row written from a waiting row waits too",
    );
    erase(&mailbox, middle);
    assert_no_stranger_or_reader_reads(&mailbox, derived, "right after middle's erase");
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, derived, "after a housekeeping pass");
    assert!(
        !reads(&mailbox.vault, derived, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads a row sealed by the erase of a source it waited on",
    );
    assert!(
        !floor_waits(&mailbox.vault, derived).expect("the floor's state"),
        "STUCK: a row sealed by the erase of its awaited source still waits after a pass",
    );
    assert_eq!(
        hidden_source_unknown(&mailbox),
        1,
        "doctor counts the row the erase sealed",
    );
}

/// P1-B, the waiter walk: `fact` waits on `middle`, which waits on `late`, a
/// row not here yet. The owner erases `middle`, which seals `fact`; then
/// `late` lands bound to the mailbox. Its landing raises what waited on it,
/// and must not walk on through the erased `middle` to free `fact`, whose
/// floor never held what `middle` would have added.
#[test]
fn a_row_sealed_by_an_erased_awaited_row_stays_sealed_when_that_rows_source_lands() {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let middle = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[middle], "learnt from middle");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact born from a waiting row waits too",
    );
    erase(&mailbox, middle);
    bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("late lands, bound to its mailbox");
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once middle's own source landed");
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after a housekeeping pass");
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads a row sealed by the erase of a source it waited on",
    );
}

/// P1-B, a binding that lands (FLOOR-OLD-FACT-ERASED-INPUT = A): a fact held
/// before floors whose birth input was erased before the backfill raised it
/// waits for good. When the binding of that input lands (as a replicated
/// binding does), nothing frees it: no stranger and no reader of the mailbox
/// reads it, and the owner, who reads every source here, reads it as before.
#[test]
fn a_fact_waiting_for_good_on_an_erased_input_stays_waiting_when_its_binding_lands() {
    let mailbox = owners_mailbox();
    let input = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.erased_input");
    let fact = claim_born_before_floors(&mailbox, &[input], "fact.held_from_input");
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    housekeeping_pass(&mailbox);
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact whose input was erased before the backfill waits for good",
    );
    binding_lands(&mailbox.vault, input).expect("the erased input's binding lands");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "FREED: the landing of an erased input's binding settled a fact waiting on it for good",
    );
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once the erased input's binding landed");
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the owner, who reads every source here, reads a fact that waits for good (ruling A)",
    );
    housekeeping_pass(&mailbox);
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "FREED: a housekeeping pass settled a fact waiting for good on an erased input",
    );
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after a later housekeeping pass");
}

/// P2-4: once the backfill has ended, a CLAIM that arrives by sync with a
/// birth naming an input this vault erased is sealed in the write that
/// lands that birth, as a local birth is: its floor can hold nothing of the
/// erased input. Before the fix it neither waited nor sealed, and a stranger
/// read it.
#[cfg(feature = "sync")]
#[test]
fn a_claim_arriving_born_from_an_input_erased_here_is_sealed() {
    use oneiron::test_doors::read_lineage_floor::replicated_birth_lands;
    use oneiron::{TimeRange, Vault};

    let mailbox = owners_mailbox();
    let input = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    erase(&mailbox, input);
    housekeeping_pass(&mailbox);
    let arrived = EntityId::now();
    let vault: &Vault = &mailbox.vault;
    vault
        .put_claim(
            &arrived,
            &super::claim_body(&mailbox, "fact.arrived", "learnt elsewhere from the input"),
            TimeRange {
                start: super::AT,
                end: super::AT,
            },
            super::AT,
        )
        .expect("FIXTURE: the arriving CLAIM");
    replicated_birth_lands(
        vault,
        arrived,
        super::made_by(&mailbox, &[input], MadeByInputRole::Input),
    )
    .expect("its birth lands as sync lands it");
    assert_no_stranger_or_reader_reads(&mailbox, arrived, "once its birth landed");
    assert!(
        !reads(vault, arrived, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads a CLAIM that arrived born from an input erased here",
    );
    assert_eq!(
        hidden_source_unknown(&mailbox),
        1,
        "doctor counts the sealed CLAIM",
    );
}

/// #10108 P1-1: `fact` waits for `late`, a row this vault never held. A
/// peer's tombstone of `late` (`reason`) replays here: what `late` would
/// have added to the floor can no longer be known, so its first application
/// seals `fact`, as the erase of a held row does. Before the fix the replay
/// ran no eraser, `fact` waited for good, and the owner read it.
fn a_row_waiting_on_a_row_never_held_here_is_sealed_by_its_tombstone(reason: TombstoneReason) {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let fact = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact born from a row not here yet waits",
    );
    replay(&mailbox, late, reason);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once the peer's tombstone replayed");
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads a fact waiting on a row a peer erased before it landed here",
    );
    housekeeping_pass(&mailbox);
    assert!(
        !floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "STUCK: a fact sealed by a replayed tombstone still waits after a pass",
    );
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after a housekeeping pass");
    assert_eq!(
        hidden_source_unknown(&mailbox),
        1,
        "doctor counts the fact the tombstone sealed",
    );
}

#[test]
fn a_row_waiting_on_a_row_never_held_here_is_sealed_by_its_hard_tombstone() {
    a_row_waiting_on_a_row_never_held_here_is_sealed_by_its_tombstone(
        TombstoneReason::UserHardDelete,
    );
}

#[test]
fn a_row_waiting_on_a_row_never_held_here_is_sealed_by_its_soft_tombstone() {
    a_row_waiting_on_a_row_never_held_here_is_sealed_by_its_tombstone(TombstoneReason::UserDelete);
}

/// #10108 P1-2: `supported` waits on its one support, `waiting`, whose own
/// floor waits for a row not here yet. Then a free support (held, whole, an
/// empty floor) supports it too, which frees it: it settles and reads to the
/// mailbox's reader. The erase of `waiting` must not seal it: its floor no
/// longer waits on `waiting`. Before the fix the settle left the old mark,
/// and the erase sealed `supported`.
#[test]
fn a_row_freed_by_a_free_support_is_not_sealed_by_the_erase_of_the_support_it_waited_on() {
    let mailbox = owners_mailbox();
    let waiting = super::claim_of_predicate_born_with(
        &mailbox,
        &[EntityId::now()],
        MadeByInputRole::Input,
        "fact.support_waiting",
        "learnt from a row on its way",
    );
    let supported = super::claim_of_predicate_born_with(
        &mailbox,
        &[],
        MadeByInputRole::Input,
        "fact.supported",
        "held by its supports",
    );
    mailbox
        .vault
        .put_edge(&waiting, EdgeKind::Supports, &supported, 1.0)
        .expect("FIXTURE: waiting supports the claim");
    assert!(
        floor_waits(&mailbox.vault, supported).expect("the floor's state"),
        "precondition: a claim whose one support waits waits too",
    );
    let free = super::claim_of_predicate_born_with(
        &mailbox,
        &[],
        MadeByInputRole::Input,
        "fact.support_free",
        "in its own words",
    );
    mailbox
        .vault
        .put_edge(&free, EdgeKind::Supports, &supported, 1.0)
        .expect("FIXTURE: a free support supports the claim too");
    assert!(
        !floor_waits(&mailbox.vault, supported).expect("the floor's state"),
        "precondition: a free support frees the claim",
    );
    assert!(
        reads(&mailbox.vault, supported, &[mailbox.reader]).expect("the reader's read"),
        "precondition: the freed claim reads to the mailbox's reader",
    );
    erase(&mailbox, waiting);
    assert!(
        reads(&mailbox.vault, supported, &[mailbox.reader]).expect("the reader's read"),
        "SEALED: the erase of a support a settled claim no longer waited on sealed it",
    );
    housekeeping_pass(&mailbox);
    assert!(
        reads(&mailbox.vault, supported, &[mailbox.reader]).expect("the reader's read"),
        "SEALED: after a pass, a settled claim no longer reads to the mailbox's reader",
    );
    assert_eq!(
        hidden_source_unknown(&mailbox),
        0,
        "doctor counts no sealed fact",
    );
}

/// #10108 P1-3 (FLOOR-OLD-FACT-ERASED-INPUT = A): a fact held before floors
/// whose birth input was soft-deleted before the backfill raised it waits
/// for good. The same soft tombstone replays here again, as a forward
/// rematerialization replays it: the input was erased already, so nothing
/// changes, and the owner reads the fact as before. Before the fix the
/// replay's teardown took the mark and sealed the fact.
#[test]
fn a_replayed_soft_tombstone_of_an_erased_input_leaves_a_fact_waiting_for_good() {
    let mailbox = owners_mailbox();
    let input = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.erased_input");
    let fact = claim_born_before_floors(&mailbox, &[input], "fact.held_from_input");
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    housekeeping_pass(&mailbox);
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact whose input was erased before the backfill waits for good",
    );
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "precondition: the owner reads a fact that waits for good (ruling A)",
    );
    replay(&mailbox, input, TombstoneReason::UserDelete);
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "SEALED: a replayed soft tombstone of an input erased here sealed a fact waiting on it for good",
    );
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "FREED: a replayed soft tombstone settled a fact waiting for good",
    );
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once the soft tombstone replayed");
    assert_eq!(
        hidden_source_unknown(&mailbox),
        0,
        "doctor counts no sealed fact",
    );
}

/// #10108 Opus P2-2 (the lead's ruling A: "if the owner wants such facts
/// gone, the erase of the source does it through the erase path"): a fact
/// that waits for good on an input soft-deleted before the backfill raised
/// it is sealed when that input is erased: here a peer's hard tombstone
/// purges its shell. The owner then reads it no more, and doctor counts it.
#[test]
fn a_hard_erase_of_an_input_deleted_before_floors_seals_the_fact_waiting_on_it() {
    let mailbox = owners_mailbox();
    let input = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.erased_input");
    let fact = claim_born_before_floors(&mailbox, &[input], "fact.held_from_input");
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    housekeeping_pass(&mailbox);
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "precondition: the owner reads a fact that waits for good (ruling A)",
    );
    replay(&mailbox, input, TombstoneReason::UserHardDelete);
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the hard erase of its input left the owner reading a fact that waited on it for good",
    );
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after its input's hard erase");
    assert_eq!(
        hidden_source_unknown(&mailbox),
        1,
        "doctor counts the fact the erase sealed",
    );
}

/// #10108 Opus P2-3, the other order: a peer's tombstone (`reason`) of
/// `late`, a row this vault never held, replays first; then a CLAIM born
/// from `late` arrives. Its birth names an input erased here, so it is
/// sealed, as it is when it arrives first and the tombstone comes after
/// (`a_row_waiting_on_a_row_never_held_here_is_sealed_by_its_*_tombstone`).
#[cfg(feature = "sync")]
fn a_claim_arriving_after_the_tombstone_of_its_input_is_sealed(reason: TombstoneReason) {
    use oneiron::test_doors::read_lineage_floor::replicated_birth_lands;
    use oneiron::{TimeRange, Vault};

    let mailbox = owners_mailbox();
    let late = EntityId::now();
    replay(&mailbox, late, reason);
    let arrived = EntityId::now();
    let vault: &Vault = &mailbox.vault;
    vault
        .put_claim(
            &arrived,
            &super::claim_body(
                &mailbox,
                "fact.arrived_after",
                "learnt from a row erased first",
            ),
            TimeRange {
                start: super::AT,
                end: super::AT,
            },
            super::AT,
        )
        .expect("FIXTURE: the arriving CLAIM");
    replicated_birth_lands(
        vault,
        arrived,
        super::made_by(&mailbox, &[late], MadeByInputRole::Input),
    )
    .expect("its birth lands as sync lands it");
    assert_no_stranger_or_reader_reads(&mailbox, arrived, "once its birth landed");
    assert!(
        !reads(vault, arrived, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads a CLAIM that arrived born from a row whose tombstone came first",
    );
    housekeeping_pass(&mailbox);
    assert_eq!(
        hidden_source_unknown(&mailbox),
        1,
        "doctor counts the sealed CLAIM",
    );
}

#[cfg(feature = "sync")]
#[test]
fn a_claim_arriving_after_the_hard_tombstone_of_its_input_is_sealed() {
    a_claim_arriving_after_the_tombstone_of_its_input_is_sealed(TombstoneReason::UserHardDelete);
}

#[cfg(feature = "sync")]
#[test]
fn a_claim_arriving_after_the_soft_tombstone_of_its_input_is_sealed() {
    a_claim_arriving_after_the_tombstone_of_its_input_is_sealed(TombstoneReason::UserDelete);
}

/// #10108 Opus P1-1: `derived` is written from `middle` (`DerivedFrom`, a
/// source the read walks), whose floor waits; `fact` is born from `derived`,
/// so it waits too. The owner's hard delete of `middle` is published (the
/// fence reads it deleted) and a housekeeping pass runs before the purge.
/// `derived` must not settle open: it reads sealed from the publication on
/// (Fable design pass 31), so `fact` is not raised open. After the purge
/// both stay sealed, and doctor counts both. Before the fix the pass
/// settled `derived` with an empty floor and raised `fact` open: a stranger
/// read it, and the purge sealed `derived` alone.
#[test]
fn a_fact_from_a_row_waiting_on_a_published_delete_stays_closed_until_the_purge_seals_it() {
    let mailbox = owners_mailbox();
    let middle = claim_born_from(&mailbox, &[EntityId::now()], "learnt from a row on its way");
    let derived = super::claim_of_predicate_born_with(
        &mailbox,
        &[],
        MadeByInputRole::Input,
        "fact.derived_from_middle",
        "derived from middle",
    );
    mailbox
        .vault
        .put_edge(&derived, EdgeKind::DerivedFrom, &middle, 1.0)
        .expect("FIXTURE: the derived row names middle");
    let fact = super::claim_of_predicate_born_with(
        &mailbox,
        &[derived],
        MadeByInputRole::Input,
        "fact.learnt_from_derived",
        "learnt from derived",
    );
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact born from a waiting row waits too",
    );
    fence_row_for_hard_delete(&mailbox.vault, middle).expect("middle's hard delete is published");
    housekeeping_pass(&mailbox);
    // Fable design pass 31, case 28: `middle` reads erased from the
    // publication on, so `derived`, which still waits on it, reads sealed
    // before the purge too, in every order of the pass and the purge.
    assert!(
        floor_sealed(&mailbox.vault, derived).expect("the floor's state"),
        "SETTLED: a pass before the purge settled a row waiting on a row whose delete is published",
    );
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after a pass before the purge");
    replay(&mailbox, middle, TombstoneReason::UserHardDelete);
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, derived, "once the purge landed");
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once the purge landed");
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads a fact whose source's floor the purge sealed",
    );
    assert_eq!(
        hidden_source_unknown(&mailbox),
        2,
        "doctor counts both rows the purge sealed",
    );
}
