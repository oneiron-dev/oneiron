//! #9289 Opus review 3: a source a floor waits on that is then erased. What
//! it would have added to the floor can no longer be known here, so the
//! floor never settles without it: the erase seals the rows that waited on
//! it (P1-A), no later landing frees them (P1-B), and a row that arrives
//! born from an input this vault erased is sealed as a local birth is
//! (P2-4). A fact whose input was erased before the floor backfill raised it
//! waits for good (FLOOR-OLD-FACT-ERASED-INPUT = A).

use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::SafeDeleteReason;
use oneiron::test_doors::read_lineage_floor::{binding_lands, floor_waits, forget_floor_state};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};
use oneiron::{EdgeActorClass, EdgeKind, EntityId};

use super::{Mailbox, claim_born_before_floors, claim_born_from, owners_mailbox};

/// The owner deletes `row`.
fn erase(mailbox: &Mailbox, row: EntityId) {
    mailbox
        .vault
        .memory(mailbox.owner, EdgeActorClass::Human)
        .safe_delete(&row.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes the row");
}

/// A housekeeping pass, which runs the floor sweep.
fn housekeeping_pass(mailbox: &Mailbox) {
    mailbox
        .vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("a housekeeping pass runs the floor sweep");
}

/// How many facts doctor counts as hidden by a source it cannot name.
fn hidden_source_unknown(mailbox: &Mailbox) -> u64 {
    mailbox
        .vault
        .doctor()
        .expect("doctor")
        .facts_hidden_source_unknown
}

/// `row` reads to neither a stranger nor the mailbox's reader (`when`
/// names the moment).
fn assert_no_stranger_or_reader_reads(mailbox: &Mailbox, row: EntityId, when: &str) {
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
    use oneiron::provenance::made_by::MadeByInputRole;
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
