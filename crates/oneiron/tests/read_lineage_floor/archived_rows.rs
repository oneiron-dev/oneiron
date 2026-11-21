//! #10117 Opus review P1: a cleanup archive tears nothing, and a restore
//! brings the row back whole, so the floor reads an archived row as held,
//! not erased. A waiting row archived keeps its wait and its marks: the
//! landing of what it waits on raises it, the erase of what it waits on
//! seals it, and the sweep leaves it waiting. Its restore raises it. Before
//! the fix each of these let the restored row read open to a stranger. The
//! floor repair raises again, once, the rows such an archive already left
//! with no floor from what they waited on: each with the rows it was written
//! from first, and a row whose source no read walks was erased meanwhile
//! waits on it for good (#10139 reviews round 2).

use oneiron::EntityId;
use oneiron::provenance::made_by::MadeByInputRole;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::read_lineage_floor::{
    floor_of, floor_waits, forget_floor_wait_before_repair,
};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};

use super::erased_sources::{
    assert_no_stranger_or_reader_reads, erase, hidden_source_unknown, housekeeping_pass,
};
use super::{Mailbox, claim_born_from, owners_mailbox};

/// The cleanup archives `row`.
fn archive(mailbox: &Mailbox, row: EntityId) {
    archive_as_cleanup(&mailbox.vault, &row).expect("the cleanup archives the row");
}

/// The owner restores `row` from the archive.
fn restore(mailbox: &Mailbox, row: EntityId) {
    mailbox
        .vault
        .restore_archived(&row)
        .expect("the owner restores the row");
}

/// `row` holds `policy` on its floor, reads to the mailbox's reader, and
/// not to a stranger (`when` names the moment).
fn assert_reads_as_its_landed_source(
    mailbox: &Mailbox,
    row: EntityId,
    policy: EntityId,
    when: &str,
) {
    assert!(
        !reads(&mailbox.vault, row, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads the row {when}",
    );
    assert!(
        floor_of(&mailbox.vault, row)
            .expect("the floor")
            .contains(&policy),
        "the row's floor misses the policy of the source that landed {when}",
    );
    assert!(
        reads(&mailbox.vault, row, &[mailbox.reader]).expect("the reader's read"),
        "the mailbox's reader does not read the row {when}",
    );
}

/// Scenario A: `fact` waits on `late`, a row not here yet. The cleanup
/// archives `fact`; then `late` lands, bound to the mailbox, and a
/// housekeeping pass runs. Its landing raises the archived `fact`, so the
/// owner's restore brings it back holding `late`'s policy. Before the fix
/// the landing skipped `fact` as erased, the pass dropped its wait, and the
/// restored `fact` read to a stranger.
#[test]
fn an_archived_fact_takes_the_floor_of_a_source_that_lands_while_it_is_archived() {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let fact = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    archive(&mailbox, fact);
    let policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("late lands, bound to its mailbox");
    housekeeping_pass(&mailbox);
    restore(&mailbox, fact);
    assert_reads_as_its_landed_source(&mailbox, fact, policy, "once restored");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, policy, "after a later pass");
}

/// Scenario B: `fact` waits on `middle`, a row whose own source is not here
/// yet. The cleanup archives `fact`; the owner erases `middle`, which seals
/// `fact`; then the owner restores `fact`. It reads to no one, the owner
/// included, before and after a housekeeping pass, and doctor counts it.
/// Before the fix the erase skipped `fact` as erased, and the pass after
/// the restore settled it open.
#[test]
fn an_archived_fact_is_sealed_by_the_erase_of_the_row_it_waits_on() {
    let mailbox = owners_mailbox();
    let middle = claim_born_from(&mailbox, &[EntityId::now()], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[middle], "learnt from middle");
    archive(&mailbox, fact);
    erase(&mailbox, middle);
    restore(&mailbox, fact);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once restored");
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after a pass once restored");
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads a fact sealed by the erase of the row it waited on",
    );
    assert_eq!(
        hidden_source_unknown(&mailbox),
        1,
        "doctor counts the fact the erase sealed",
    );
}

/// Scenario C: `fact` waits on `late`. The cleanup archives it, a
/// housekeeping pass runs, and the owner restores it: it still waits, so no
/// stranger reads it. Then `late` lands, and `fact` reads to the mailbox's
/// reader. Before the fix the pass dropped the archived row's wait for
/// good: the restored `fact` read to a stranger at once, and the landing of
/// `late` never raised it.
#[test]
fn an_archived_fact_keeps_waiting_through_a_pass_and_settles_when_its_source_lands() {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let fact = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    archive(&mailbox, fact);
    housekeeping_pass(&mailbox);
    restore(&mailbox, fact);
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads a restored fact whose source has not landed",
    );
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "a restored fact whose source has not landed no longer waits for it",
    );
    let policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("late lands, bound to its mailbox");
    assert_reads_as_its_landed_source(&mailbox, fact, policy, "once its source landed");
}

/// The repair: a fact archived while it waited, before the fix, lost its
/// wait and its marks, and its restore brought it back with no floor from
/// what it waited on (here: its source lands after, and raises nothing).
/// The floor repair, which a housekeeping pass runs once, raises it again:
/// it then holds its source's policy, and no stranger reads it.
#[test]
fn the_floor_repair_raises_a_fact_an_archive_left_without_its_wait() {
    let mailbox = owners_mailbox();
    housekeeping_pass(&mailbox);
    let late = EntityId::now();
    let fact = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    forget_floor_wait_before_repair(&mailbox.vault, fact)
        .expect("FIXTURE: the fact as an archive and its restore left it before the fix");
    let policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("late lands, bound to its mailbox");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, policy, "after the floor repair");
}

/// More entity rows than one page of the floor repair reads.
const ROWS_PAST_A_REPAIR_PAGE: usize = 128;

/// An open CLAIM about the owner at the id `id`, under `predicate`, whose
/// birth names `inputs` as its evidence.
fn claim_at(mailbox: &Mailbox, id: EntityId, inputs: &[EntityId], predicate: &str) {
    super::put_claim_made_by(
        &mailbox.vault,
        id,
        &super::claim_body(mailbox, predicate, "learnt from a row"),
        super::made_by(mailbox, inputs, MadeByInputRole::Input),
    )
    .expect("FIXTURE: the CLAIM and its birth");
}

/// #10139 review round 2 P1-3: `fact` is born from `middle`, and `middle`
/// from `late`, a row not here yet; both lost their waits to an archive
/// before the fix, and `late` then landed, bound to the mailbox, raising
/// neither. `fact` sorts on an earlier page of the floor repair than
/// `middle`. The repair raises `middle` with `fact`, first, so `fact` takes
/// `late`'s policy through it. Before the fix the repair raised `fact` from
/// `middle`'s empty floor, then `middle` on a later page, never `fact`
/// again, and a stranger read `fact`.
#[test]
fn the_floor_repair_raises_a_fact_after_the_fact_it_was_born_from() {
    let mailbox = owners_mailbox();
    housekeeping_pass(&mailbox);
    let fact = EntityId::now();
    for index in 0..ROWS_PAST_A_REPAIR_PAGE {
        super::claim_of_predicate_born_with(
            &mailbox,
            &[],
            MadeByInputRole::Input,
            &format!("fixture.row_between_{index}"),
            "a row between",
        );
    }
    let middle = EntityId::now();
    let late = EntityId::now();
    claim_at(&mailbox, middle, &[late], "fact.middle_from_late");
    claim_at(&mailbox, fact, &[middle], "fact.from_middle");
    for row in [fact, middle] {
        forget_floor_wait_before_repair(&mailbox.vault, row)
            .expect("FIXTURE: the row as an archive and its restore left it before the fix");
    }
    let policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("late lands, bound to its mailbox");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, policy, "after the floor repair");
}

/// #10139 Opus review 2 P2-6, Scenario B before the fix: `fact` waits on
/// `middle`, a row whose own source is not here yet. An archive before the
/// fix dropped `fact`'s wait and its marks; the owner then erased `middle`,
/// which sealed nothing, and the restore brought `fact` back. The floor
/// repair reads `middle`'s erasure as the backfill does: `fact` waits on it
/// for good, so the owner reads it and no one else does. Before the fix the
/// repair settled `fact` open, and a stranger read it.
#[test]
fn the_floor_repair_keeps_waiting_a_fact_whose_input_was_erased_after_its_wait_was_lost() {
    let mailbox = owners_mailbox();
    housekeeping_pass(&mailbox);
    let middle = claim_born_from(&mailbox, &[EntityId::now()], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[middle], "learnt from middle");
    forget_floor_wait_before_repair(&mailbox.vault, fact)
        .expect("FIXTURE: the fact as an archive and its restore left it before the fix");
    erase(&mailbox, middle);
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after the floor repair");
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the owner loses a fact the repair left waiting for good",
    );
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "the repair settled a fact whose input was erased while its wait was lost",
    );
}
