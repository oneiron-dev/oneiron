//! #10117 Opus review P1-1: a cleanup archive tears nothing, and a restore
//! brings the row back whole, so the floor reads an archived WAITER as held,
//! not erased. A waiting row archived keeps its wait and its marks: the
//! landing of what it waits on raises it, the erase of what it waits on
//! seals it, and the sweep leaves it waiting. Its restore raises it. Before
//! the fix each of these let the restored row read open to a stranger.
//!
//! FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS (#10222 Opus reviews 2 and 3): a row
//! written from an archived row the backfill never raised settled on its
//! empty floor and read open: by a birth input or a walked link, by a child
//! restored before its parent, and by a restore after the floor state was
//! lost. The backfill raises archived rows too, and runs once more in a
//! vault whose backfill ended before it did; an archived row then reads as
//! held on both sides. Review 3 P2-1: a mark on an archived row is
//! followed, so a row waiting on it settles when its floor does.

use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::read_lineage_floor::{
    end_backfill_without_archived_rows, floor_of, floor_waits,
};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};
use oneiron::{EdgeKind, EntityId};

use super::erased_sources::{
    assert_no_stranger_or_reader_reads, erase, hidden_source_unknown, housekeeping_pass,
};
use super::{Mailbox, claim_born_before_floors, claim_born_from, owners_mailbox};
use oneiron::test_doors::read_lineage_floor::forget_floor_state;

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
/// yet. The cleanup archives `fact`; the owner erases `middle`, and a
/// housekeeping pass runs while `fact` is archived; then the owner restores
/// `fact`. The erase sealed it: it reads to no one, the owner included,
/// before and after a later pass, and doctor counts it. Before the fix the
/// erase skipped `fact` as erased, the pass dropped its wait, and the
/// restored `fact` read open.
#[test]
fn an_archived_fact_is_sealed_by_the_erase_of_the_row_it_waits_on() {
    let mailbox = owners_mailbox();
    let middle = claim_born_from(&mailbox, &[EntityId::now()], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[middle], "learnt from middle");
    archive(&mailbox, fact);
    erase(&mailbox, middle);
    housekeeping_pass(&mailbox);
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

/// An archived SOURCE from before floors (#10222 Opus review P1-1, scenario
/// 1; FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS): `source` was learnt from the
/// mailbox's row and `fact` from `source`, both before floors, and the
/// cleanup archived `source`. The backfill raises the archived `source`
/// with `fact`, so `fact` holds the mailbox's policy at once, reads to the
/// mailbox's reader and to no stranger, before and after the owner's
/// restore. Before #10222 the backfill settled `fact` with `source`'s empty
/// floor and a stranger read it; #10222 kept `fact` waiting until the
/// restore.
#[test]
fn a_fact_from_an_archived_source_held_before_floors_reads_under_its_sources_policy() {
    let mailbox = owners_mailbox();
    let source = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.archived_source");
    let fact = claim_born_before_floors(&mailbox, &[source], "fact.held_from_archived");
    archive(&mailbox, source);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after the backfill");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after a later pass");
    restore(&mailbox, source);
    assert_reads_as_its_landed_source(
        &mailbox,
        fact,
        mailbox.policy,
        "once its source is restored",
    );
}

/// An archived SOURCE the backfill had not raised yet (#10222 Spark review
/// P1; FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS): in a vault that held no policy
/// yet, `source` was learnt from `late`, a row not here, and `fact` from
/// `source`, and no floor was written. Then `late` lands, bound to a
/// member's mailbox, and the cleanup archives `source`. The backfill raises
/// the archived `source` from `late`, and `fact` from `source`: `fact` holds
/// `late`'s policy, reads to the mailbox's reader and to no stranger, before
/// and after the restore. Before #10222 `fact` settled with `source`'s
/// empty floor at the first pass, and a stranger read it; #10222 kept
/// `fact` waiting until the restore.
#[test]
fn a_fact_from_a_source_archived_before_the_backfill_raised_it_reads_under_its_sources_policy() {
    let late = EntityId::now();
    let mut mailbox = mailbox_with_no_policy_yet(late);
    let source = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[source], "learnt from source");
    mailbox.policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.reader])
        .expect("late lands, bound to a member's mailbox");
    archive(&mailbox, source);
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after the backfill");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after a later pass");
    restore(&mailbox, source);
    assert_reads_as_its_landed_source(
        &mailbox,
        fact,
        mailbox.policy,
        "once its source is restored",
    );
}

/// A vault holding no policy yet, so no row can have a floor: its mailbox
/// row `row` has not landed, and its policy is a placeholder until it does.
fn mailbox_with_no_policy_yet(row: EntityId) -> Mailbox {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device())
        .expect("FIXTURE: open the vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    Mailbox {
        _dir: dir,
        vault,
        owner,
        reader: EntityId::now(),
        stranger: EntityId::now(),
        row,
        policy: EntityId::now(),
    }
}

/// FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS, a walked link (#10222 Opus review 3,
/// case a): in a vault that held no policy yet, `source` was learnt from
/// `late`, a row not here, and `fact` is `DerivedFrom` `source`; no floor
/// was written. `late` lands, bound to a member's mailbox, and the cleanup
/// archives `source`. The backfill raises the archived `source`, so `fact`
/// holds `late`'s policy. Before the fix the backfill skipped `source`, and
/// `fact` settled with its empty floor: a read walk that reaches
/// `source`'s bytes finds no policy there, so a stranger read `fact`.
#[test]
fn a_fact_derived_from_a_source_archived_before_floors_takes_its_floor_at_the_backfill() {
    let late = EntityId::now();
    let mut mailbox = mailbox_with_no_policy_yet(late);
    let source = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[], "derived from source");
    mailbox
        .vault
        .put_edge(&fact, EdgeKind::DerivedFrom, &source, 1.0)
        .expect("FIXTURE: fact names its source");
    mailbox.policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.reader])
        .expect("late lands, bound to a member's mailbox");
    archive(&mailbox, source);
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after the backfill");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after a later pass");
}

/// FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS, a child restored first (#10222 Opus
/// review 3, case b): `parent` was learnt from the mailbox's row and
/// `child` from `parent`, both before floors, and the cleanup archived both.
/// The backfill raises both, so the owner's restore of `child` alone brings
/// it back holding the mailbox's policy, and `parent`'s later restore keeps
/// it so. Before the fix the backfill skipped both, and the restore raise
/// of `child` (no first raise) settled it with the archived `parent`'s
/// empty floor: a stranger read it.
#[test]
fn a_child_restored_before_its_archived_parent_reads_under_the_parents_source() {
    let mailbox = owners_mailbox();
    let parent = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.archived_parent");
    let child = claim_born_before_floors(&mailbox, &[parent], "fact.archived_child");
    archive(&mailbox, parent);
    archive(&mailbox, child);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    housekeeping_pass(&mailbox);
    restore(&mailbox, child);
    assert_reads_as_its_landed_source(
        &mailbox,
        child,
        mailbox.policy,
        "once restored before its parent",
    );
    housekeeping_pass(&mailbox);
    restore(&mailbox, parent);
    assert_reads_as_its_landed_source(
        &mailbox,
        child,
        mailbox.policy,
        "once its parent is restored too",
    );
}

/// FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS, a restore after the floor state was
/// lost (#10222 Opus review 3, case c): `fact` was learnt from `input`,
/// both before floors; the cleanup archived `fact`, the owner erased
/// `input`, and the floor state was lost (a checkpoint restore). The
/// backfill raises the archived `fact` for the first time over an erased
/// input, so it waits for good (FLOOR-OLD-FACT-ERASED-INPUT = A): once
/// restored it reads to no stranger and to no reader, through a later pass,
/// and the owner, who reads every source here, reads it. Before the fix the
/// backfill skipped `fact`, and its restore raise settled it unsealed and
/// open.
#[test]
fn a_fact_archived_over_an_erased_input_waits_for_good_after_the_floor_state_was_lost() {
    let mailbox = owners_mailbox();
    let input = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.erased_input");
    let fact = claim_born_before_floors(&mailbox, &[input], "fact.archived_over_erased_input");
    archive(&mailbox, fact);
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: the floor state is lost");
    housekeeping_pass(&mailbox);
    restore(&mailbox, fact);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once restored");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "a restored fact whose input was erased before the backfill raised it no longer waits",
    );
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after a pass once restored");
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the owner, who reads every source here, does not read a fact that waits for good",
    );
}

/// FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS in a vault whose backfill ended
/// before the backfill raised archived rows (#10222 Opus review 3: run it
/// once more): `source` was learnt from the mailbox's row and `fact` from
/// `source`, both before floors, and the cleanup archived `source`; that
/// backfill settled `fact` with the archived `source`'s empty floor, so a
/// stranger reads it. The next pass raises every row once more, `source`
/// with them, and `fact` then holds the mailbox's policy. `kept`, learnt
/// from `input` while it stood, keeps reading to the mailbox's reader
/// through that run though `input` was erased since: the run holds no live
/// row for good.
#[test]
fn a_vault_backfilled_before_archived_rows_were_raised_raises_them_in_one_more_run() {
    let mailbox = owners_mailbox();
    let input = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    let kept = claim_born_from(&mailbox, &[input], "learnt from input while it stood");
    let source =
        claim_born_before_floors(&mailbox, &[mailbox.row], "fact.archived_source_backfilled");
    let fact = claim_born_before_floors(&mailbox, &[source], "fact.held_from_archived_backfilled");
    archive(&mailbox, source);
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    end_backfill_without_archived_rows(&mailbox.vault)
        .expect("FIXTURE: the backfill ended before it raised archived rows");
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.stranger]).expect("the stranger's read"),
        "precondition: that backfill left the fact from the archived source open",
    );
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after one more run");
    assert_reads_as_its_landed_source(
        &mailbox,
        kept,
        mailbox.policy,
        "after one more run, its input erased since it was raised",
    );
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after a later pass");
}

/// #10222 Opus review 3 P2-1: `source` waits on `late`, a row not here yet,
/// and `fact`, learnt from `source`, waits on `source`; the cleanup
/// archives `source`. `late` lands, bound to the mailbox: its landing
/// raises the archived `source`, and `fact` with it, so `fact` reads to the
/// mailbox's reader at once, while `source` is still archived, and after
/// its restore. Before the fix the mark of `fact` on the archived `source`
/// was not followed: `fact` read to no reader until `source`'s restore.
#[test]
fn a_fact_waiting_on_an_archived_source_settles_when_that_sources_floor_does() {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let source = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[source], "learnt from source");
    archive(&mailbox, source);
    let policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("late lands, bound to its mailbox");
    assert_reads_as_its_landed_source(
        &mailbox,
        fact,
        policy,
        "once late landed, its source archived",
    );
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, policy, "after a pass");
    restore(&mailbox, source);
    assert_reads_as_its_landed_source(&mailbox, fact, policy, "once its source is restored");
}
