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
//!
//! #10265 review P1-1, P1-2: in that run again, an archived row's first
//! raise stays its first when the raise stores its floor before it settles,
//! and when its restore comes before the run reaches it. #10265 Opus review
//! P2-2: a pass marks archived rows raised only once it ends, and only when
//! it began in this build with no row raised yet; P2-3: the run again starts
//! from the state an older backfill left. #10265 review 2 P1-1, P1-2: the
//! run again starts at the first row whatever cursor an older pass saved,
//! and an older pass's raised marks never make it skip a row.
//!
//! Fable design pass 31: the migration from the old backfill's tables
//! judges these rows (section 5, M2; cases 60 to 66), so each reading above
//! holds after the first housekeeping pass of this build.

use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::read_lineage_floor::{
    backfill_first_page, backfill_from_an_older_pass_cursor, end_backfill_without_archived_rows,
    floor_of, floor_waits, land_peer_turn_marked_with_no_thread, mark_backfill_done, mark_raised,
    mark_waiting_on,
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
/// once more), from the state that backfill left (#10265 Opus review P2-3):
/// in a vault that held no policy yet, `source` was learnt from the
/// mailbox's row, then on its way, and the cleanup archived it once that
/// row landed. That backfill read the archived `source` as erased: `fact`,
/// learnt from `source`, waits on it with a mark, and `linked`,
/// `DerivedFrom` `source`, settled on `source`'s empty floor, so a stranger
/// reads it. The next pass raises every row once more, `source` with them:
/// `fact` follows its mark, `linked` is raised again, and both then hold the
/// mailbox's policy. `kept`, learnt from `input` while it stood, keeps
/// reading to the mailbox's reader through that run though `input` was
/// erased since: the run holds no live row for good. Fable design pass 31
/// (case 64): before the migration visits them, a read judges `fact` and
/// `linked` as the migration will, so both read so at once.
#[test]
fn a_vault_backfilled_before_archived_rows_were_raised_raises_them_in_one_more_run() {
    let late = EntityId::now();
    let mut mailbox = mailbox_with_no_policy_yet(late);
    let source = claim_born_before_floors(&mailbox, &[late], "fact.archived_source_backfilled");
    let fact = claim_born_before_floors(&mailbox, &[source], "fact.held_from_archived_backfilled");
    let linked = claim_born_before_floors(&mailbox, &[], "fact.linked_to_archived_backfilled");
    mailbox
        .vault
        .put_edge(&linked, EdgeKind::DerivedFrom, &source, 1.0)
        .expect("FIXTURE: linked names its source");
    mailbox.policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.reader])
        .expect("late lands, bound to a member's mailbox");
    let input = claim_born_from(&mailbox, &[late], "learnt from the mailbox");
    let kept = claim_born_from(&mailbox, &[input], "learnt from input while it stood");
    archive(&mailbox, source);
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    mark_waiting_on(&mailbox.vault, fact, source)
        .expect("FIXTURE: that backfill left fact waiting on the archived source");
    end_backfill_without_archived_rows(&mailbox.vault)
        .expect("FIXTURE: the backfill ended before it raised archived rows");
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "before the migration");
    assert_reads_as_its_landed_source(&mailbox, linked, mailbox.policy, "before the migration");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after one more run");
    assert_reads_as_its_landed_source(&mailbox, linked, mailbox.policy, "after one more run");
    assert_reads_as_its_landed_source(
        &mailbox,
        kept,
        mailbox.policy,
        "after one more run, its input erased since it was raised",
    );
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after a later pass");
    assert_reads_as_its_landed_source(&mailbox, linked, mailbox.policy, "after a later pass");
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

/// #10265 review P1-1: in a vault whose backfill ended before it raised
/// archived rows, `fact` was learnt from the mailbox's row and from
/// `input`, a row learnt from a mailbox the reader does not read, all before
/// floors; the cleanup archived `fact` and the owner erased `input`. One
/// more run raises `fact` for the first time over an erased input, so it
/// waits for good: once restored it reads to no stranger and not to the
/// mailbox's reader. Before the fix that raise stored `fact`'s floor (the
/// mailbox's policy) before it asked whether it was the first, and the
/// stored floor read as an earlier raise's: `fact` settled with the
/// mailbox's policy alone, and the reader read it.
#[test]
fn an_archived_fact_from_a_held_and_an_erased_input_waits_for_good_after_one_more_run() {
    let mailbox = owners_mailbox();
    let other = EntityId::now();
    bound_row_read_by(&mailbox.vault, other, &[mailbox.owner])
        .expect("FIXTURE: a mailbox the reader does not read");
    let input = claim_born_before_floors(&mailbox, &[other], "fact.erased_input_of_other_mailbox");
    let fact = claim_born_before_floors(
        &mailbox,
        &[mailbox.row, input],
        "fact.archived_from_held_and_erased_inputs",
    );
    archive(&mailbox, fact);
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    end_backfill_without_archived_rows(&mailbox.vault)
        .expect("FIXTURE: the backfill ended before it raised archived rows");
    housekeeping_pass(&mailbox);
    restore(&mailbox, fact);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once restored");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "a restored fact whose input was erased before its first raise no longer waits",
    );
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after a pass once restored");
}

/// #10265 review P1-2: in a vault whose backfill ended before it raised
/// archived rows, `fact` was learnt from `input`, both before floors; the
/// cleanup archived `fact` and the owner erased `input`. The owner restores
/// `fact` before one more run reaches it: the restore raise is its first,
/// over an erased input, so it waits for good, once restored and through
/// that run, and the owner, who reads every source here, reads it. Before
/// the fix the restore took the archive marker off before it raised `fact`,
/// so the raise read a live row that backfill had raised, no first raise:
/// `fact` settled with an empty floor, a stranger read it, and the run
/// skipped it as raised.
#[test]
fn an_archived_fact_restored_before_one_more_run_waits_for_good_on_its_erased_input() {
    let mailbox = owners_mailbox();
    let input =
        claim_born_before_floors(&mailbox, &[mailbox.row], "fact.erased_input_restored_early");
    let fact = claim_born_before_floors(&mailbox, &[input], "fact.restored_before_one_more_run");
    archive(&mailbox, fact);
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    end_backfill_without_archived_rows(&mailbox.vault)
        .expect("FIXTURE: the backfill ended before it raised archived rows");
    restore(&mailbox, fact);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once restored");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "a fact restored before one more run no longer waits on its erased input",
    );
    housekeeping_pass(&mailbox);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "after one more run");
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.owner]).expect("the owner's read"),
        "the owner, who reads every source here, does not read a fact that waits for good",
    );
}

/// Rows one backfill write reads (`BACKFILL_PAGE`): a row created after
/// this many rows sits past the first page.
const BACKFILL_PAGE_ROWS: usize = 64;

/// #10265 Opus review P2-2, a pass an older build ends: the backfill's
/// first page runs in this build, then a build before it goes on with the
/// pass and ends it. `source`, learnt from the mailbox's row and archived,
/// sits past the first page, and so does `fact`, learnt from `source`: the
/// older build skipped `source`, read it as erased, and left `fact` waiting
/// on it. The next run raises every row once more, `source` with them, so
/// `fact` follows its mark and holds the mailbox's policy. Before the fix
/// the first page marked archived rows raised for the whole pass: the next
/// run read the backfill as done, and `fact` settled on the never raised
/// `source`'s empty floor, so a stranger read it.
#[test]
fn a_pass_an_older_build_ends_after_the_first_page_raises_archived_rows_once_more() {
    let mailbox = owners_mailbox();
    for row in 0..BACKFILL_PAGE_ROWS {
        claim_born_before_floors(&mailbox, &[], &format!("fact.first_page_row_{row}"));
    }
    let source = claim_born_before_floors(
        &mailbox,
        &[mailbox.row],
        "fact.archived_past_the_first_page",
    );
    let fact = claim_born_before_floors(&mailbox, &[source], "fact.learnt_past_the_first_page");
    archive(&mailbox, source);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    backfill_first_page(&mailbox.vault).expect("the backfill's first page runs in this build");
    mark_waiting_on(&mailbox.vault, fact, source)
        .expect("FIXTURE: the older build leaves fact waiting on the archived source");
    end_backfill_without_archived_rows(&mailbox.vault)
        .expect("FIXTURE: the older build ends the pass");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after the next run");
}

/// #10265 Opus review P2-2, a row an older build raised before this
/// build's first page: in a vault that held no policy yet, `linked` is
/// `DerivedFrom` `source`, learnt from the mailbox's row, then on its way;
/// the row lands, and the cleanup archives `source`. A write of a build before
/// this one raised `linked` while the backfill ran, without the archived
/// `source`, so `linked` keeps `source`'s empty floor, and marked it raised;
/// then this build's pass began. Its end leaves the backfill to run once
/// more, which raises `linked` again, so a fact learnt from `linked` after
/// that holds the mailbox's policy. Before the fix the pass skipped
/// `linked` as raised and marked archived rows raised: `linked` kept its
/// empty stored floor, and the later fact, which takes it, read open to a
/// stranger.
#[test]
fn a_row_an_older_build_raised_before_the_first_page_is_raised_once_more() {
    let late = EntityId::now();
    let mut mailbox = mailbox_with_no_policy_yet(late);
    let source = claim_born_before_floors(
        &mailbox,
        &[late],
        "fact.archived_source_of_an_early_raised_row",
    );
    let linked = claim_born_before_floors(&mailbox, &[], "fact.raised_early_by_an_older_build");
    mailbox
        .vault
        .put_edge(&linked, EdgeKind::DerivedFrom, &source, 1.0)
        .expect("FIXTURE: linked names its source");
    mailbox.policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.reader])
        .expect("late lands, bound to a member's mailbox");
    archive(&mailbox, source);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    mark_raised(&mailbox.vault, linked)
        .expect("FIXTURE: an older build's write raised linked without its archived source");
    housekeeping_pass(&mailbox);
    housekeeping_pass(&mailbox);
    let later = claim_born_from(&mailbox, &[linked], "learnt from linked");
    assert_reads_as_its_landed_source(
        &mailbox,
        later,
        mailbox.policy,
        "once learnt from a row an older build raised early",
    );
}

/// #10265 review 2 P1-1, a run again from an older pass's cursor: `fact`,
/// learnt from `input` before floors, was archived, and the owner erased
/// `input`. A build before this one skipped the archived `fact` and ended
/// its pass, but the cursor the sweep kept is the one it saved after the
/// page that ended at `after`, a row past `fact`. The run again starts at
/// the first row all the same, so it raises `fact` for the first time over
/// its erased input: once restored, `fact` waits for good and reads to no
/// stranger. Before the fix the run again went on from that cursor, never
/// raised `fact`, and marked archived rows raised; the restore then settled
/// `fact` on an empty floor, open.
#[test]
fn a_run_again_from_an_older_pass_cursor_starts_at_the_first_row() {
    let mailbox = owners_mailbox();
    let input = claim_born_before_floors(
        &mailbox,
        &[mailbox.row],
        "fact.erased_input_before_the_cursor",
    );
    let fact = claim_born_before_floors(&mailbox, &[input], "fact.archived_before_the_cursor");
    let after = claim_born_before_floors(&mailbox, &[], "fact.past_the_cursor");
    archive(&mailbox, fact);
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    end_backfill_without_archived_rows(&mailbox.vault)
        .expect("FIXTURE: the older build ends its pass");
    backfill_from_an_older_pass_cursor(&mailbox.vault, after)
        .expect("the run again from the older pass's cursor");
    restore(&mailbox, fact);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once restored");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "a fact the run again never raised settled though its input was erased",
    );
}

/// #10265 review 2 P1-2, raised marks an older pass left: in a vault that
/// held no policy yet, `linked` is `DerivedFrom` `source`, learnt from the
/// mailbox's row, then on its way, and `fact` is learnt from `linked`; the
/// row lands, and the cleanup archives `source`. A build before this one
/// skipped the archived `source`, raised `linked` and `fact` on its empty
/// floor and marked them raised, and committed its pass's end before its
/// clearing pages ran. The run again raises both again, `source` with
/// them, so both hold the mailbox's policy. Before the fix the run again
/// skipped both on the older pass's marks: their floors stayed empty, and
/// `fact` read open to a stranger.
#[test]
fn a_run_again_raises_rows_an_older_pass_left_marked_raised() {
    let late = EntityId::now();
    let mut mailbox = mailbox_with_no_policy_yet(late);
    let source = claim_born_before_floors(&mailbox, &[late], "fact.archived_source_of_marked_rows");
    let linked = claim_born_before_floors(&mailbox, &[], "fact.linked_and_marked_raised");
    mailbox
        .vault
        .put_edge(&linked, EdgeKind::DerivedFrom, &source, 1.0)
        .expect("FIXTURE: linked names its source");
    let fact = claim_born_before_floors(&mailbox, &[linked], "fact.learnt_from_a_marked_row");
    mailbox.policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.reader])
        .expect("late lands, bound to a member's mailbox");
    archive(&mailbox, source);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    mark_raised(&mailbox.vault, linked).expect("FIXTURE: the older pass raised linked");
    mark_raised(&mailbox.vault, fact).expect("FIXTURE: the older pass raised fact");
    mark_backfill_done(&mailbox.vault)
        .expect("FIXTURE: the older pass commits its end before its clearing pages run");
    housekeeping_pass(&mailbox);
    assert_reads_as_its_landed_source(&mailbox, linked, mailbox.policy, "after the run again");
    assert_reads_as_its_landed_source(&mailbox, fact, mailbox.policy, "after the run again");
}

/// Fable design pass 31, case 63 (#10265 Opus review P2-1): in a vault
/// whose backfill ended before it raised archived rows, `fact` was learnt
/// from `input`, a row with no source, so `fact`'s floor is empty, and
/// `kid` from `fact` and the mailbox's row; the owner erased `input` since.
/// The cleanup archives `fact` before the migration reaches it: the archive
/// judges `fact` first, while it is live, as a row an older build raised,
/// so the erased input takes nothing off its floor and holds nothing.
/// `fact` does not wait, and `kid` reads to the mailbox's reader after the
/// migration and after `fact`'s restore. Judged once archived, `fact` would
/// read as a row that backfill never raised (archived, no stored floor) and
/// wait for good on its erased input, and `kid` on `fact`.
#[test]
fn a_live_row_archived_before_the_migration_reaches_it_keeps_reading_as_its_floor_says() {
    let mailbox = owners_mailbox();
    let input = claim_born_from(&mailbox, &[], "learnt from no source");
    let fact = claim_born_from(&mailbox, &[input], "learnt from input");
    let kid = claim_born_from(
        &mailbox,
        &[mailbox.row, fact],
        "learnt from fact and the row",
    );
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault an older build backfilled");
    end_backfill_without_archived_rows(&mailbox.vault)
        .expect("FIXTURE: that backfill ended before it raised archived rows");
    archive(&mailbox, fact);
    housekeeping_pass(&mailbox);
    assert!(
        !floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "a row archived while live waits for good on an input erased after its floor was taken",
    );
    assert_reads_as_its_landed_source(&mailbox, kid, mailbox.policy, "after the migration");
    restore(&mailbox, fact);
    assert_reads_as_its_landed_source(&mailbox, kid, mailbox.policy, "once fact is restored");
}

/// Fable design pass 31, M3 in a vault whose backfill ended before it
/// raised archived rows: in a vault that held no policy yet, `fact` was
/// learnt from `input` and is `DerivedFrom` `linked`, both learnt from the
/// mailbox's row, then on its way; the cleanup archived `fact`, the row
/// landed, and the owner erased `input`. That backfill never raised the
/// archived `fact`. The owner's erase of `linked` judges `fact` for its
/// link to `linked` before the edge goes (`fact` takes its floor), and
/// marks `fact` an old fact, so the migration then judges its every link as
/// one: `input` was erased before `fact` was raised, so `fact` waits for
/// good and reads to no stranger and to no reader once restored. Taken for
/// a row an older build raised (it now holds a floor), `fact` would be
/// healed, its erased input left alone, and the reader would read it.
#[test]
fn an_archived_old_fact_a_delete_judges_for_one_link_stays_an_old_fact() {
    let late = EntityId::now();
    let mut mailbox = mailbox_with_no_policy_yet(late);
    let input = claim_born_before_floors(&mailbox, &[late], "fact.erased_before_its_raise");
    let linked = claim_born_before_floors(&mailbox, &[late], "fact.erased_after_its_link");
    let fact = claim_born_before_floors(&mailbox, &[input], "fact.archived_old_fact");
    mailbox
        .vault
        .put_edge(&fact, EdgeKind::DerivedFrom, &linked, 1.0)
        .expect("FIXTURE: fact names linked");
    archive(&mailbox, fact);
    mailbox.policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.reader])
        .expect("late lands, bound to a member's mailbox");
    erase(&mailbox, input);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault an older build backfilled");
    end_backfill_without_archived_rows(&mailbox.vault)
        .expect("FIXTURE: that backfill ended before it raised archived rows");
    erase(&mailbox, linked);
    housekeeping_pass(&mailbox);
    restore(&mailbox, fact);
    assert_no_stranger_or_reader_reads(&mailbox, fact, "once restored");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "an archived old fact whose input was erased before its raise no longer waits",
    );
}

/// #10265 Opus review 3 P2-1, under pass 31 (oracle case 69): `turn` is a
/// peer's TURN whose phone mark names no thread, landed in a vault that held
/// no policy yet, so it reads to no one; the cleanup archived it while no
/// row could have a floor, so the archive judged nothing. `late` lands,
/// bound to a member's mailbox. The migration judges the archived `turn`, a
/// row with no link, and stores its seal, and the owner's restore keeps it:
/// doctor counts it hidden, and the mailbox's reader does not read it.
/// Before the fix a row no link gave a floor stored no seal, so doctor,
/// which reads the stored floors, missed it (main's backfill and restore,
/// before #10265's last push, read the archived row as an erased shell and
/// left the seal out the same way).
#[test]
fn an_archived_turn_whose_phone_mark_names_no_thread_keeps_its_seal_through_its_restore() {
    let late = EntityId::now();
    let mut mailbox = mailbox_with_no_policy_yet(late);
    let turn = EntityId::now();
    land_peer_turn_marked_with_no_thread(&mailbox.vault, turn)
        .expect("FIXTURE: a peer's TURN, landed before floors");
    archive(&mailbox, turn);
    mailbox.policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.reader])
        .expect("late lands, bound to a member's mailbox");
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    assert_eq!(
        hidden_source_unknown(&mailbox),
        0,
        "precondition: no stored floor holds the seal yet",
    );
    housekeeping_pass(&mailbox);
    assert_eq!(
        hidden_source_unknown(&mailbox),
        1,
        "the migration's judgement of the archived TURN left its seal out of its stored floor",
    );
    restore(&mailbox, turn);
    assert_eq!(
        hidden_source_unknown(&mailbox),
        1,
        "the restored TURN's stored floor lost its seal",
    );
    assert!(
        !reads(&mailbox.vault, turn, &[mailbox.reader]).expect("the reader's read"),
        "LEAK: the mailbox's reader reads a TURN whose phone mark names no thread",
    );
}
