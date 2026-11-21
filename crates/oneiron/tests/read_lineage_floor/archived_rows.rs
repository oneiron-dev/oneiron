//! #10117 Opus review P1-1: a cleanup archive tears nothing, and a restore
//! brings the row back whole, so the floor reads an archived WAITER as held,
//! not erased. A waiting row archived keeps its wait and its marks: the
//! landing of what it waits on raises it, the erase of what it waits on
//! seals it, and the sweep leaves it waiting. Its restore raises it. Before
//! the fix each of these let the restored row read open to a stranger.
//!
//! #10222 review P1-1 (Opus and Spark): an archived SOURCE still reads gone.
//! The backfill never raises an archived row, so its floor may not be
//! whole: a row written from it waits on it until its restore raises both.

use oneiron::EntityId;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::read_lineage_floor::{floor_of, floor_waits};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};

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

/// `fact` waits on the archived `source`: no stranger reads it, and its
/// floor is not known whole (`when` names the moment).
fn assert_waits_on_its_archived_source(mailbox: &Mailbox, fact: EntityId, when: &str) {
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads a fact learnt from an archived source {when}",
    );
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "a fact learnt from an archived source no longer waits on it {when}",
    );
}

/// An archived SOURCE from before floors (#10222 Opus review P1-1, scenario
/// 1): `source` was learnt from the mailbox's row and `fact` from `source`,
/// both before floors, and the cleanup archived `source`. The backfill
/// never raises an archived row, so `source` holds no floor: `fact` waits
/// on it through two housekeeping passes. The owner's restore raises
/// `source`, and `fact` with it: `fact` then holds the mailbox's policy and
/// reads to the mailbox's reader. Before the fix the archived source read
/// held, the first pass settled `fact` with `source`'s empty floor, and a
/// stranger read it.
#[test]
fn a_fact_from_an_archived_source_held_before_floors_waits_until_its_restore() {
    let mailbox = owners_mailbox();
    let source = claim_born_before_floors(&mailbox, &[mailbox.row], "fact.archived_source");
    let fact = claim_born_before_floors(&mailbox, &[source], "fact.held_from_archived");
    archive(&mailbox, source);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    housekeeping_pass(&mailbox);
    assert_waits_on_its_archived_source(&mailbox, fact, "after the backfill");
    housekeeping_pass(&mailbox);
    assert_waits_on_its_archived_source(&mailbox, fact, "after a later pass");
    restore(&mailbox, source);
    assert_reads_as_its_landed_source(
        &mailbox,
        fact,
        mailbox.policy,
        "once its source is restored",
    );
}

/// An archived SOURCE the backfill had not raised yet (#10222 Spark review
/// P1): in a vault that held no policy yet, `source` was learnt from `late`,
/// a row not here, and `fact` from `source`, and no floor was written. Then
/// `late` lands, bound to a member's mailbox, and the cleanup archives
/// `source`. The backfill raises `fact` but not the archived `source`, so
/// `fact` waits on it; the owner's restore raises both, and `fact` holds
/// `late`'s policy. Before the fix `fact` settled with `source`'s empty
/// floor at the first pass, and a stranger read it.
#[test]
fn a_fact_from_a_source_archived_before_the_backfill_raised_it_waits_until_its_restore() {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device())
        .expect("FIXTURE: open the vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let late = EntityId::now();
    let mut mailbox = Mailbox {
        _dir: dir,
        vault,
        owner,
        reader: EntityId::now(),
        stranger: EntityId::now(),
        row: late,
        policy: EntityId::now(),
    };
    let source = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[source], "learnt from source");
    mailbox.policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.reader])
        .expect("late lands, bound to a member's mailbox");
    archive(&mailbox, source);
    housekeeping_pass(&mailbox);
    assert_waits_on_its_archived_source(&mailbox, fact, "after the backfill");
    housekeeping_pass(&mailbox);
    assert_waits_on_its_archived_source(&mailbox, fact, "after a later pass");
    restore(&mailbox, source);
    assert_reads_as_its_landed_source(
        &mailbox,
        fact,
        mailbox.policy,
        "once its source is restored",
    );
}
