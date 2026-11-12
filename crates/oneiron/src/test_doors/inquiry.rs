//! Door for `tests/inquiry_records.rs` (INQUIRE-1 PR 1): the writers of the
//! member's log and the asking side's receipt, each in one write transaction
//! at the vault's store clock; the member side (PR 3) calls the log writers
//! itself. `tests/inquiry_asking_side.rs` (PR 4) ends a TASK through
//! [`cancel_task`] and counts the held answers through
//! [`held_inquiry_answer_count`].

use crate::error::Result;
use crate::inquiry::{
    Inquiry, InquiryAnswer, InquiryDecider, InquiryLogEntry, InquiryOutcome, log_inquiry_in_txn,
    settle_inquiry_in_txn, write_inquiry_receipt_in_txn,
};
use crate::receipt::ReceiptRecord;
use crate::{EntityId, Vault};

/// Logs `inquiry`, received over `edge`, in the member's vault.
///
/// # Errors
///
/// As `log_inquiry_in_txn`.
pub fn receive(vault: &Vault, edge: EntityId, inquiry: &Inquiry) -> Result<InquiryLogEntry> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        log_inquiry_in_txn(&vault.store, txn, edge, inquiry, now)
    })
}

/// Settles the logged inquiry `inquiry_id` over `edge` with `answer`.
///
/// # Errors
///
/// As `settle_inquiry_in_txn`.
pub fn settle(
    vault: &Vault,
    edge: EntityId,
    inquiry_id: EntityId,
    answer: InquiryAnswer,
    decided_by: InquiryDecider,
) -> Result<InquiryLogEntry> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        settle_inquiry_in_txn(&vault.store, txn, edge, inquiry_id, answer, decided_by, now)
    })
}

/// The asking side's receipt of one send of `inquiry` about `member`.
///
/// # Errors
///
/// As `write_inquiry_receipt_in_txn`.
pub fn record_send(
    vault: &Vault,
    inquiry: &Inquiry,
    member: &EntityId,
    outcome: InquiryOutcome,
) -> Result<ReceiptRecord> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        write_inquiry_receipt_in_txn(&vault.store, txn, inquiry, member, outcome, now)
    })
}

/// Ends `task` as `tasks.cancel` does for an open TASK with no attempt
/// running: the immutable Cancelled fact, by `actor`, at the store clock.
/// `tests/inquiry_asking_side.rs` ends the asking task with it.
///
/// # Errors
///
/// Storage errors.
pub fn cancel_task(vault: &Vault, task: EntityId, actor: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        crate::context_board::cancel_task_in_txn(vault, txn, task, actor, now)
    })
}

/// How many task-held inquiry answers `vault` holds now. Unlike
/// `Vault::held_inquiry_answer`, it drops none first, so a test sees what a
/// housekeeping pass dropped.
#[must_use]
pub fn held_inquiry_answer_count(vault: &Vault) -> usize {
    vault.inquiry_answers.held_count()
}

/// The tables whose actor scrub [`erase_actor_in_inquiry_tables`] runs.
const INQUIRY_TABLES: [&str; 2] = ["INQUIRY_LOG", "INQUIRY_RECEIPT"];

/// The part of `actor`'s erase that runs over the inquiry tables: the actor
/// scrub each of [`INQUIRY_TABLES`] registers, as an erase and a restore's
/// rerun run it. Returns how many of those tables registered one.
///
/// # Errors
///
/// Storage errors.
pub fn erase_actor_in_inquiry_tables(vault: &Vault, actor: &EntityId) -> Result<usize> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut ran = 0;
    for (decl, scrub) in crate::side_table::actor_scrubs() {
        if INQUIRY_TABLES.contains(&decl.name) {
            scrub(vault, &mut wtxn, actor)?;
            ran += 1;
        }
    }
    wtxn.commit()?;
    Ok(ran)
}

/// Runs the actor scrub each of `tables` registers, in the order of
/// `tables` and in one writer, as an erase and a restore's rerun run them
/// (`tests/inquiry_member_answer.rs`, INQUIRE-1 PR 3). Returns how many of
/// `tables` registered one.
///
/// # Errors
///
/// Storage errors.
pub fn erase_actor_in_tables_in_order(
    vault: &Vault,
    actor: &EntityId,
    tables: &[&str],
) -> Result<usize> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut ran = 0;
    for name in tables {
        if let Some((_, scrub)) =
            crate::side_table::actor_scrubs().find(|(decl, _)| decl.name == *name)
        {
            scrub(vault, &mut wtxn, actor)?;
            ran += 1;
        }
    }
    wtxn.commit()?;
    Ok(ran)
}
