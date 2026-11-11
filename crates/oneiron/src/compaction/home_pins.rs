//! The revisions a self-written summary's home was read at (FIX 4817).
//!
//! Each home part a call wore whole keeps the live revision of its row in
//! the snapshot its words were read in. The summary lands, serves and keeps
//! its words only while every such row still reads at that revision, and,
//! for a worn self-model, while the writer's binding still names that
//! SUMMARY (FIX 4570). An erasure withdraws the summary through its row
//! dependency, as before. An edit keeps the row and publishes another
//! revision: the publishing write withdraws the summary
//! ([`crate::ports::withdraw_changed_home_dependents_in_txn`]), and every
//! landing and read fences it here. The home is never the summary's
//! evidence: these pins fence its words, not its facts.

use super::{CompactionExecution, CompactionHomeRef, compaction_home_worn_parts};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};
use crate::vault::ReadMode;

/// The home part a self-model binding names (FIX 4570).
pub const HOME_PART_SELF_MODEL: &str = "self_model";

/// Whether worn part `part` of `writer`'s home still reads, through `dbs`,
/// at the revision its words were read at: an absent part pins nothing, and
/// a self-model is also still the SUMMARY `writer`'s binding names.
pub(super) fn worn_part_stands_in(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    writer: EntityId,
    part: &CompactionHomeRef,
) -> Result<bool> {
    let Some(row) = part.row else {
        return Ok(true);
    };
    let live =
        crate::vault::entity_revision::revision_for_mode_in_txn(dbs, txn, &row, ReadMode::Live)?;
    if live != part.revision {
        return Ok(false);
    }
    if part.part == HOME_PART_SELF_MODEL {
        return Ok(crate::code_run::bound_self_model_in(dbs, txn, &writer)? == Some(row));
    }
    Ok(true)
}

/// Whether every home part `execution` wore whole still stands through
/// `dbs`, as [`worn_part_stands_in`] reads each one.
pub(crate) fn home_pins_stand_in(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    execution: &CompactionExecution,
) -> Result<bool> {
    for part in compaction_home_worn_parts(&execution.home) {
        if !worn_part_stands_in(dbs, txn, execution.writer, part)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The landing fence (FIX 4817): a self-written summary whose worn home
/// changed after its call and before its mint does not land as a fresh
/// summary. The mint refuses and its transaction writes nothing; the flight
/// keeps its raw window, and the paid call is not run again unseen.
pub(crate) fn check_home_pins_in_txn(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    writer: Option<&CompactionExecution>,
) -> Result<()> {
    match writer {
        Some(execution) if !home_pins_stand_in(dbs, txn, execution)? => Err(
            Error::ConcurrentWrite("a home part the summary wore changed before it landed"),
        ),
        _ => Ok(()),
    }
}

/// The self-written receipt of `dependent`, a row the dependency index names
/// as written from some source (FIX 4817): a conversation epoch's landing
/// receipt, a fold's ledger record or an executor epoch's coverage receipt.
/// `None` for any other row.
pub(crate) fn self_written_execution_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    dependent: &EntityId,
) -> Result<Option<CompactionExecution>> {
    if let Some(receipt) = super::conversation_receipt_in(store, txn, dependent)? {
        return Ok(Some(receipt.execution));
    }
    if let Some(execution) = super::fold_words::fold_execution_in(store, txn, dependent)? {
        return Ok(Some(execution));
    }
    crate::code_run::epoch_execution_in(store, txn, dependent)
}
