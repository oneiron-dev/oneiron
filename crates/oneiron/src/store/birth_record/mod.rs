//! Immutable row birth records and their trigger index.

use heed::{RoTxn, RwTxn};
use crate::write_envelope::provenance::made_by::{MadeByInputRole, MadeByTrigger};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::ManifestDbs;
use crate::vault::live_entity_row_in_txn;
pub use crate::store::row_birth::{
    RoomEvidence, RoomEvidenceRef, RowBirth, WithheldKey, WithheldRef, WithheldRole,
};

pub(crate) mod prompted;

/// One row's birth envelope. Key: id16 (the born row).
pub(crate) const ROW_BIRTH: SideTable<EntityId, RowBirth, Named> =
    SideTable::new(&side_table::PROVENANCE_ROW_BIRTH);

/// The born-from index. Key: id16 (the trigger's ref) + id16 (the born row).
pub(crate) const BIRTH_BY_TRIGGER: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::PROVENANCE_BIRTH_BY_TRIGGER);

/// A run's durable replay record, the identity a `Run` trigger names.
pub(crate) const CODE_RUN_REPLAY_KEYS: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY);

/// Whether `trigger` names a live row of its kind (a run: a stored replay
/// record) in this transaction.
pub(crate) fn trigger_is_live_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    trigger: &MadeByTrigger,
) -> Result<bool> {
    let expected = match trigger {
        MadeByTrigger::Task(_) => crate::registry::ENTITY_TYPE_TASK,
        MadeByTrigger::Ask(_) => crate::registry::ENTITY_TYPE_TURN,
        MadeByTrigger::Skill(_) => crate::registry::ENTITY_TYPE_SKILL,
        MadeByTrigger::Run(run) => return CODE_RUN_REPLAY_KEYS.contains(store, txn, run),
    };
    Ok(live_entity_row_in_txn(store, txn, &trigger.row())?.live_type() == Some(expected))
}

/// Whether `run` has a durable replay record, for a receipt that names it.
pub(crate) fn run_exists(vault: &crate::Vault, run: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    CODE_RUN_REPLAY_KEYS.contains(&vault.store, &rtxn, run)
}

/// Stamps `row`'s birth inside the transaction that births it. The row must
/// be live; every prompt input must be a row this vault holds, or held and
/// erased since the prompt was read (FIX 8192: its words are still in the
/// row), and a trigger must name a live task, ask, run or skill. Birth is
/// immutable: the same envelope again is a no-op, a different one is refused.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a malformed envelope, an absent row, a
/// prompt this vault never held or a dead trigger; [`Error::InvariantViolation`] when the
/// row already has a different birth; storage errors as they occur. A
/// room's evidence on `birth` is treated as absent ([`RowBirth::base_form`]).
pub(crate) fn stamp_row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    let birth = birth.base_form();
    let birth = &*birth;
    birth.check_shape()?;
    // A local producer names its own refs; only a copy withholds any.
    if !birth.withheld.is_empty() {
        return Err(Error::InvalidConfig(
            "a locally stamped row birth withholds no ref".into(),
        ));
    }
    if !live_entity_row_in_txn(store, txn, row)?.is_live() {
        return Err(Error::InvalidConfig(
            "a row birth names a row this transaction does not hold".into(),
        ));
    }
    for input in &birth.made_by.inputs {
        if input.role == MadeByInputRole::Prompt
            && !prompted::prompt_input_held_in_txn(store, txn, &input.row)?
        {
            return Err(Error::InvalidConfig(
                "a row birth's prompt input is no row this vault holds or held".into(),
            ));
        }
    }
    if let Some(trigger) = &birth.made_by.trigger
        && !trigger_is_live_in_txn(store, txn, trigger)?
    {
        return Err(Error::InvalidConfig(
            "a row birth's trigger is not a live task, ask, run or skill".into(),
        ));
    }
    match ROW_BIRTH.get(store, txn, row)? {
        Some(stored) if stored == *birth => return Ok(()),
        Some(_) => {
            return Err(Error::InvariantViolation(
                "a row's birth envelope is immutable",
            ));
        }
        None => {}
    }
    ROW_BIRTH.put(store, txn, row, birth)?;
    if let Some(trigger) = &birth.made_by.trigger {
        BIRTH_BY_TRIGGER.put(store, txn, &(trigger.row(), *row), &())?;
    }
    Ok(())
}

/// Stamps `row`'s birth unless it already has one. A document birth names
/// the row's birth actor and time; a row its writing door stamped keeps
/// that birth, so the door's richer envelope is never refused here.
///
/// # Errors
///
/// As [`stamp_row_birth_in_txn`].
pub(crate) fn stamp_birth_if_absent_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    if ROW_BIRTH.contains(store, txn, row)? {
        return Ok(());
    }
    stamp_row_birth_in_txn(store, txn, row, birth)
}

/// Stamps a birth that arrived on sync beside its row. The shape rules, the
/// live-row rule and immutability hold as in [`stamp_row_birth_in_txn`], but
/// a prompt input or trigger may be absent here: it can sit in another
/// window, outside the receiver's grant, or not have arrived yet. The trigger
/// index is written from the envelope alone, so the born-from read still
/// lists the row once the trigger lands. A document birth stamped before the
/// carried one landed was a stand-in: the carried birth replaces it (Engine
/// 10-18, FIX 1180: the origin's carried birth wins). A birth whose process
/// actor this vault hard-erased never lands (FIX 6279): this vault's own
/// `dt:` marker for the actor, read in this transaction, decides, as
/// `deletion::ACTOR_ERASE_CARRIER_SOURCE` says; never an absent row or a
/// peer's word.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a malformed envelope, an absent row or an
/// actor erased here; [`Error::InvariantViolation`] when the row already has
/// a different birth that is not a document birth; storage errors as they
/// occur. A room's evidence on `birth` is treated as absent
/// ([`RowBirth::base_form`]).
pub(crate) fn stamp_replicated_row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    let birth = birth.base_form();
    let birth = &*birth;
    birth.check_shape()?;
    if !live_entity_row_in_txn(store, txn, row)?.is_live() {
        return Err(Error::InvalidConfig(
            "a replicated row birth names a row this transaction does not hold".into(),
        ));
    }
    let maker = &birth.made_by.process.actor;
    if store.port_deletion_marked(txn, DeletionMarker::HardDelete, maker)? {
        return Err(Error::InvalidConfig(
            "a replicated row birth names an actor this vault erased".into(),
        ));
    }
    match ROW_BIRTH.get(store, txn, row)? {
        Some(stored) if stored == *birth => return Ok(()),
        Some(stored) if stored.is_document_birth() => {
            if let Some(trigger) = &stored.made_by.trigger {
                BIRTH_BY_TRIGGER.delete(store, txn, &(trigger.row(), *row))?;
            }
        }
        Some(_) => {
            return Err(Error::InvariantViolation(
                "a row's birth envelope is immutable",
            ));
        }
        None => {}
    }
    ROW_BIRTH.put(store, txn, row, birth)?;
    if let Some(trigger) = &birth.made_by.trigger {
        BIRTH_BY_TRIGGER.put(store, txn, &(trigger.row(), *row), &())?;
    }
    Ok(())
}

/// `row`'s birth envelope, or `None` when the row has no stamped birth.
/// Unknown provenance is never read as stated.
pub(crate) fn row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<RowBirth>> {
    ROW_BIRTH.get(store, txn, row)
}

/// The rows whose birth names `trigger` (a task, ask, run or skill ref), in
/// id order.
pub(crate) fn rows_born_from_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    trigger: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(BIRTH_BY_TRIGGER
        .scan_keys(store, txn, trigger.as_bytes())?
        .into_iter()
        .map(|(_, row)| row)
        .collect())
}

/// Drops `row`'s birth and its born-from index row. The erase paths call it
/// beside the row's other carriers, so a recreated id is born afresh.
pub(crate) fn erase_row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    if let Some(birth) = ROW_BIRTH.get(store, txn, row)? {
        if let Some(trigger) = &birth.made_by.trigger {
            BIRTH_BY_TRIGGER.delete(store, txn, &(trigger.row(), *row))?;
        }
        ROW_BIRTH.delete(store, txn, row)?;
    }
    Ok(())
}
