//! The owner restore lands customer hold rows before their history.

use std::collections::BTreeMap;

use super::events::EVENTS;
use super::{HeldKey, ROWS, TARGETS, check_opaque, distinct, partition_hold_id};
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::deletion::{LegalHold, LegalHoldEvent, LegalHoldKind, LegalHoldTarget};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, SideKey};
use RetainedSideHeldBackReason::{
    InconsistentCompanion, InvalidEncoding, InvalidValue, MissingCompanion, MissingLiveEntity,
};

/// A canonical source row decoded before any legal-hold landing writes.
enum DecodedRow {
    /// A customer hold primary and its source key.
    Hold(EntityId, LegalHold),
    /// A target index envelope, never an independent write source.
    Target((HeldKey, EntityId)),
    /// A customer hold event at its archived sequence.
    Event((EntityId, u64), LegalHoldEvent),
}

/// Decodes each envelope with its owning codec and the shared credential predicate.
fn decode_row(
    row: &ArchiveRetainedSideRow,
) -> std::result::Result<DecodedRow, RetainedSideHeldBackReason> {
    match row.source_table.as_str() {
        name if name == side_table::LEGAL_HOLD_ROW.name => {
            decode_archived_row(&ROWS, row).map(|(key, value)| DecodedRow::Hold(key, value))
        }
        name if name == side_table::LEGAL_HOLD_TARGET.name => {
            decode_archived_row(&TARGETS, row).map(|(key, ())| DecodedRow::Target(key))
        }
        name if name == side_table::LEGAL_HOLD_EVENT.name => {
            decode_archived_row(&EVENTS, row).map(|(key, value)| DecodedRow::Event(key, value))
        }
        _ => Err(InvalidEncoding),
    }
}

/// Checks customer writer values without requiring a target record to exist.
fn valid_hold(key: &EntityId, hold: &LegalHold) -> bool {
    if *key != hold.hold_id || hold.kind != LegalHoldKind::Customer || hold.requires_non_use {
        return false;
    }
    if !distinct(hold.targets.clone()).is_ok_and(|targets| targets == hold.targets) {
        return false;
    }
    if hold
        .matter_ref
        .as_ref()
        .is_some_and(|value| check_opaque(value, "matter reference").is_err())
        || hold
            .placed_by
            .as_ref()
            .is_some_and(|value| check_opaque(value, "placed by").is_err())
    {
        return false;
    }
    if let Some(target) = hold
        .targets
        .iter()
        .find(|target| matches!(target, LegalHoldTarget::GatePartition(_)))
    {
        if hold.targets.len() != 1
            || !partition_hold_id(target).is_ok_and(|hold_id| hold_id == hold.hold_id)
        {
            return false;
        }
    }
    true
}

/// Lands hold rows and their ordered events. No hold indexes its targets or keeps
/// a record in the vault (LEGAL-HOLD-USE = B), so an archived target index row
/// lands nowhere.
pub(crate) fn land_archived_legal_hold_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    use ArchivedSideRowOutcome::{HeldBack, Installed, KeptLive, Unchanged};

    let decoded: Vec<_> = rows.iter().map(decode_row).collect();
    let mut outcomes: Vec<_> = decoded
        .iter()
        .map(|row| match row {
            Err(reason) => HeldBack(*reason),
            Ok(_) => HeldBack(MissingCompanion),
        })
        .collect();
    // Remember even a rejected primary with a decodable key, so its companions cannot
    // fall back to an unrelated destination row.
    let primary_inputs: BTreeMap<_, _> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            (row.source_table == side_table::LEGAL_HOLD_ROW.name)
                .then(|| EntityId::decode_key(&row.source_key).map(|key| (key, index)))
                .flatten()
        })
        .collect();

    for (index, row) in decoded.iter().enumerate() {
        let Ok(DecodedRow::Hold(key, hold)) = row else {
            continue;
        };
        if !valid_hold(key, hold) {
            outcomes[index] = HeldBack(InvalidValue);
            continue;
        }
        if hold.stands() {
            match vault.refuse_erased_targets_in_txn(txn, &hold.targets) {
                Ok(()) => {}
                Err(Error::Record(RecordError::HoldTargetErased(_))) => {
                    outcomes[index] = HeldBack(MissingLiveEntity);
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        outcomes[index] = install_archived_row(&ROWS, vault, txn, permit, key, &rows[index])?;
    }

    for (index, row) in decoded.iter().enumerate() {
        let Ok(DecodedRow::Target(key)) = row else {
            continue;
        };
        if let Some(primary) = primary_inputs.get(&key.1) {
            match outcomes[*primary] {
                KeptLive => {
                    outcomes[index] = HeldBack(InconsistentCompanion);
                    continue;
                }
                HeldBack(_) => {
                    outcomes[index] = HeldBack(MissingCompanion);
                    continue;
                }
                Installed | Unchanged => {}
            }
        }
        // No hold indexes its targets (LEGAL-HOLD-USE = B), so an archived
        // index row names no target of its hold and lands nowhere.
        outcomes[index] = match ROWS.get(vault, txn, &key.1)? {
            None => HeldBack(MissingCompanion),
            Some(_) => HeldBack(InconsistentCompanion),
        };
    }

    let mut events: Vec<_> = decoded
        .iter()
        .enumerate()
        .filter_map(|(index, row)| match row {
            Ok(DecodedRow::Event(key, event)) => Some((*key, index, event)),
            _ => None,
        })
        .collect();
    events.sort_by_key(|(key, _, _)| *key);
    for (key, index, event) in events {
        if key.0 != event.hold_id {
            outcomes[index] = HeldBack(InvalidValue);
            continue;
        }
        let Some(primary) = primary_inputs.get(&key.0) else {
            outcomes[index] = HeldBack(MissingCompanion);
            continue;
        };
        match outcomes[*primary] {
            KeptLive => {
                outcomes[index] = HeldBack(InconsistentCompanion);
                continue;
            }
            HeldBack(_) => {
                outcomes[index] = HeldBack(MissingCompanion);
                continue;
            }
            Installed | Unchanged => {}
        }
        let Some(hold) = ROWS.get(vault, txn, &key.0)? else {
            outcomes[index] = HeldBack(MissingCompanion);
            continue;
        };
        outcomes[index] = if event.kind != LegalHoldKind::Customer
            || event.kind != hold.kind
            || event.matter_ref != hold.matter_ref
        {
            HeldBack(InconsistentCompanion)
        } else {
            install_archived_row(&EVENTS, vault, txn, permit, &key, &rows[index])?
        };
    }
    Ok(outcomes)
}
