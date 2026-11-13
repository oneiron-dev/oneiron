//! The owner restore lands customer hold protection before its dependent markers and history.

use std::collections::{BTreeMap, BTreeSet};

use super::events::EVENTS;
use super::notice::retaining_holds_in_txn;
use super::use_limit::USE_LIMITS;
use super::{
    ERASE_LINKS, EraseLink, HeldKey, ROWS, TARGETS, check_opaque, distinct, held_keys,
    partition_hold_id,
};
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::deletion::{
    LegalHold, LegalHoldEvent, LegalHoldKind, LegalHoldReason, LegalHoldTarget, LegalHoldUseLimit,
};
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
    /// A record's privacy-erase use marker.
    UseLimit(EntityId, LegalHoldUseLimit),
    /// A record's confirmed-erase completion links.
    EraseLink(EntityId, EraseLink),
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
        name if name == side_table::LEGAL_HOLD_USE_LIMIT.name => {
            decode_archived_row(&USE_LIMITS, row)
                .map(|(key, value)| DecodedRow::UseLimit(key, value))
        }
        name if name == side_table::LEGAL_HOLD_ERASE_LINK.name => {
            decode_archived_row(&ERASE_LINKS, row)
                .map(|(key, value)| DecodedRow::EraseLink(key, value))
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

/// Lands primary protection, target accounting, use limits, erase links and ordered events.
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
    let mut written_targets = BTreeSet::new();

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
        let outcome = install_archived_row(&ROWS, vault, txn, permit, key, &rows[index])?;
        if matches!(outcome, Installed | Unchanged) {
            for held in held_keys(hold) {
                let target = (held, *key);
                if !TARGETS.contains(vault, txn, &target)? {
                    TARGETS.put(vault, txn, &target, &())?;
                    written_targets.insert(target);
                }
            }
        }
        outcomes[index] = outcome;
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
        outcomes[index] = match ROWS.get(vault, txn, &key.1)? {
            None => HeldBack(MissingCompanion),
            Some(hold) if !held_keys(&hold).contains(&key.0) => HeldBack(InconsistentCompanion),
            Some(_) if written_targets.contains(key) => Installed,
            Some(_) if TARGETS.contains(vault, txn, key)? => Unchanged,
            // Without a primary landing, an envelope cannot repair a missing index.
            Some(_) => HeldBack(MissingCompanion),
        };
    }

    for (index, row) in decoded.iter().enumerate() {
        let Ok(DecodedRow::UseLimit(key, limit)) = row else {
            continue;
        };
        if *key != limit.record || limit.reason != LegalHoldReason::PrivacyEraseKept {
            outcomes[index] = HeldBack(InvalidValue);
            continue;
        }
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, key)?.is_live() {
            outcomes[index] = HeldBack(MissingLiveEntity);
            continue;
        }
        if retaining_holds_in_txn(vault, txn, key)?.is_empty() {
            outcomes[index] = HeldBack(MissingCompanion);
            continue;
        }
        if USE_LIMITS.get_bytes(vault, txn, key)?.is_none() {
            crate::dreamer_consolidation::mark_person_about_dropped_in_txn(&vault.store, txn, key)?;
        }
        outcomes[index] = install_archived_row(&USE_LIMITS, vault, txn, permit, key, &rows[index])?;
    }

    for (index, row) in decoded.iter().enumerate() {
        let Ok(DecodedRow::EraseLink(key, link)) = row else {
            continue;
        };
        // The link writer never stores an empty or repeated hold list.
        let named: BTreeSet<_> = link.holds.iter().collect();
        if link.holds.is_empty() || named.len() != link.holds.len() {
            outcomes[index] = HeldBack(InvalidValue);
            continue;
        }
        let mut backed = true;
        for hold in &link.holds {
            let landed = primary_inputs
                .get(hold)
                .is_some_and(|primary| matches!(outcomes[*primary], Installed | Unchanged));
            if !landed
                || !ROWS
                    .get(vault, txn, hold)?
                    .is_some_and(|row| row.kind == LegalHoldKind::Customer)
            {
                backed = false;
                break;
            }
        }
        outcomes[index] = if backed {
            install_archived_row(&ERASE_LINKS, vault, txn, permit, key, &rows[index])?
        } else {
            HeldBack(MissingCompanion)
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
