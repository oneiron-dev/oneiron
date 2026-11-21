//! A row's open entries on the owner's full window (Fable design pass 31,
//! section 1.5, write 3; step L-S4).
//!
//! A machine that holds a row open on an input publishes its open set beside
//! the row ([`crate::source_audience::carried::Carrier::Open`]). A holder adds
//! each entry that first arrives to the row's open set here, before the update
//! that carries it lands: an entry both sides hold keeps an old fact's flag if
//! either has one, at the softer level ([`OpenFlags::merge`]). An input bound
//! and whole here hands over its floor at once; one erased here seals the row
//! at its next read; one pending here keeps it waiting. So a row that waits on
//! the machine that wrote it waits here too, and an input erased here seals
//! it, whichever of the row and the input's tombstone arrives first (oracle
//! case 50).

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::judge::{fold_entry_in_txn, take_input_floor_in_store_txn};
use super::{OPEN, OPEN_BY, OpenFlags, SourceState, StateReader, entry_flags_in, open_of_in};
use crate::error::Result;
use crate::{EntityId, Vault};

/// The open entries of `row`, by input: what this machine publishes for the
/// row on the owner's full window.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn open_entries_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<BTreeMap<EntityId, OpenFlags>> {
    Ok(open_of_in(store, txn, row)?.into_iter().collect())
}

/// Adds, in `txn`, the open entries `carried` that a full-window carrier
/// brought for `row`, held here or not yet (section 1.5, write 3). An entry
/// this vault holds already takes the carried flags by
/// [`OpenFlags::merge`]; an ordinary entry on an input bound and whole here
/// hands over the input's floor at once and is not written; a support bound
/// and whole here folds as a landing folds it. Every other entry stays open,
/// a self entry included: the verdict reads each input as it is now. A row
/// erased here takes none: its erase took its open set with it. Whether
/// anything changed here.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn merge_carried_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    carried: &BTreeMap<EntityId, OpenFlags>,
) -> Result<bool> {
    let store = &vault.store;
    if crate::ports::erased_in_txn(store, txn, row)? {
        return Ok(false);
    }
    let mut changed = false;
    let mut supports = false;
    for (input, carried_flags) in carried {
        let held = entry_flags_in(store, txn, row, input)?;
        let flags = held.map_or(*carried_flags, |held| held.merge(*carried_flags));
        if held == Some(flags) {
            continue;
        }
        if held.is_none() && input != row && flags == OpenFlags::ORDINARY {
            let state = StateReader::reader(vault, txn)?.state(input)?;
            if let SourceState::Bound(floor) = state {
                changed |= take_input_floor_in_store_txn(store, txn, row, &floor)?;
                continue;
            }
        }
        OPEN.put(store, txn, &(*row, *input), &flags.to_byte())?;
        OPEN_BY.put(store, txn, &(*input, *row), &())?;
        supports |= flags.is_attestation();
        changed = true;
    }
    if supports {
        for (input, flags) in open_of_in(store, txn, row)? {
            if !flags.is_attestation() || flags.before_floors_level().is_some() {
                continue;
            }
            let state = StateReader::reader(vault, txn)?.state(&input)?;
            if let SourceState::Bound(floor) = state {
                fold_entry_in_txn(store, txn, row, &input, &floor)?;
            }
        }
    }
    Ok(changed)
}
