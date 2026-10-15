//! This install's pin: the owner recovery root whose anchor it trusts
//! (world privacy P6b, R1).
//!
//! The pin is local, like the machine id it goes with. It never syncs, and
//! every restore that makes the vault a new machine drops it with the machine
//! identity (`identity::drop_machine_identity_in_txn`). Only a pin door on
//! this install writes it, from something the host cannot forge. The fold
//! applies it only while it holds the pinned root as valid
//! ([`AuthorityFold::pinned_root`]).

use super::{MachineAdmitter, PinnedRoot, RecoveryRootId};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Key: `()`. Value: [`PIN_ROW_V1`] ‖ root id (32) ‖ anchor key (32) ‖ the
/// earlier admitter: 0, 1 (roster) or 2 ‖ anchor key (32). Or, while a pin
/// door awaits a root: [`PIN_ROW_V2`] ‖ 0, or 1 ‖ root id ‖ anchor key ‖ the
/// earlier admitter, as in V1 ‖ the awaited root's id (32).
const PINNED_ROOT: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::IDENTITY_PINNED_ROOT);
const PIN_ROW_V1: u8 = 1;
const PIN_ROW_V2: u8 = 2;

/// The singleton: the pin, the admitter this install's machine was mine
/// under before the pin last changed (kept from the change before when it
/// was not mine then either), and the root a pin door awaits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PinRow {
    pub(crate) pin: Option<PinnedRoot>,
    pub(crate) earlier: Option<MachineAdmitter>,
    /// A root the owner pinned by its fingerprint before this install
    /// stored it (Astra #1422e F1, r23). It widens only what the store
    /// gate admits: that root's own row and its anchor's marks. It never
    /// changes the fold's trust, the pin or what counts.
    pub(crate) awaiting: Option<RecoveryRootId>,
}

/// A malformed row is corruption, never "unpinned".
fn decode(raw: &[u8]) -> Result<PinRow> {
    let corrupt = || Error::CorruptedIndex("pinned root row");
    let key = |bytes: &[u8]| <[u8; 32]>::try_from(bytes).map_err(|_| corrupt());
    let (awaits, pinned, rest) = match raw {
        [PIN_ROW_V1, rest @ ..] => (false, true, rest),
        [PIN_ROW_V2, 0, rest @ ..] => (true, false, rest),
        [PIN_ROW_V2, 1, rest @ ..] => (true, true, rest),
        _ => return Err(corrupt()),
    };
    let (pin, rest) = if pinned {
        if rest.len() < 64 {
            return Err(corrupt());
        }
        let (id, rest) = rest.split_at(32);
        let (anchor_key, rest) = rest.split_at(32);
        let pin = PinnedRoot {
            id: RecoveryRootId(key(id)?),
            anchor_key: key(anchor_key)?,
        };
        (Some(pin), rest)
    } else {
        (None, rest)
    };
    let (earlier, awaiting) = if !awaits {
        (rest, None)
    } else {
        let at = rest.len().checked_sub(32).ok_or_else(corrupt)?;
        let (earlier, awaiting) = rest.split_at(at);
        (earlier, Some(RecoveryRootId(key(awaiting)?)))
    };
    let earlier = match earlier {
        [0] => None,
        [1] => Some(MachineAdmitter::Roster),
        [2, anchor @ ..] => Some(MachineAdmitter::Anchor(key(anchor)?)),
        _ => return Err(corrupt()),
    };
    Ok(PinRow {
        pin,
        earlier,
        awaiting,
    })
}

fn encode(row: &PinRow) -> Vec<u8> {
    let mut raw = match (row.pin, row.awaiting) {
        (Some(_), None) => vec![PIN_ROW_V1],
        (Some(_), Some(_)) => vec![PIN_ROW_V2, 1],
        (None, _) => vec![PIN_ROW_V2, 0],
    };
    if let Some(pin) = row.pin {
        raw.extend_from_slice(&pin.id.0);
        raw.extend_from_slice(&pin.anchor_key);
    }
    match row.earlier {
        None => raw.push(0),
        Some(MachineAdmitter::Roster) => raw.push(1),
        Some(MachineAdmitter::Anchor(anchor)) => {
            raw.push(2);
            raw.extend_from_slice(&anchor);
        }
    }
    if let Some(awaiting) = row.awaiting {
        raw.extend_from_slice(&awaiting.0);
    }
    raw
}

/// The singleton in the caller's snapshot.
pub(crate) fn read_pin_row_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<PinRow> {
    PINNED_ROOT
        .get(store, txn, &())?
        .map_or(Ok(PinRow::default()), |raw| decode(&raw))
}

/// The pin in the caller's snapshot: the one read the fold, its cache key and
/// the pin doors share.
pub(crate) fn read_pinned_root_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<PinnedRoot>> {
    Ok(read_pin_row_in_txn(store, txn)?.pin)
}

/// The pin and the earlier admitter the singleton keeps beside it.
pub(crate) fn read_pin_and_earlier_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<(Option<PinnedRoot>, Option<MachineAdmitter>)> {
    let row = read_pin_row_in_txn(store, txn)?;
    Ok((row.pin, row.earlier))
}

/// Writes `row` in the caller's write transaction and moves the authority
/// cache generation with it, so every view and verdict keyed by the
/// generation, the store gate's among them, reads it. An abort drops both.
fn write_pin_row_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>, row: &PinRow) -> Result<()> {
    PINNED_ROOT.put(store, wtxn, &(), &encode(row))?;
    super::readonly_fold::advance_authority_cache_generation(store, wtxn)
}

/// Pins `root` in the caller's write transaction, and so refolds every view
/// under the new pin. A pin write ends any wait for a root.
pub(crate) fn write_pinned_root_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    root: PinnedRoot,
    earlier: Option<MachineAdmitter>,
) -> Result<()> {
    let row = PinRow {
        pin: Some(root),
        earlier,
        awaiting: None,
    };
    write_pin_row_in_txn(store, wtxn, &row)
}

/// Records the root a pin door awaits beside the pin, which stays, or that
/// it awaits none; a write that changes nothing writes nothing.
pub(crate) fn write_awaited_root_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    awaiting: Option<RecoveryRootId>,
) -> Result<()> {
    let row = read_pin_row_in_txn(store, wtxn)?;
    if row.awaiting == awaiting {
        return Ok(());
    }
    write_pin_row_in_txn(store, wtxn, &PinRow { awaiting, ..row })
}

/// Drops the pin with the machine identity it belongs to. A dropped pin moves
/// the generation as a written one does.
pub(crate) fn drop_pinned_root_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    if PINNED_ROOT.delete(store, wtxn, &())? {
        super::readonly_fold::advance_authority_cache_generation(store, wtxn)?;
    }
    Ok(())
}

/// The pin's row key, for the image scrub of a direct restore.
pub(crate) fn is_pinned_root_row(key: &[u8]) -> bool {
    key == side_table::IDENTITY_PINNED_ROOT.prefix
}
