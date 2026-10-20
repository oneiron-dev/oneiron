//! This install's pin: the owner recovery root whose anchor it trusts
//! (world privacy P6b, R1).
//!
//! The pin is local, like the machine id it goes with. It never syncs, and
//! every restore that makes the vault a new machine drops it with the machine
//! identity (`identity::drop_machine_identity_in_txn`). Only a pin door on
//! this install writes it, from something the host cannot forge. The fold
//! applies it only while it holds the pinned root as valid
//! ([`AuthorityFold::pinned_root`]).
//!
//! A wait a root request's pickup committed is that request's (FIX 5582):
//! once this install's fold holds the request cancelled or superseded, the
//! store gate and the owner's root view read no wait, in the same snapshot
//! that folded the cancel or the newer request, and the next pickup clears
//! it byte-free. A wait the owner made at the pin door stays his until a pin
//! ends it. No pin moves and nothing enacted is undone.

use super::{AuthorityEntryHash, AuthorityFold, MachineAdmitter, PinnedRoot, RecoveryRootId};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Key: `()`. Value: [`PIN_ROW_V1`] ‖ root id (32) ‖ anchor key (32) ‖ the
/// earlier admitter: 0, 1 (roster) or 2 ‖ anchor key (32). Or, while a pin
/// door awaits a root: [`PIN_ROW_V2`] ‖ 0, or 1 ‖ root id ‖ anchor key ‖ the
/// earlier admitter, as in V1 ‖ the awaited root's id (32). Or, while a root
/// request's pickup awaits one: [`PIN_ROW_V3`] ‖ the rest as in V2 ‖ the
/// request's signed entry (32).
const PINNED_ROOT: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::IDENTITY_PINNED_ROOT);
const PIN_ROW_V1: u8 = 1;
const PIN_ROW_V2: u8 = 2;
const PIN_ROW_V3: u8 = 3;

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
    /// The root request whose pickup committed `awaiting`, by its signed
    /// entry; `None` for a wait the owner made at this install's pin door.
    /// Such a wait lasts while the fold holds that request open
    /// ([`effective_awaited_root`], FIX 5582).
    pub(crate) awaited_for: Option<AuthorityEntryHash>,
}

/// A malformed row is corruption, never "unpinned".
fn decode(raw: &[u8]) -> Result<PinRow> {
    let corrupt = || Error::CorruptedIndex("pinned root row");
    let key = |bytes: &[u8]| <[u8; 32]>::try_from(bytes).map_err(|_| corrupt());
    let (awaits, for_request, pinned, rest) = match raw {
        [PIN_ROW_V1, rest @ ..] => (false, false, true, rest),
        [PIN_ROW_V2, 0, rest @ ..] => (true, false, false, rest),
        [PIN_ROW_V2, 1, rest @ ..] => (true, false, true, rest),
        [PIN_ROW_V3, 0, rest @ ..] => (true, true, false, rest),
        [PIN_ROW_V3, 1, rest @ ..] => (true, true, true, rest),
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
    let (rest, awaited_for) = if for_request {
        let at = rest.len().checked_sub(32).ok_or_else(corrupt)?;
        let (rest, request) = rest.split_at(at);
        (rest, Some(key(request)?))
    } else {
        (rest, None)
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
        awaited_for,
    })
}

fn encode(row: &PinRow) -> Vec<u8> {
    let awaited_for = row.awaiting.and(row.awaited_for);
    let mut raw = match (row.pin, row.awaiting, awaited_for) {
        (Some(_), None, _) => vec![PIN_ROW_V1],
        (Some(_), Some(_), None) => vec![PIN_ROW_V2, 1],
        (None, _, None) => vec![PIN_ROW_V2, 0],
        (Some(_), _, Some(_)) => vec![PIN_ROW_V3, 1],
        (None, _, Some(_)) => vec![PIN_ROW_V3, 0],
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
    if let Some(request) = awaited_for {
        raw.extend_from_slice(&request);
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
/// A row with no pin, admitter or wait is the singleton's absence.
fn write_pin_row_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>, row: &PinRow) -> Result<()> {
    if *row == PinRow::default() {
        PINNED_ROOT.delete(store, wtxn, &())?;
    } else {
        PINNED_ROOT.put(store, wtxn, &(), &encode(row))?;
    }
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
        awaited_for: None,
    };
    write_pin_row_in_txn(store, wtxn, &row)
}

/// Records the root a pin door awaits beside the pin, which stays, or that
/// it awaits none; a write that changes nothing writes nothing. `for_request`
/// names the root request whose pickup awaits it, `None` at the owner's own
/// pin door. The owner's own wait for that same root stays his: a request
/// that ends never ends it (FIX 5582).
pub(crate) fn write_awaited_root_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    awaiting: Option<RecoveryRootId>,
    for_request: Option<AuthorityEntryHash>,
) -> Result<()> {
    let row = read_pin_row_in_txn(store, wtxn)?;
    let awaited_for = match awaiting {
        None => None,
        Some(root) if row.awaiting == Some(root) && row.awaited_for.is_none() => None,
        Some(_) => for_request,
    };
    if row.awaiting == awaiting && row.awaited_for == awaited_for {
        return Ok(());
    }
    let row = PinRow {
        awaiting,
        awaited_for,
        ..row
    };
    write_pin_row_in_txn(store, wtxn, &row)
}

/// Ends the wait the root request signed as entry `request` committed, in
/// the caller's write transaction; the pin, the earlier admitter and any
/// other wait stay.
pub(crate) fn end_request_wait_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    request: AuthorityEntryHash,
) -> Result<()> {
    let row = read_pin_row_in_txn(store, wtxn)?;
    if row.awaiting.is_none() || row.awaited_for != Some(request) {
        return Ok(());
    }
    let row = PinRow {
        awaiting: None,
        awaited_for: None,
        ..row
    };
    write_pin_row_in_txn(store, wtxn, &row)
}

/// The root request whose wait `row` keeps, when `fold` holds that request
/// closed: cancelled by the owner or superseded by a newer request on this
/// install (CALLS ROOT_WORK_CANCEL, ROOT_WORK_SUPERSESSION), or answered
/// refused, its final state (FIX 5696): its wait has ended (FIX 5582).
/// `None` for the owner's own wait, a request still open or enacted, or no
/// wait.
pub(crate) fn ended_request_wait(row: &PinRow, fold: &AuthorityFold) -> Option<AuthorityEntryHash> {
    let request = row.awaiting.and(row.awaited_for)?;
    (fold.root_request_cancelled(&request)
        || fold.root_request_superseded(&request)
        || fold.root_request_refused(&request))
    .then_some(request)
}

/// The root `row` awaits as `fold` stands: its wait, unless a root request
/// committed it and `fold` holds that request ended
/// ([`ended_request_wait`]).
pub(crate) fn effective_awaited_root(row: &PinRow, fold: &AuthorityFold) -> Option<RecoveryRootId> {
    row.awaiting
        .filter(|_| ended_request_wait(row, fold).is_none())
}

/// [`effective_awaited_root`] in `txn`'s snapshot, against the fold read in
/// it under the store's posture: what the store gate takes as awaited. Only
/// a request's wait folds. A fold that cannot answer here, such as one that
/// needs history this vault does not hold yet, leaves the wait standing, as
/// it stood before: an import of that history still lands.
pub(crate) fn effective_awaited_root_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &PinRow,
) -> Option<RecoveryRootId> {
    if row.awaited_for.is_none() {
        return row.awaiting;
    }
    match super::readonly_fold::authority_view_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
    ) {
        Ok(fold) => effective_awaited_root(row, &fold),
        Err(_) => row.awaiting,
    }
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
