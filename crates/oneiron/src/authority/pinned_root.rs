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
/// earlier admitter: 0, 1 (roster) or 2 ‖ anchor key (32).
const PINNED_ROOT: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::IDENTITY_PINNED_ROOT);
const PIN_ROW_V1: u8 = 1;

/// The stored pin, and the admitter this install's machine was mine under
/// before the pin last changed (kept from the change before when it was not
/// mine then either). A malformed row is corruption, never "unpinned".
fn decode(raw: &[u8]) -> Result<(PinnedRoot, Option<MachineAdmitter>)> {
    let corrupt = || Error::CorruptedIndex("pinned root row");
    let key = |bytes: &[u8]| <[u8; 32]>::try_from(bytes).map_err(|_| corrupt());
    let [PIN_ROW_V1, rest @ ..] = raw else {
        return Err(corrupt());
    };
    if rest.len() < 65 {
        return Err(corrupt());
    }
    let (id, rest) = rest.split_at(32);
    let (anchor_key, earlier) = rest.split_at(32);
    let earlier = match earlier {
        [0] => None,
        [1] => Some(MachineAdmitter::Roster),
        [2, anchor @ ..] => Some(MachineAdmitter::Anchor(key(anchor)?)),
        _ => return Err(corrupt()),
    };
    Ok((
        PinnedRoot {
            id: RecoveryRootId(key(id)?),
            anchor_key: key(anchor_key)?,
        },
        earlier,
    ))
}

/// The pin in the caller's snapshot: the one read the fold, its cache key and
/// the pin doors share.
pub(crate) fn read_pinned_root_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<PinnedRoot>> {
    PINNED_ROOT
        .get(store, txn, &())?
        .map(|raw| decode(&raw).map(|(root, _)| root))
        .transpose()
}

/// Pins `root` in the caller's write transaction and moves the authority
/// cache generation with it, so every view and verdict keyed by the
/// generation refolds under the new pin. An abort drops both.
#[cfg(test)]
pub(crate) fn write_pinned_root_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    root: PinnedRoot,
    earlier: Option<MachineAdmitter>,
) -> Result<()> {
    let mut row = vec![PIN_ROW_V1];
    row.extend_from_slice(&root.id.0);
    row.extend_from_slice(&root.anchor_key);
    match earlier {
        None => row.push(0),
        Some(MachineAdmitter::Roster) => row.push(1),
        Some(MachineAdmitter::Anchor(anchor)) => {
            row.push(2);
            row.extend_from_slice(&anchor);
        }
    }
    PINNED_ROOT.put(store, wtxn, &(), &row)?;
    super::readonly_fold::advance_authority_cache_generation(store, wtxn)
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
