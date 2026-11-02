//! Holder debts on the custody head (FIX 11206): each copy of an erasable
//! key another machine holds ([`super::super::holders`]), as the key's ref
//! and the holder machine, never a key. Every member's head carries every
//! debt standing in its host-readable compartments, paged with their other
//! rows, so a disaster recovery's landing keeps each one owed and a retired
//! key's copy kept elsewhere still reads
//! `custody_remote_retirement_pending(<holder>)` on the new host. A head
//! with no debt carries an empty list, and a landing of it keeps none.
//!
//! The key a debt names rides the same head as every erasable key does:
//! live, or once retired as its terminal record, the retirement fact whose
//! item is its whole name (purpose, parent, incarnation and ref), in the
//! same host-readable compartments. A landing retires each such key in
//! place, so the new host finds every retired key a debt names by its ref.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::holders::HolderDebt;
use super::wire::Bodies;
use super::{CompartmentScope, head_corrupt};

/// One holder debt on the wire: the key's ref and the holder machine.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HolderDebtWire {
    pub(super) key_ref: [u8; 32],
    pub(super) holder: [u8; 16],
}

/// Puts each of `debts` in the host-readable compartments.
pub(super) fn push_debts(bodies: &mut Bodies, debts: &BTreeSet<HolderDebt>) {
    for (key_ref, holder) in debts {
        bodies
            .body(CompartmentScope::HostReadable, 32 + 16)
            .holders
            .push(HolderDebtWire {
                key_ref: *key_ref,
                holder: *holder.as_bytes(),
            });
    }
}

/// Adds the debts `wires` name to `into`; a holder that is no entity id is
/// refused.
pub(super) fn open_debts(wires: &[HolderDebtWire], into: &mut BTreeSet<HolderDebt>) -> Result<()> {
    for wire in wires {
        let holder = EntityId::from_bytes(wire.holder).map_err(|_| head_corrupt())?;
        into.insert((wire.key_ref, holder));
    }
    Ok(())
}
