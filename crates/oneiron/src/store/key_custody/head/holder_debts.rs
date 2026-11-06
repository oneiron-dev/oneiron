//! Core half of `store::key_custody::head::holder_debts`: its store-layer items live in `oneiron_store::key_custody::head::holder_debts` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::head::holder_debts::*;

use super::super::holders::HolderDebt;
use super::wire::Bodies;
use super::{CompartmentScope, head_corrupt};
use crate::entity_id::EntityId;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
