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

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::key_custody::head::scope::CompartmentScope;

/// One holder debt on the wire: the key's ref and the holder machine.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderDebtWire {
    pub key_ref: [u8; 32],
    pub holder: [u8; 16],
}
