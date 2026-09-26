//! The NOTE-adjacent per-entity `sync_state` workflow rows swept alongside
//! the canonical entity-document family. These sit beside, but are distinct
//! from, the ARCH-0023b document families (`d:e:`, `u:e:`, `sv:e:`, `ssv:e:`,
//! `m:u_seq:e:`), which go through the document-row port
//! (`crate::ports::DocumentRowStore`).
//!
//! Every one of these prefixes is also written from `crate::sync`, outside
//! this module's assigned slice; the bindings here are local to the NOTE
//! module's own call sites (get/contains/delete/delete_from), never the full
//! read/write surface of the family.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::side_table::{self, LegacyJson, Raw, SideTable};

use super::operations::NoteOperationReceipt;
use super::side_keys::HexPair;

/// The wire shape of an actor id inside a durable NOTE receipt row.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct EntityIdWire(#[serde(with = "super::id_codec")] pub(super) EntityId);

/// Per-entity text-document subscription marker (`ds:e:`); this module only
/// checks for its presence and, on erasure, deletes it.
pub(super) const SYNC_DS_E: SideTable<side_table::HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_DS_E);

/// Durable unacknowledged local text-document edit frame (`qd:e:`); swept
/// wholesale on erasure/recovery, never decoded here.
pub(super) const SYNC_QD_E: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QD_E);

/// Durable pending semantic NOTE-operation request (`qn:e:`), keyed by entity
/// then request id.
pub(super) const SYNC_QN_E: SideTable<HexPair, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QN_E);

/// Per-admission disclosure floor (`ad:e:`); swept wholesale here, never
/// decoded (its key carries an optional middle segment this module never
/// parses).
pub(super) const SYNC_AD_E: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_AD_E);

/// Durable applied/rejected NOTE-operation receipt (`nc:e:`); swept wholesale
/// here, never decoded.
pub(super) const SYNC_NC_E: SideTable<Vec<u8>, serde_json::Value, LegacyJson> =
    SideTable::new(&side_table::SYNC_NC_E);

/// Idempotent operation receipt for one authenticated NOTE command (`nr:e:`),
/// keyed by entity then request id.
pub(super) const NOTE_RECEIPT_BY_REQUEST: SideTable<
    HexPair,
    (EntityIdWire, NoteOperationReceipt),
    LegacyJson,
> = SideTable::new(&side_table::NOTE_RECEIPT_BY_REQUEST);
