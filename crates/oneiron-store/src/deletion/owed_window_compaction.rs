//! Window-compaction obligations written by an erase.

use crate::window_key::WindowKey;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeSet;

/// Sweep-queue prefix of an owed window compaction, `hc:{window}`. Its value
/// is a fresh id per raise, so a pass settles only the raise it read, then
/// the receipts waiting on it.
pub const OWED_COMPACTION_PREFIX: &[u8] = b"hc:";

/// The bytes of one id in an owed row's value.
const ID_LEN: usize = 16;

/// The receipts an owed row's `value` names after its raise; a tail that is
/// no whole id names none past it.
pub fn waiting_receipts(value: &[u8]) -> BTreeSet<EntityId> {
    value
        .get(ID_LEN..)
        .unwrap_or_default()
        .chunks_exact(ID_LEN)
        .filter_map(|bytes| EntityId::from_bytes(bytes.try_into().ok()?).ok())
        .collect()
}
