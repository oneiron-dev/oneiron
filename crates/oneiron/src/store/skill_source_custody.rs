//! Core half of `store::skill_source_custody`: its store-layer items live in `oneiron_store::skill_source_custody` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::skill_source_custody::*;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;
use crate::store::skill_source_carrier::source_carrier_id;
use crate::write_envelope::skill_record::SkillContentHash;

/// Source-custody state (live/dead/unseen byte) for one (holder, content
/// hash) pair.
pub(crate) const INDEX: SideTable<(EntityId, [u8; 32]), CustodyState, Raw> =
    SideTable::new(&side_table::SKILL_HUB_SOURCE_CUSTODY);

pub(crate) fn source_rows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<Vec<(SkillContentHash, CustodyState)>> {
    Ok(INDEX
        .scan_from(store, txn, holder.as_bytes())?
        .into_iter()
        .map(|((_, hash), state)| (SkillContentHash::from_bytes(hash), state))
        .collect())
}

pub(crate) fn source_custody_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<bool> {
    Ok(source_rows(store, txn, holder)?
        .iter()
        .any(|(_, state)| *state == CustodyState::Live))
}

/// Only IDs remain after deletion, so the existing hard-history sweep can
/// cover every revision and pending carrier without retaining its payload.
pub(crate) fn source_carriers_for_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<Vec<EntityId>> {
    source_rows(store, txn, holder)?
        .iter()
        .filter(|(_, state)| *state != CustodyState::Unseen)
        .map(|(hash, _)| source_carrier_id(holder, hash))
        .collect()
}
