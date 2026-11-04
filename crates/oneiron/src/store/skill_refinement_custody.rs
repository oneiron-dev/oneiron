//! The custody index of a skill candidate's refinement carriers: which
//! carriers a candidate owns, the holder each carrier binds to, the latest
//! ruling pointer and the retired carrier fence. The skill hub
//! (`skill_hub::refinement_custody`) stages, retires and erases these rows;
//! the store's erase, deindex and replay paths test and remove them.
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
};

/// Empty marker per (holder, carrier id) the holder currently owns.
pub(crate) const OWNED: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_OWNED);
/// Carrier id to the holder (candidate) it was indexed under.
pub(crate) const BINDING: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_BINDING);
/// The local gate's latest ruling for a holder.
pub(crate) const LATEST: SideTable<EntityId, LatestRuling, Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_LATEST);
/// Empty marker that one carrier id is permanently retired.
pub(crate) const RETIRED_SOURCE: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_SOURCE_RETIRED);

/// Latest-ruling pointer: the ruling id, then the carrier id (32 bytes).
pub(crate) struct LatestRuling {
    pub(crate) ruling: [u8; 16],
    pub(crate) carrier: [u8; 16],
}

impl RawValue for LatestRuling {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok([self.ruling, self.carrier].concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.len() != 32 {
            return Err(Error::CorruptedIndex("refinement latest pointer").into());
        }
        let mut ruling = [0; 16];
        let mut carrier = [0; 16];
        ruling.copy_from_slice(&bytes[..16]);
        carrier.copy_from_slice(&bytes[16..]);
        Ok(Self { ruling, carrier })
    }
}

/// The active payload scope is the candidate's OWNED prefix, not a scan of
/// unrelated receipt bodies or a remembered latest pointer.
pub(crate) fn refinement_custody_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    candidate: &EntityId,
) -> Result<bool> {
    let mut owned = OWNED.iter_raw_from(store, txn, candidate.as_bytes())?;
    Ok(owned.next().transpose()?.is_some() || LATEST.contains(store, txn, candidate)?)
}

/// Source-id deletion drops ownership and retains only a content-free ID fence.
pub(crate) fn remove_refinement_carrier_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(holder) = BINDING.get(store, txn, id)? else {
        return Ok(());
    };
    OWNED.delete(store, txn, &(holder, *id))?;
    // A malformed pointer is left in place, as before: only a well-formed
    // pointer naming this carrier is dropped.
    if LATEST
        .get_lenient(store, txn, &holder)?
        .is_some_and(|pointer| pointer.carrier == *id.as_bytes())
    {
        LATEST.delete(store, txn, &holder)?;
    }
    RETIRED_SOURCE.put(store, txn, id, &())?;
    Ok(())
}
