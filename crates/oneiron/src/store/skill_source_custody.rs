//! The source-custody index of a skill holder: the live, dead or unseen
//! state of each (holder, content hash) pair. The skill hub
//! (`skill_hub::source_custody`) stages and retires these rows; the store's
//! erase, replay and deletion-receipt paths test a holder and list its
//! carriers.
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;
use crate::store::skill_source_carrier::source_carrier_id;
use crate::write_envelope::skill_record::SkillContentHash;

/// Source-custody state for one (holder, content hash) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyState {
    Live,
    Dead,
    Unseen,
}

impl RawValue for CustodyState {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![match self {
            Self::Live => 0,
            Self::Dead => 1,
            Self::Unseen => 2,
        }])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [0] => Ok(Self::Live),
            [1] => Ok(Self::Dead),
            [2] => Ok(Self::Unseen),
            _ => Err(Error::CorruptedIndex("source custody index value").into()),
        }
    }
}

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
