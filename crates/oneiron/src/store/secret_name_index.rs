//! The live secret name index: each live custody record's name, the record
//! it resolves to and the name's generation high-water. Custody's doors
//! write it (`secret_custody::doors`); the lease and rotation doors resolve
//! names through it.

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Result, SideTableRowProblem};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

/// Live secret name -> custody `EntityId` and the name's generation
/// high-water, keyed by the name itself. `run_bound` reads a run's names
/// and forgets them with their records (FIX 8028).
pub(crate) const NAME_INDEX: SideTable<String, NameEntry, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_NAME_INDEX);

/// One name's index row: the custody record the name resolves to, and the
/// highest `rotation_generation` a record has held under the name here. The
/// high-water outlives its record: a name whose record is gone from the store
/// starts its next life above it, never at the caller's number (FIX 5958).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NameEntry {
    pub(crate) id: EntityId,
    pub(crate) high_water: u32,
}

/// The record's id bytes, then the high-water as four big-endian bytes.
impl RawValue for NameEntry {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut raw = self.id.as_bytes().to_vec();
        raw.extend_from_slice(&self.high_water.to_be_bytes());
        Ok(raw)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let undecodable = || CodecError::Row(SideTableRowProblem::Undecodable);
        let (id, high_water) = bytes
            .split_at_checked(ENTITY_ID_LEN)
            .ok_or_else(undecodable)?;
        let high_water = <[u8; 4]>::try_from(high_water).map_err(|_| undecodable())?;
        Ok(Self {
            id: <EntityId as RawValue>::from_raw(id)?,
            high_water: u32::from_be_bytes(high_water),
        })
    }
}

/// Resolves a live secret name to its custody `EntityId` inside an
/// existing txn. `pub(crate)` for SECRET-02's lease doors (ONE-1920), which
/// hold their own write txn and must not open a nested read txn.
pub(crate) fn resolve_secret_ref_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<Option<EntityId>> {
    Ok(NAME_INDEX
        .get(store, txn, &name.to_owned())?
        .map(|entry| entry.id))
}
