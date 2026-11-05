//! Core half of `store::secret_name_index`: its store-layer items live in `oneiron_store::secret_name_index` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::secret_name_index::*;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Result, SideTableRowProblem};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

/// Live secret name -> custody `EntityId` and the name's generation
/// high-water, keyed by the name itself. `run_bound` reads a run's names
/// and forgets them with their records (FIX 8028).
pub(crate) const NAME_INDEX: SideTable<String, NameEntry, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_NAME_INDEX);

/// Resolves a live secret name to its custody `EntityId` inside an
/// existing txn. `pub(crate)` for SECRET-02's lease doors (ONE-1920), which
/// hold their own write txn and must not open a nested read txn.
pub(crate) fn resolve_secret_ref_in_txn(
    store: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<Option<EntityId>> {
    Ok(NAME_INDEX
        .get(store, txn, &name.to_owned())?
        .map(|entry| entry.id))
}
