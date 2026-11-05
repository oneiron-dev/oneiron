//! Core half of `store::secret_handle_labels`: its store-layer items live in `oneiron_store::secret_handle_labels` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::secret_handle_labels::*;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use heed::RwTxn;
use serde::{Deserialize, Serialize};

/// One handle's owner-set label. Key: id16 (the custody record id).
pub(crate) const LABEL: SideTable<EntityId, SecretHandleLabel, Named> =
    SideTable::new(&side_table::SECRET_HANDLE_LABEL);

/// Drops the label on the custody record `custody`, whose row is being
/// erased: the label must not survive it.
pub(crate) fn erase_secret_handle_label_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    custody: &EntityId,
) -> Result<()> {
    LABEL.delete(store, wtxn, custody)?;
    Ok(())
}
