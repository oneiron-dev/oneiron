//! The owner-set labels on custody handles: one stored label per custody
//! record, with the Gate receipt of the set that wrote it. Custody's label
//! door (`secret_custody::handle_labels`) sets and reads them; an erase
//! drops a record's label with its row.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// One handle's owner-set label. Key: id16 (the custody record id).
pub(crate) const LABEL: SideTable<EntityId, SecretHandleLabel, Named> =
    SideTable::new(&side_table::SECRET_HANDLE_LABEL);

/// The stored owner-set label on one custody handle: the label text and the
/// Gate receipt of the set that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHandleLabel {
    pub label: String,
    pub receipt: String,
}

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
