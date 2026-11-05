//! The owner-set labels on custody handles: one stored label per custody
//! record, with the Gate receipt of the set that wrote it. Custody's label
//! door (`secret_custody::handle_labels`) sets and reads them; an erase
//! drops a record's label with its row.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The stored owner-set label on one custody handle: the label text and the
/// Gate receipt of the set that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHandleLabel {
    pub label: String,
    pub receipt: String,
}
