//! Doors for `tests/history_import_source_sharing.rs` (L2-18): the rows a
//! history import landed, found by the source's own message id.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ingest::history::HistorySource;

/// The rows one imported message landed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportedMessageRows {
    pub conversation: EntityId,
    pub turn: EntityId,
    /// The MESSAGE its latest text still in the vault landed as.
    pub message: EntityId,
}

/// The rows the import of the message `native_id` of `source` landed;
/// `None` before an import landed it.
///
/// # Errors
///
/// Storage failures.
pub fn imported_message_rows(
    vault: &Vault,
    source: HistorySource,
    native_id: &str,
) -> Result<Option<ImportedMessageRows>> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        crate::ingest::history::landed_rows_in(&vault.store, &txn, source, native_id)?.map(
            |(conversation, turn, message)| ImportedMessageRows {
                conversation,
                turn,
                message,
            },
        ),
    )
}
