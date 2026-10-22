//! A document's text index when the repo blob its row stands for is masked
//! again (FIX 7608 slice 3): the document's fields are indexed again as
//! their copy, through the same door its birth indexed them by. Its
//! persistence, history and generation stay as they are.

use heed::RwTxn;

use crate::error::Result;
use crate::{EntityId, Vault};

/// Indexes record `entity`'s document text again, its fields read as their
/// repo copies; nothing for a record that owns no document.
///
/// # Errors
/// A store failure, or the text index's.
pub(crate) fn reindex_repo_document_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    if !super::has_record_head(&vault.store, txn, entity)? {
        return Ok(());
    }
    let h = super::head(&vault.store, txn, entity)?;
    let doc = super::load(&vault.store, txn, &h)?;
    super::index_document(vault, txn, entity, &h, &doc)
}
