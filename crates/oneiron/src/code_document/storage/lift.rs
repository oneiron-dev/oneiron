//! Code documents the historical lift sweep reads again (OF-067, Engine
//! ruling G2 = b). A new edit that brings a key into a clean file is
//! refused; a file that held one before keeps it, and its frontiers and
//! receipts bind what each operation wrote. The sweep marks the keys of each
//! stored text, as the batch door marks a file's (owner ruling C2): the live
//! head, each tested frontier and each operation's edit. Every text, op and
//! hash stays as it is. A reader other than the owner reads each lifted key
//! as its handle (`Memory::lifted_view`), and an edit of a file whose text
//! was lifted marks the text it leaves, its keys keeping their records.

use heed::{RoTxn, RwTxn};

use super::{
    CODE_DOCUMENT_FRONTIER, CODE_DOCUMENT_HEAD, CODE_DOCUMENT_INGRESS, checked_snapshot,
    load_frontier,
};
use crate::Vault;
use crate::batch::secret_scan::{LiftedKeys, mark_carrier_texts_in_txn};
use crate::code_document::{CodeDocumentFrontier, CodeFileEdit};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table;
use crate::store::Store;

/// One family of a code document's stored rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodeDocumentRows {
    /// The live head: its text and every operation's edit.
    Head,
    /// One tested frontier's text.
    Frontier,
    /// One ingress receipt's edit.
    Ingress,
}

/// The texts one stored row of `rows` holds, by its key after the table's
/// prefix; none for a row that is gone or a key no row of it has.
pub(crate) fn code_document_texts_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    rows: CodeDocumentRows,
    key: &[u8],
) -> Result<Vec<String>> {
    let mut texts = Vec::new();
    match rows {
        CodeDocumentRows::Head => {
            let Ok(id) = <[u8; 32]>::try_from(key) else {
                return Ok(texts);
            };
            let Some(row) = CODE_DOCUMENT_HEAD.get(store, txn, &id)? else {
                return Ok(texts);
            };
            texts.push(checked_snapshot(&row.state)?.get_text("body").to_string());
            for receipt in &row.receipts {
                edit_texts(&receipt.edit, &mut texts);
            }
        }
        CodeDocumentRows::Frontier => {
            let (Some(document), Some(fold)) = (
                key.get(..32).and_then(|id| <[u8; 32]>::try_from(id).ok()),
                key.get(32..)
                    .and_then(|fold| <[u8; 32]>::try_from(fold).ok()),
            ) else {
                return Ok(texts);
            };
            let Some(row) = CODE_DOCUMENT_FRONTIER.get(store, txn, &(document, fold))? else {
                return Ok(texts);
            };
            texts.push(checked_snapshot(&row)?.get_text("body").to_string());
        }
        CodeDocumentRows::Ingress => {
            let Some(operation) = <[u8; 16]>::try_from(key)
                .ok()
                .and_then(|id| EntityId::from_bytes(id).ok())
            else {
                return Ok(texts);
            };
            let Some(row) = CODE_DOCUMENT_INGRESS.get(store, txn, &operation)? else {
                return Ok(texts);
            };
            edit_texts(&row.edit, &mut texts);
        }
    }
    Ok(texts)
}

fn edit_texts(edit: &CodeFileEdit, texts: &mut Vec<String>) {
    for text in [&edit.expected, &edit.replacement] {
        if !text.is_empty() {
            texts.push(text.clone());
        }
    }
}

/// After an edit of the document `document` the write door let stand
/// because the file read as secret before it: the text it leaves (`after`)
/// is marked, each lifted value keeping its record.
pub(super) fn remark_code_document_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    document: &[u8; 32],
    after: &str,
) -> Result<()> {
    mark_carrier_texts_in_txn(
        vault,
        txn,
        &side_table::CODE_DOCUMENT_HEAD,
        document,
        &[after.to_owned()],
    )?;
    Ok(())
}

impl Vault {
    /// The keys the lifted texts of the tested states `frontiers` hold.
    pub(crate) fn code_document_lifted_keys(
        &self,
        frontiers: &[&CodeDocumentFrontier],
    ) -> Result<LiftedKeys> {
        let txn = self.store.env.read_txn()?;
        let mut texts = Vec::with_capacity(frontiers.len());
        for frontier in frontiers {
            texts.push(
                load_frontier(&self.store, &txn, frontier)?
                    .get_text("body")
                    .to_string(),
            );
        }
        LiftedKeys::of_in_txn(&self.store, &txn, texts)
    }
}
