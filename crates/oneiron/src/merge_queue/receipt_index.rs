//! Keyed reads of the checker's receipts (FIX 7349): a reused, bound or
//! sealed receipt is found through one index row by its inputs digest and
//! verdict, never by a scan of every work row and its exhaust. The rows are
//! written in the writer that saves the work row; a reader reads each named
//! work row whole and judges its receipts.
use std::collections::BTreeSet;

use super::check_inputs::QueueCheckReceipt;
use super::check_store::{CHECK_WORK, QueueCheckWork};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// One row per receipt. Key: hex(repo identity) ":" inputs digest ":"
/// verdict ref (empty for none) ":" hex64(request digest).
const RECEIPT_INDEX: SideTable<String, (), Named> =
    SideTable::new(&side_table::MERGE_QUEUE_RECEIPT_INDEX);

/// Writes the index rows of `work`'s receipts in `txn`; a row already
/// there is put again unchanged.
///
/// # Errors
/// A store failure.
pub(super) fn put_receipt_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    work: &QueueCheckWork,
) -> Result<()> {
    for receipt in &work.receipts {
        let key = format!(
            "{}{}",
            index_prefix(
                &work.store,
                &receipt.inputs_digest,
                Some(receipt.verdict_ref.as_deref())
            ),
            work.work_ref()
        );
        RECEIPT_INDEX.put(store, txn, &key, &())?;
    }
    Ok(())
}

fn index_prefix(store: &str, digest: &str, verdict: Option<Option<&str>>) -> String {
    match verdict {
        Some(verdict) => format!("{store}:{digest}:{}:", verdict.unwrap_or_default()),
        None => format!("{store}:{digest}:"),
    }
}

/// The receipts of `store`'s work rows the index files under `digest`, and
/// under `verdict` when it is given (`Some(None)`: a receipt with no
/// verdict), read in `txn`: each work row in key order, its receipts
/// oldest first. Only receipts of that digest are answered.
///
/// # Errors
/// A store failure.
pub(super) fn indexed_receipts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    repo_hex: &str,
    digest: &str,
    verdict: Option<Option<&str>>,
) -> Result<Vec<QueueCheckReceipt>> {
    let prefix = index_prefix(repo_hex, digest, verdict);
    let works: BTreeSet<String> = RECEIPT_INDEX
        .scan_keys(store, txn, prefix.as_bytes())?
        .into_iter()
        .filter_map(|key| {
            key.rsplit_once(':')
                .map(|(_, work)| format!("{repo_hex}:{work}"))
        })
        .collect();
    let mut receipts = Vec::new();
    for key in works {
        if let Some(work) = CHECK_WORK.get(store, txn, &key)? {
            receipts.extend(
                work.receipts
                    .into_iter()
                    .filter(|receipt| receipt.inputs_digest == digest),
            );
        }
    }
    Ok(receipts)
}
