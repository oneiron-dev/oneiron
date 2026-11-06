//! Receipt capture and its final reporter witness share the native filing writer.

use super::{BlockedReplaySource, SOURCE, ownership};
use crate::{EntityId, Result, Vault};

pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &EntityId,
    source: &BlockedReplaySource,
) -> Result<()> {
    let stored = SOURCE.put_as_stored(vault, txn, receipt, source)?;
    let stored = SOURCE.decode_value(&stored)?;
    ownership::replace_receipt_reporter_in_txn(&vault.store, txn, receipt, stored.reporter)
}
