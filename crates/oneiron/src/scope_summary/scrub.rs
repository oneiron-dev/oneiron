//! A withdrawn scope-summary copy's words leave this device (FIX 931, FIX
//! 11804). A reply TURN copies its scope summary's words; once a withdrawal
//! marks it stale, it takes the withdrawn record's Shell
//! ([`crate::deletion::scrub_withdrawn_record_in_txn`]). The summary keeps
//! its editor history, and its merge.summary CLAIM holds refs only, so
//! neither is scrubbed here.

use super::codec::reply_summary;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::Store;

/// Scrubs `id`, just withdrawn, when it is a reply TURN that copies a scope
/// summary's words; whether it scrubbed. Any other row, or a TURN whose body
/// does not decode as a reply, is left as it is.
pub(crate) fn scrub_withdrawn_copy_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(false);
    };
    if row.entity_type != ENTITY_TYPE_TURN || !matches!(reply_summary(&row.body), Ok(Some(_))) {
        return Ok(false);
    }
    crate::deletion::scrub_withdrawn_record_in_txn(store, txn, id)
}
