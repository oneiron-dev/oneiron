//! Plants an undecodable CALL_RECEIPT row for
//! `tests/agent_health_calls_drops_unread.rs`: the row sits past the write
//! door's validation, so the agent-health call reads meet it as store
//! damage.

use crate::receipt::CallReceipt;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

/// Stores `body` as the CALL_RECEIPT row `id`, past the write door's
/// validation. A body the codec never produces does not decode, so the
/// call reads meet it as a receipt that did not read.
///
/// # Errors
///
/// The store refuses the write.
pub fn put_undecodable_call_receipt(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    vault.with_write_txn(|txn| CALL_RECEIPTS.put_undecodable(&vault.store, txn, id, body))
}
