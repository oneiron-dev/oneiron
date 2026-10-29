//! A settle that says whose reply stands (FIX 4284): the settle a wait's
//! answerer makes when it has to tell its caller whether their reply is the
//! one every waiter is delivered. The comparison is the settle's own
//! put-if-absent, so two concurrent answers never both hear that their
//! reply stands. Delivery to the parked runs is [`ExecutorStorage::deliver_wait`]'s,
//! unchanged.

use super::{
    SETTLED, SETTLED_TAG, WaitDeliveries, WaitDelivery, deliver_wait_listing_in_txn,
    put_if_absent_routed, reply_text, settled_in_txn,
};
use crate::code_run::ExecutorStorage;
use crate::{EntityId, Error, Result};

impl WaitDeliveries<'_> {
    /// [`Self::deliver`] that says whether `reply` settled `wait_id`:
    /// `true` when this call's reply is the one its waiters are delivered,
    /// `false` when an earlier reply settled it first and stands. Beside it,
    /// the settled reply that stands.
    ///
    /// # Errors
    ///
    /// A reply that is not JSON, storage errors, and the typed unavailable
    /// of a settled reply an erase took.
    pub fn settle_reporting(
        &self,
        wait_id: EntityId,
        reply: &serde_json::Value,
        now_ms: u64,
    ) -> Result<(bool, WaitDelivery)> {
        let missing = || Error::InvariantViolation("a settled code-run wait has no row");
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault.with_write_txn_grouped(|txn| {
                let won = !SETTLED.contains(&vault.store, txn, &(SETTLED_TAG, wait_id))?;
                deliver_wait_listing_in_txn(vault, txn, wait_id, reply, None, now_ms)?;
                let settled = settled_in_txn(&vault.store, txn, wait_id)?.ok_or_else(missing)?;
                Ok((won, settled))
            }),
            ExecutorStorage::Session(binding) => {
                let fresh = WaitDelivery {
                    reply: reply_text(reply)?,
                    delivered_at_ms: now_ms,
                    source_rows: None,
                    erased: false,
                };
                let won = binding.answered(|| {
                    put_if_absent_routed(binding, &SETTLED, &(SETTLED_TAG, wait_id), &fresh)
                })?;
                self.storage.deliver_wait(wait_id, reply, None, now_ms)?;
                let settled = binding
                    .answered(|| {
                        binding
                            .session
                            .side_table_get(&SETTLED, &(SETTLED_TAG, wait_id))
                    })?
                    .ok_or_else(missing)?;
                Ok((won, settled))
            }
        }
    }
}
