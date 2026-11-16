//! A door to the counterparty contact family's own head writer (census
//! L6-21). It moves a contact's `counterparty_contact.*` heads and nothing
//! else, so an integration test can hold a live `counterparty_contact.opt_out`
//! head with no party `comm.opt_out` beside it: what a replica holds until the
//! party's head syncs, or a vault written before the family wrote that head.

use crate::Vault;
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Supersedes `contact_id`'s family heads with `record`'s, in one write
/// transaction, through the family's own head writer only: no party head and
/// no cache row.
///
/// # Errors
/// The family head writer's errors.
pub fn write_contact_family_heads(
    vault: &Vault,
    contact_id: &EntityId,
    record: &CounterpartyContactRecord,
    now: u64,
) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault.supersede_counterparty_contact_claim_heads_for_test(wtxn, contact_id, record, now)
    })
}
