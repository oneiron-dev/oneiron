//! Door for `tests/delete_widens_values.rs`: lands a `comm.*` claim as
//! written on this node.
//!
//! The shipped manifest names no rule for most `comm.*` predicates, so each
//! falls to the critical default, and the criticality floor holds a `comm.*`
//! claim on the raw put door whatever approval it carries (`gate::confirm`:
//! the floor lift excludes `comm.*`). Only the projector and the typed comm
//! doors write the family, and none writes a `comm.reachable_via`. The
//! fixture lands each row through the reserved door, as a door that owns its
//! predicate's decision does. The delete doors under test read the stored
//! row, not how it landed.

use crate::claim::ClaimBody;
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault};

/// Puts `body`, a `comm.*` claim, under `id` on `vault`.
///
/// # Errors
///
/// A body under any other predicate, and the write's refusal.
pub fn put_comm_claim_row(
    vault: &Vault,
    id: &EntityId,
    body: &ClaimBody,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    if !body.predicate.starts_with("comm.") {
        return Err(Error::InvalidClaimBody(
            "the fixture door lands comm.* rows only",
        ));
    }
    vault.with_write_txn_grouped(|txn| {
        vault.put_reserved_claim_in_txn(txn, id, body, occurred, learned_at)
    })
}
