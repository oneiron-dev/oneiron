//! A door for `tests/world_access_local_authority.rs`: lands one world-access
//! row as written on this node (census L2-53).
//!
//! The shipped manifest names no rule for either tier, so both fall to the
//! critical default, and the raw put door parks an Approved stamp that carries
//! no owner proof at the floor (`tests/owner_approval_criticality_floor.rs`).
//! An owner's grant is Approved, so the fixture lands each row through the
//! reserved door, as a door that owns its predicate's decision does. The
//! sync doors under test read the stored row, not how it landed.

use crate::claim::ClaimBody;
use crate::error::{Error, Result};
use crate::write_envelope::world_access_predicates::is_world_access_tier_predicate;
use crate::{EntityId, TimeRange, Vault};

/// Puts `body`, an ALLOWED-SET grant or a DEFAULT-SUBSET row, under `id` on
/// `vault`.
///
/// # Errors
///
/// A body under any other predicate, and the write's refusal.
pub fn put_world_access_row(
    vault: &Vault,
    id: &EntityId,
    body: &ClaimBody,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    if !is_world_access_tier_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "the fixture door lands world-access rows only",
        ));
    }
    vault.with_write_txn_grouped(|txn| {
        vault.put_reserved_claim_in_txn(txn, id, body, occurred, learned_at)
    })
}
