//! Doors for `tests/world_access_local_authority.rs` and
//! `tests/world_access_owner_writer.rs`: one lands a world-access row as
//! written on this node (census L2-53); one revokes the owner's binding and
//! binds it again (census L2-56).
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

/// Revokes the host root's binding of `owner` and binds it again, as a host
/// that withdraws and then restores the owner's key does. The owner stays a
/// live owner, and a write it makes needs the authority frontier it observes
/// now: a row it wrote before, with no frontier, stays quarantined.
///
/// # Errors
///
/// No live binding of `owner` under the host root, and the authority log's.
pub fn revoke_and_rebind_host_owner(vault: &Vault, owner: EntityId) -> Result<()> {
    use crate::authority::{ActorBindingStatus, AuthorityOp};
    let issuer = crate::test_support::test_host_issuer();
    vault.bind_host_owner_for_test(&issuer, owner)?;
    let fold = vault.authority_fold()?;
    let epoch = fold
        .actor_bindings
        .get(&issuer.public_key())
        .filter(|binding| {
            binding.actor_ref == owner && binding.status == ActorBindingStatus::Active
        })
        .map(|binding| binding.epoch)
        .ok_or_else(|| Error::InvalidConfig("the host root binds no owner".into()))?;
    vault.log_host_op_for_test(
        &issuer,
        AuthorityOp::RevokeActor {
            authority_key: issuer.public_key(),
            epoch,
        },
    )?;
    vault.bind_host_owner_for_test(&issuer, owner)
}
