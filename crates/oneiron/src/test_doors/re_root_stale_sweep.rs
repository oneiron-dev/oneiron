//! Doors for `tests/re_root_stale_sweep.rs` (L7-31): a foreign world
//! registered to a pact in a write that sweeps nothing, and the raw root move
//! [`crate::Vault::re_root_authority`] signed by the live host root.

use crate::Vault;
use crate::authority::{AuthorityLogEntry, HostSlipIssuer};
use crate::entity_id::ForeignWorldId;
use crate::error::Result;

/// Registers `world` as delivered by `pact_id`, as the sync lane does. The
/// write stages no authority row, so it runs no stale-stamp sweep unless one
/// is already owed.
///
/// # Errors
///
/// A storage error.
pub fn register_foreign_world_for_pact(
    vault: &Vault,
    pact_id: &[u8; 32],
    world: ForeignWorldId,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::federation::register_foreign_world_for_pact_in(vault, txn, pact_id, world)
    })
}

/// Moves the root from the live host root `current` to `next`'s key through
/// [`crate::Vault::re_root_authority`], and returns the signed move.
///
/// # Errors
///
/// As [`crate::Vault::re_root_authority`].
pub fn re_root_authority_as_host(
    vault: &Vault,
    current: &HostSlipIssuer,
    next: &HostSlipIssuer,
) -> Result<AuthorityLogEntry> {
    crate::authority::re_root_authority_as_host_for_test(vault, current, next)
}
