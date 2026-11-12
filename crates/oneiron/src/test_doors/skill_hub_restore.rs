//! Door for `tests/gate_pins_authority_rechecks.rs` (OPUS-T0-F gate pins, G99):
//! the shipped-default step of the owner's restore. `Vault::restore_default_skills`
//! checks the owner, fetches the pinned first-hub library, then runs this step,
//! which checks the owner again and re-imports each missing or retired shipped
//! skill from the bytes embedded in the engine. The door skips only the
//! library fetch, so the pin runs offline.

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, TimeRange, Vault};

/// Restores the shipped (bootstrap) skills `owner` retired, as
/// `Vault::restore_default_skills` does after its library fetch. Returns the
/// fresh Candidate ids.
///
/// # Errors
///
/// As the restore's: an owner that is no longer live, a store error, or a
/// refused import.
pub fn restore_bootstrap_skills(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<Vec<EntityId>> {
    vault.restore_bootstrap_skills(owner, occurred, learned_at)
}
