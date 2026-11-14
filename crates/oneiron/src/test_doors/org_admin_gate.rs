//! Door for `tests/org_admin_step_up.rs` (L7-17 PR 2): the gate an org
//! Admin power's door runs, for a writer that shows no step-up.
//!
//! RED SEAM: the base has no step-up, so its Admin doors run the shared
//! vault gate alone.

use crate::Vault;
use crate::error::Result;
use crate::federation::{OrgAdminPower, SharedVaultWrite};
use crate::write_envelope::WriteActor;

/// Whether `actor`, showing no step-up, may use `power` over shared vault
/// `vault_id` now.
pub fn admin_act_gate(
    vault: &Vault,
    vault_id: u64,
    actor: WriteActor,
    power: OrgAdminPower,
) -> Result<()> {
    vault.authorize_shared_vault_write(vault_id, &actor, &SharedVaultWrite::Admin(power))
}
