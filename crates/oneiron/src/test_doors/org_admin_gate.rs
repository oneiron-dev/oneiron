//! Door for `tests/org_admin_step_up.rs` (L7-17 PR 2): the gate an org
//! Admin power's door runs, for a writer that shows no step-up.

use crate::Vault;
use crate::error::Result;
use crate::federation::{OrgAdminPower, OrgAdminWriter};
use crate::write_envelope::WriteActor;

/// Whether `actor`, showing no step-up, may use `power` over shared vault
/// `vault_id` now.
pub fn admin_act_gate(
    vault: &Vault,
    vault_id: u64,
    actor: WriteActor,
    power: OrgAdminPower,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    vault.authorize_org_admin_act_in_txn(&txn, vault_id, &OrgAdminWriter::from(actor), power)
}
