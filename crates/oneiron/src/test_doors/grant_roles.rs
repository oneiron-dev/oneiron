//! Door for `tests/grant_roles_seven.rs` (ROLES R1, the lead 11 Nov 11:38):
//! the default membership scope a vault's policy manifest gives a role, as
//! the minting writer resolves it.

use crate::error::Result;
use crate::federation::{FederationGrantRole, ScopeAxis};
use crate::{EntityId, Vault};

/// The verbs `role`'s membership grant starts with in `vault_id`, resolved
/// in one read as a membership mint resolves them. `None` when the verb axis
/// is unbounded (the Owner's).
pub fn default_membership_verbs(
    vault: &Vault,
    role: FederationGrantRole,
    vault_id: u64,
    holder: EntityId,
) -> Result<Option<Vec<String>>> {
    let txn = vault.store.env.read_txn()?;
    let scope = vault.grant_default_scope_in_txn(&txn, role, vault_id, holder)?;
    Ok(match scope.verbs {
        ScopeAxis::Some(verbs) => Some(verbs.into_iter().collect()),
        ScopeAxis::All => None,
        ScopeAxis::Bottom => Some(Vec::new()),
    })
}
