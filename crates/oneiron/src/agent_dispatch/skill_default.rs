//! Default-hub workflow references, with the existing derived fallback.

use crate::{EntityId, Result, Vault};

/// Reads the configured hub's installed holder and its current loadable head
/// in one snapshot. An absent holder or head keeps the derived reference.
pub(super) fn workflow_default(vault: &Vault, name: &str) -> Result<EntityId> {
    let fallback = || {
        EntityId::derive(
            crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
            &[name.as_bytes()],
        )
    };
    let txn = vault.store.env.read_txn()?;
    let Some(root) = vault.default_hub_skill_in_txn(&txn, name)? else {
        return fallback();
    };
    match super::task_type_tree::skill_head_in_force_in_txn(vault, &txn, root)? {
        Some(head) => Ok(head),
        None => fallback(),
    }
}
