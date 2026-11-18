//! Default-hub workflow references and the loop's bootstrap skill roots, with
//! the existing derived fallback.

use crate::{EntityId, Result, Vault};

/// Reads the configured hub's installed holder and its current loadable head
/// in one snapshot. An absent holder or head keeps the derived reference.
/// The Coach's offer pass finds its library skill the same way.
pub(crate) fn workflow_default(vault: &Vault, name: &str) -> Result<EntityId> {
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

/// The root a loop pass walks for the shipped loop skill `name` (the
/// bootstrap set, ARCH-0053:273): the bootstrap id while its succession holds
/// a loadable revision, as before; else the least restored default of `name`
/// (restore defaults' fresh import) whose succession holds one; else the
/// bootstrap id, so the pass answers as before
/// (FIX BOOTSTRAP-SEED-ADDED-SKILL-MISSES-SEEDED-VAULTS).
pub(crate) fn bootstrap_skill_root_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<EntityId> {
    bootstrap_skill_root_sourced_in_txn(vault, txn, name).map(|(root, _)| root)
}

/// The same root, with its source rows: a known empty set while the
/// bootstrap id's own succession settles the root (the walk from it reports
/// its rows), unknown once the restored defaults were read, since that read
/// scans every skill row.
pub(crate) fn bootstrap_skill_root_sourced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<(EntityId, Option<Vec<EntityId>>)> {
    let seed = EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[name.as_bytes()],
    )?;
    if super::task_type_tree::skill_head_in_force_in_txn(vault, txn, seed)?.is_some() {
        return Ok((seed, Some(Vec::new())));
    }
    for restored in vault.restored_bootstrap_skills_in_txn(txn, name)? {
        if super::task_type_tree::skill_head_in_force_in_txn(vault, txn, restored)?.is_some() {
            return Ok((restored, None));
        }
    }
    Ok((seed, None))
}

/// The revision a pass loads for the shipped loop skill `name`: the in-force
/// head from [`bootstrap_skill_root_in_txn`]'s root, else that root, so a
/// load answers as before when no revision is loadable.
pub(crate) fn bootstrap_skill_in_force_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<EntityId> {
    let root = bootstrap_skill_root_in_txn(vault, txn, name)?;
    Ok(super::task_type_tree::skill_head_in_force_in_txn(vault, txn, root)?.unwrap_or(root))
}
