//! Door for `tests/bootstrap_loop_skills.rs` (FIX
//! BOOTSTRAP-SEED-ADDED-SKILL-MISSES-SEEDED-VAULTS; ARCH-0053:273 the loop's
//! shipped skills version with the engine; BOOTSTRAP-SEED-ON-UPGRADE = A):
//! the shipped skills' seed ids, the heads two loop passes load, the fit
//! rung's activation of a restored default, and a later engine's seed pass.

use crate::error::Result;
use crate::{EntityId, Vault};

/// The seed id of the shipped skill `name` (its bootstrap id).
///
/// # Errors
///
/// Only an id derivation failure.
pub fn bootstrap_skill_id(name: &str) -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[name.as_bytes()],
    )
}

/// The skill whose rubric the judge loads (`judge_rubric_sourced_in_txn`),
/// or `None` when no rubric is in force.
///
/// # Errors
///
/// A store error.
pub fn judge_rubric_skill(vault: &Vault) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        crate::skill_optimize::labels::judge_rubric_sourced_in_txn(vault, &txn)?
            .0
            .map(|rubric| rubric.skill),
    )
}

/// The reviewer revision the agent-health pass loads its policy from, or
/// `None` when the pass runs on its compiled seeds.
///
/// # Errors
///
/// A store error.
pub fn agent_health_reviewer_revision(vault: &Vault) -> Result<Option<EntityId>> {
    vault.agent_health_reviewer_revision_for_test()
}

/// Admits the restored default `id` Active at `at`, as the fit rung does on
/// a held-out win that asks no permission (the scorer itself is skipped).
///
/// # Errors
///
/// As the admission write's: a missing record or a refused admission.
pub fn admit_restored_default(vault: &Vault, id: &EntityId, at: u64) -> Result<()> {
    vault.admit_restored_default_for_test(id, at)
}

/// Runs a later open's seed pass as an engine that ships the shipped skills
/// plus `extra` (each a name and its SKILL.md) would.
///
/// # Errors
///
/// As the seed pass's: a malformed SKILL.md or a refused import.
pub fn seed_bootstrap_skills_adding(
    vault: &Vault,
    extra: &[(&'static str, &'static str)],
) -> Result<()> {
    vault.seed_bootstrap_skills_adding_for_test(extra)
}
