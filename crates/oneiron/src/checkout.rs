pub mod lease;
pub use lease::*;
#[cfg(test)]
mod tests;

pub mod env_blueprint;

pub use env_blueprint::{
    CheckoutEnvPlan, EnvBlueprint, EnvBlueprintError, EnvBlueprintResult, EnvBlueprintStages,
    EnvBlueprintStore, EnvKey, EnvSecretRef, EnvStep, EnvStepId, EnvValue, KnowledgeInput,
    KnowledgeSourceSpec, MaterializationSpec, RepoRelativeGlob, RepoRelativePath,
    VaultEnvBlueprintStore, resolve_materialization,
};

/// The single checkout→blueprint consult point. It does not materialize a repo,
/// resolve secret bytes, run a step, or ingest knowledge.
///
/// With no blueprint row this is the unchanged ONE-1901 path: it returns
/// `CheckoutEnvPlan::legacy()` after exactly one store read.
pub fn resolve_checkout_environment<S: EnvBlueprintStore>(
    store: &S,
    lease: &CheckoutLeaseAct,
) -> EnvBlueprintResult<CheckoutEnvPlan> {
    let Some(blueprint) = store.get(&lease.repo_ref)? else {
        return Ok(CheckoutEnvPlan::legacy());
    };
    let blueprint_identity = env_blueprint::env_blueprint_repo_identity(&blueprint.repo_ref);
    let lease_identity = env_blueprint::env_blueprint_repo_identity(&lease.repo_ref);
    if blueprint_identity != lease_identity {
        return Err(EnvBlueprintError::RepoKeyMismatch);
    }
    blueprint.checkout_plan(lease.task_class)
}
