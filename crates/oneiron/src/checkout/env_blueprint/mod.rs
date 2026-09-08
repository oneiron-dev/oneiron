//! Declarative per-repository environment blueprints for checkouts (CSTDY-07).
//!
//! Exactly one [`EnvBlueprint`] exists per commit-stripped canonical repository
//! identity. It declares three stage families — init, maintenance, and
//! knowledge — and persists as one versioned `vault_meta` row keyed by the
//! domain-separated BLAKE3 of that identity.
//!
//! This module declares and validates only. It never executes a step, resolves
//! a secret, or ingests knowledge: those remain the dispatch/sandbox owner's
//! and L1-SECRET's contracts.

mod blueprint;
mod values;

pub use self::blueprint::{
    CheckoutEnvPlan, ENV_BLUEPRINT_KEY_PREFIX, ENV_BLUEPRINT_REPO_KEY_DOMAIN,
    ENV_BLUEPRINT_SCHEMA_VERSION, EnvBlueprint, EnvBlueprintError, EnvBlueprintResult,
    EnvBlueprintStages, EnvBlueprintStore, EnvStep, EnvValue, KnowledgeInput, KnowledgeSourceSpec,
    MaterializationSpec, VaultEnvBlueprintStore, resolve_materialization,
};
pub use self::values::{EnvKey, EnvSecretRef, EnvStepId, RepoRelativeGlob, RepoRelativePath};

pub(crate) use self::blueprint::env_blueprint_repo_identity;

#[cfg(test)]
mod tests;

// The flat env_blueprint.rs module used to provide these names to the sibling
// test module through `use super::*`: the `values` names arrive via the public
// seam above, the `blueprint` remainder (including the row struct and the
// pub(crate) key/codec fns) via the glob below, plus the crate/std imports
// the tests relied on. After the directory split `tests.rs` resolves exactly
// as it did before.
#[cfg(test)]
use self::blueprint::*;
#[cfg(test)]
use super::lease::{CheckoutMaterializationOptions, CheckoutTaskClass};
#[cfg(test)]
use crate::batch::secret_scan::scan_file_content;
#[cfg(test)]
use crate::codebase::RepoRef;
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::vault::Vault;
#[cfg(test)]
use std::collections::BTreeMap;
