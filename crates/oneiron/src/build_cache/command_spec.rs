//! Core half of `build_cache::command_spec`: its store-layer items live in `oneiron_store::build_cache::command_spec` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::build_cache::command_spec::*;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeBuildSpec {
    /// Native, owner-authorized build command. No shell or inherited environment is added.
    pub argv: Vec<String>,
    pub env_allowlist: BTreeMap<String, String>,
    /// Pin the toolchain and platform inputs here; undeclared outside state is not proved.
    pub platform: BTreeMap<String, String>,
    pub declared_outputs: Vec<String>,
    /// Declared consumption taint only. This call neither reveals nor injects a secret.
    pub secret_taint_refs: Vec<CodeSecretTaintRef>,
    pub class: CodeBuildClass,
}

impl CodeBuildSpec {
    pub(crate) fn engine_taint_refs(&self) -> Vec<crate::secret_lease::SecretTaintRef> {
        self.secret_taint_refs
            .iter()
            .map(|taint| crate::secret_lease::SecretTaintRef {
                secret_ref: taint.secret_ref.clone(),
                generation: taint.rotation_generation,
            })
            .collect()
    }
}
