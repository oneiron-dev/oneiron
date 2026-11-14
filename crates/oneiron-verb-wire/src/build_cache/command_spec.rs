//! Moved from `crates/oneiron/src/build_cache/command_spec.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::build_cache::command_spec::*;
use serde::Deserialize;
use serde::Serialize;
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
    pub fn engine_taint_refs(&self) -> Vec<oneiron_store::secret_lease::types::SecretTaintRef> {
        self.secret_taint_refs
            .iter()
            .map(|taint| oneiron_store::secret_lease::types::SecretTaintRef {
                secret_ref: taint.secret_ref.clone(),
                generation: taint.rotation_generation,
            })
            .collect()
    }
}
