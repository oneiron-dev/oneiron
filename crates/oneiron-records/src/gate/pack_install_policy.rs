//! Moved from `crates/oneiron/src/gate/pack_install_policy.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackInstallPrecedence {
    NestedNarrowingHolderCappedAtVault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePackInstallPolicy {
    pub hidden_instructions: Vec<String>,
    pub parameter_injection: Vec<String>,
    pub allowed_calls: BTreeSet<String>,
    pub known_bad_patterns: Vec<String>,
    pub removed_hashes: Vec<String>,
}

/// Owner policy changes are narrowings: additions to the refusal classes and
/// an optional subset of already-allowed analyzed calls. `holder_ref` scopes
/// this narrowing to one publisher; None narrows the entire vault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackInstallPolicyOverride {
    pub holder_ref: Option<String>,
    pub hidden_instruction_phrases: Vec<String>,
    pub parameter_description_phrases: Vec<String>,
    pub allowed_python_calls: Option<Vec<String>>,
    pub known_bad_patterns: Vec<String>,
    pub removed_hashes: Vec<String>,
}
