//! Moved from `crates/oneiron/src/policy_model/enforce.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::verdict::PolicyVerdictCategory;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEnforcementVoice {
    Persona,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHelpRouting {
    pub category: PolicyVerdictCategory,
    pub message: String,
    pub diagnosis: Option<String>,
    pub persona_present: bool,
    /// Host-configured resources, not an engine-owned safety taxonomy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<oneiron_store::gate_decision::types::GateSystemNoticeAction>,
}
