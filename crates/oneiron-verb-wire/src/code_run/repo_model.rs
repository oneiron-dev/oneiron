//! Moved from `crates/oneiron/src/code_run/repo_model.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// The content to serve on the attached run's registered model seat and line.
/// Model, actor, lease, scope and payer are always supplied by the host.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RepoModelGenerateInput {
    pub messages: Vec<oneiron_model::llm::LlmMessage>,
    #[serde(default)]
    pub tools: Vec<oneiron_model::llm::LlmToolSpec>,
    #[serde(default)]
    pub params: BTreeMap<String, Value>,
    #[serde(default)]
    pub provider_options: BTreeMap<String, Value>,
    pub response_format: oneiron_model::llm::ResponseFormat,
}
