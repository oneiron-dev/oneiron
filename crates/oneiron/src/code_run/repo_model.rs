//! Request content for an attached run's real model invocation (FIX 7176).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The content to serve on the attached run's registered model seat and line.
/// Model, actor, lease, scope and payer are always supplied by the host.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RepoModelGenerateInput {
    pub messages: Vec<crate::LlmMessage>,
    #[serde(default)]
    pub tools: Vec<crate::LlmToolSpec>,
    #[serde(default)]
    pub params: BTreeMap<String, Value>,
    #[serde(default)]
    pub provider_options: BTreeMap<String, Value>,
    pub response_format: crate::ResponseFormat,
}
