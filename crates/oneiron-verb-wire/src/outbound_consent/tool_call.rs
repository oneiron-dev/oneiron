//! Moved from `crates/oneiron/src/outbound_consent/tool_call.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_consent_state::connector_key::tool_remember::ConnectorToolRememberContext;
use oneiron_consent_state::consent::tool_scope::DataClass;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MutationIntent {
    #[default]
    Preview,
    ExplicitMutation,
}
