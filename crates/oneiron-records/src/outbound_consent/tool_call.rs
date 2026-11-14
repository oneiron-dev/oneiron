//! Moved from `crates/oneiron/src/outbound_consent/tool_call.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::consent::tool_scope::ToolGrantDataClass;
use oneiron_base::error::Error;
pub use oneiron_verb_wire::outbound_consent::tool_call::MutationIntent;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderGrantRequirement {
    pub parameter: String,
    pub header: String,
    pub data_class: ToolGrantDataClass,
}

pub fn invalid_schema() -> Error {
    Error::InvalidConfig("tool schema or resolved header parameters are invalid".into())
}
