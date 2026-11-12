//! Moved from `crates/oneiron/src/connector_key/slate_scope_signal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_consent_state::consent::tool_scope::DataClass;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The grant axis one call exceeded and what the call asked for on it: never
/// the payload, a header's value or a credential.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorScopeExceed {
    /// The endpoint the call resolved is not on the grant's allowlist.
    Endpoint { requested: String },
    /// The payload's class is above the grant's ceiling.
    PayloadClass {
        requested: DataClass,
        ceiling: DataClass,
    },
    /// The call carries a data class the grant does not let through:
    /// `arguments` or `x_mcp_header`.
    ToolDataClass { requested: String },
}

impl ConnectorScopeExceed {
    /// The exceeded axis's stable name.
    #[must_use]
    pub const fn axis(&self) -> &'static str {
        match self {
            Self::Endpoint { .. } => "endpoint",
            Self::PayloadClass { .. } => "payload_class",
            Self::ToolDataClass { .. } => "tool_data_class",
        }
    }

    /// What the call asked for on that axis.
    #[must_use]
    pub fn requested(&self) -> &str {
        match self {
            Self::Endpoint { requested } | Self::ToolDataClass { requested } => requested,
            Self::PayloadClass { requested, .. } => requested.as_str(),
        }
    }
}
