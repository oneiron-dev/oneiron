//! Moved from `crates/oneiron/src/outbound_consent/connector_call_types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::outbound_consent::tool_call::MutationIntent;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Which interface a served connector call or schema read selects. This
/// chooses a route, never a credential, grant or approved manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSource {
    Catalog,
    Builtin,
}

impl ConnectorSource {
    /// An omitted choice keeps the served door's implicit name selection.
    #[must_use]
    pub fn resolve(source: Option<Self>, name: &str) -> Self {
        source.unwrap_or_else(|| {
            if name == oneiron_store::settings::web_connector::WEB_CONNECTOR_NAME {
                Self::Builtin
            } else {
                Self::Catalog
            }
        })
    }
}

/// One connector call and its arguments. It carries no endpoint,
/// credential, schema, grant or principal: the engine and host resolve
/// those beneath the name. Native catalog-only calls do not serve builtins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCallRequest {
    /// The connector's name within the selected source.
    pub name: String,
    /// Explicit catalog or builtin selection at a served door. When absent,
    /// a served `web` call selects the builtin; other names select catalog.
    /// Native catalog-only calls accept catalog or no explicit selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ConnectorSource>,
    /// The tool, as the connector's approved manifest names it.
    pub tool: String,
    /// The tool's arguments, a JSON object.
    #[serde(default = "empty_arguments")]
    pub arguments: Value,
    /// Preview (the default) or an explicit mutation.
    #[serde(default)]
    pub mutation: MutationIntent,
}

pub fn empty_arguments() -> Value {
    Value::Object(serde_json::Map::new())
}
