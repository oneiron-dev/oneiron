//! Moved from `crates/oneiron/src/verbs/secret_grant.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `self.secrets.renew`'s spec: a fresh grant at the secret's current
/// generation, in the named grant's place.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantRenewRequest {
    /// The grant, as `self.secrets.materialize` answered it.
    pub grant: String,
    /// As [`SecretGrantMintRequest::ttl_secs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

/// `self.secrets.teardown`'s spec.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantTeardownRequest {
    /// The grant, as `self.secrets.materialize` answered it.
    pub grant: String,
}

/// `self.secrets.use`'s spec: `self.use`'s envelope with a grant in place of
/// the handle.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantUseRequest {
    /// The grant, as `self.secrets.materialize` answered it. A door grant
    /// for this operation, or for the connector `connector.call` names.
    pub grant: String,
    /// The operation, such as `slack.auth_test`, or `connector.call`.
    pub operation: String,
    /// The operation's arguments, a JSON object; `{}` for one that takes
    /// none. `connector.call` takes one connector call, as it takes it.
    #[serde(default = "no_arguments")]
    pub arguments: serde_json::Value,
}

fn no_arguments() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// A T2 grant's file: where it is and which project it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrantRegistration {
    pub path: String,
    pub project_id: String,
}
