//! Moved from `crates/oneiron/src/verbs/secret_use.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::code_run::dispatcher::agent_verb::SecretUseAnswer;
pub use crate::code_run::dispatcher::agent_verb::SecretUseRecord;
pub use crate::code_run::dispatcher::agent_verb::SecretUseStatus;
use serde::Deserialize;
use serde::Serialize;

/// `self.use`'s input: the handle, the operation, and its arguments.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretUseRequest {
    /// The secret's handle, such as `sc12`, as the text or field holds it.
    pub handle: String,
    /// The operation, such as `slack.auth_test`.
    pub operation: String,
    /// The operation's arguments, a JSON object; `{}` for one that takes
    /// none.
    #[serde(default = "no_arguments")]
    pub arguments: serde_json::Value,
}

fn no_arguments() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}
