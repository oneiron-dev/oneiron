//! Moved from `crates/oneiron/src/federation/pending_act.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::federation::pending_act::policy_change::SharedActPolicyChangeState;
use oneiron_base::error::Error;
use std::collections::BTreeSet;

/// The row an act without its own row resolves to.
pub const DEFAULT_ROW: &str = "_default";

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid shared-vault act".into())
}

pub fn key(prefix: &[u8], suffix: &str) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(suffix.as_bytes());
    key
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Whether an individual holder may request a stricter setting.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SharedActPrecedence {
    VaultOnly,
    HolderMayNarrow,
}

/// The request that carried a completed act's effect, claimed in that effect's
/// own linearizing write, and its receipt once the effect wrote one.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ActExecution {
    pub request: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
}
pub mod policy_change;
