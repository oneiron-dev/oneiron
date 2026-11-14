//! Moved from `crates/oneiron/src/verbs/custody_drain.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::key_custody::protocol::drain::DrainAck;
use oneiron_store::key_custody::protocol::TargetScope;
use serde::Deserialize;
use serde::Serialize;
use std::path::PathBuf;
use zeroize::Zeroize;

/// `vault.custody.members.drain.begin`'s and `.drain.folder`'s input: one
/// member of the required set.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CustodyMemberRef {
    /// The member's id, `<kind>:<name>`, as the set names it.
    pub target_id: String,
}

/// `vault.custody.members.drain.commit`'s input: the member's ack of its
/// begun drain, as its adapter wrote it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CustodyDrainCommitRequest {
    #[schemars(with = "serde_json::Value")]
    pub ack: DrainAck,
}

/// `vault.custody.members.reenrol`'s input: the member the owner drained,
/// by its id (a hosted holder's, or `residence:<machine hex>`), or, for a
/// folder member, by its absolute folder on this install.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CustodyMemberReenrolRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// What a hosted holder keeps: `head_and_log` (when absent) or
    /// `log_only`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub scope: Option<TargetScope>,
}
