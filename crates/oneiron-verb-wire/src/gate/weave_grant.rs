//! Moved from `crates/oneiron/src/gate/weave_grant.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A writer class an auto-weave Grant names: an agent or the system. The
/// gate admits only those two past Proposed
/// ([`landing_weave_grant_in_txn`]), so the door takes no human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AutoWeaveWriterClass {
    Agent,
    System,
}

/// `vault.consent.create_auto_weave_grant`'s input: the writer the Grant
/// names and the one scope it covers. Ids are 32 hex: an entity id, or for
/// `campaign` the campaign's 16-byte root attempt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AutoWeaveGrantRequest {
    /// The writer's entity id, as 32 hex.
    pub writer: String,
    /// The writer's actor class.
    pub writer_class: AutoWeaveWriterClass,
    /// One of `project`, `campaign` or `skill`.
    pub scope: String,
    /// The scope's id, as 32 hex.
    pub scope_id: String,
}
