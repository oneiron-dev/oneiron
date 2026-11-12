//! Moved from `crates/oneiron/src/source_audience/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// What one change to a policy's readers did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceAudienceOp {
    /// A source's readers were set (connect, or a group's members edited).
    ReaderAdded,
    ReaderRemoved,
    /// A thread was shared with a person by an explicit act.
    Shared,
    /// A thread's share with a person was withdrawn.
    Unshared,
    /// A source was stood open to the vault, or closed again.
    Opened,
    Closed,
}

/// One change to a policy's readers, as its receipt list shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAudienceEventView {
    pub revision: u64,
    pub op: SourceAudienceOp,
    /// The person the change names, 32-hex; absent for an open or a close,
    /// or once that person was erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_ref: Option<String>,
    /// Who made the change, 32-hex; absent once that actor was erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_ref: Option<String>,
    pub at: u64,
}
