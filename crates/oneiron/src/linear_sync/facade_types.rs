//! The wire shapes of the TASK ↔ issue mirror doors (OF-427 C6, C7):
//! `vault.tasks.linear.mapping`, `vault.tasks.linear.mapping.edit` and
//! `vault.tasks.linear.provenance`.

use serde::{Deserialize, Serialize};

use super::mirror_event::LinearMirrorEvent;
use super::model::{LinearFieldConflict, LinearIssueRef};

/// A provenance page's rows when the caller names no limit.
pub const LINEAR_PROVENANCE_PAGE_DEFAULT: u32 = 50;

/// The most rows one provenance page holds.
pub const LINEAR_PROVENANCE_PAGE_MAX: u32 = 200;

/// `vault.tasks.linear.mapping`'s input: the TASK named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearMappingRequest {
    pub task_ref: String,
}

/// One TASK's mirror mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LinearMappingView {
    pub task_ref: String,
    /// The TASK revision the mirror tracks: a `tasks.update` `edit` names it
    /// as its expected revision.
    pub task_revision: u64,
    /// The TASK's link, when it has one.
    pub link: Option<LinearLinkView>,
    /// Whether the scheduler pushes nothing for the TASK.
    pub opted_out: bool,
    /// The revision a mapping edit names as its expected one.
    pub mapping_revision: u64,
    /// The TASK revision waiting to be pushed, if any.
    pub dirty_revision: Option<u64>,
    /// The newest event rows of the TASK, newest first, as
    /// `vault.tasks.linear.provenance` names them.
    pub newest_event_refs: Vec<String>,
}

/// One TASK's durable link to its issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LinearLinkView {
    pub issue: LinearIssueRef,
    /// The link row's compare-and-set revision.
    pub link_revision: u64,
    /// Watermark: the TASK revision the link last observed.
    pub task_revision: u64,
    /// Watermark: the tracker `updated_at` the link last synchronized.
    pub issue_updated_at_ms: u64,
    /// Same-field edits the mirror refused to resolve.
    pub unresolved_conflicts: Vec<LinearFieldConflict>,
}

/// `vault.tasks.linear.mapping.edit`'s input: one mapping edit of one TASK
/// at the mapping revision the caller read, under its intent key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearMappingEdit {
    pub task_ref: String,
    pub expected_mapping_revision: u64,
    /// The same key with the same op answers the first edit's receipt.
    pub intent_key: String,
    pub op: LinearMappingOp,
}

/// One mapping edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinearMappingOp {
    /// Links an unlinked TASK to an issue of the configured tracker team
    /// that no other TASK links. The link has no common base, so every
    /// field that differs at the next inbound event is a conflict.
    Link {
        issue_id: String,
        identifier: String,
    },
    /// Removes the link and opts the TASK out of the mirror; the TASK, the
    /// issue and the history stay.
    Unlink,
    /// Opts an unlinked TASK back in; the next pass creates a fresh issue.
    Mirror,
}

impl LinearMappingOp {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Link { .. } => "link",
            Self::Unlink => "unlink",
            Self::Mirror => "mirror",
        }
    }
}

/// What one mapping edit did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LinearMappingEditReceipt {
    pub task_ref: String,
    /// `link`, `unlink` or `mirror`.
    pub op: String,
    /// The mapping revision the edit wrote.
    pub mapping_revision: u64,
    pub opted_out: bool,
    /// The issue linked or unlinked.
    pub issue: Option<LinearIssueRef>,
    /// The event row the edit is recorded under.
    pub event_ref: String,
    /// Whether this answers an already-recorded edit.
    pub replayed: bool,
    pub at: u64,
}

/// `vault.tasks.linear.provenance`'s input: the TASK, and where the page
/// resumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearProvenanceRequest {
    pub task_ref: String,
    /// The `next_cursor` of the page before.
    #[serde(default)]
    pub cursor: Option<String>,
    /// At most [`LINEAR_PROVENANCE_PAGE_MAX`]; [`LINEAR_PROVENANCE_PAGE_DEFAULT`]
    /// when absent.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One page of a TASK's mirror events, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LinearProvenancePage {
    pub task_ref: String,
    pub events: Vec<LinearProvenanceEntry>,
    /// Where the next page resumes; `None` when this one is the last.
    pub next_cursor: Option<String>,
}

/// One stored mirror event and its ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LinearProvenanceEntry {
    pub event_ref: String,
    pub event: LinearMirrorEvent,
}
