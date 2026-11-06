//! Typed SUMMARY doors over the retained scope-summary and entity-document APIs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SummaryPath {
    Canonical,
    Branch(String),
    BranchSpan { after: String, through: String },
    SubSession(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SummaryQueued {
    pub attempt: String,
    pub status: String,
    pub coalesced: bool,
}

/// Names exactly one: a summary declaration's `attempt`, or a sitting by
/// `session_ref`, whose close queued its summary (FIX 7509). A sitting's
/// summary is read by that sitting's own actor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryStatusRequest {
    #[serde(default)]
    pub attempt: Option<String>,
    #[serde(default)]
    pub session_ref: Option<String>,
}

/// Half-open Unicode scalar offsets, used only to acquire stable cursors.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummarySpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryReadRequest {
    pub summary_ref: String,
    #[serde(default)]
    pub spans: Vec<SummarySpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryKeepRequest {
    pub summary_ref: String,
    pub frontier: Vec<u8>,
    pub keep: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SummaryKeepResult {
    pub summary_ref: String,
    pub frontier: Vec<u8>,
    pub keep: String,
}

/// A declared rewrite always opens a fork; it cannot implicitly switch heads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryRegenerateRequest {
    pub summary_ref: String,
    pub base: Vec<u8>,
    pub keep: String,
    pub text: String,
    pub read_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryProposalRequest {
    pub proposal_ref: String,
}
