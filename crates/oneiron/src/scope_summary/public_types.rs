//! Typed SUMMARY doors over the retained scope-summary and entity-document APIs.

use crate::entity_doc::{Birth, ForkRecord, ProposalBundle, TextAnchor, TextReceipt};
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
#[serde(deny_unknown_fields)]
pub struct SummaryScope {
    pub conversation_ref: String,
    pub path: SummaryPath,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub include_forks: bool,
}

/// A declaration, never caller-composed SUMMARY text. The Dreamer supplies it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryCreateRequest {
    pub scope: SummaryScope,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub land_on: Option<String>,
    #[serde(default)]
    pub as_record: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SummaryQueued {
    pub attempt: String,
    pub status: String,
    pub coalesced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryStatusRequest {
    pub attempt: String,
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
pub struct SummaryReadView {
    pub summary_ref: String,
    pub document: String,
    pub frontier: Vec<u8>,
    pub text: String,
    pub metadata: super::ScopeSummaryMetadata,
    pub covers: Vec<String>,
    /// All retained source dependencies, including pending generated forks.
    pub read_refs: Vec<String>,
    pub anchors: Vec<TextAnchor>,
    pub birth: Birth,
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

/// Actor attribution comes from the calling credential, never this payload.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SummaryEdit {
    AppendToSection { section: TextAnchor, text: String },
    ReplaceQuotedSpan { span: TextAnchor, text: String },
    InsertAfterAnchor { anchor: TextAnchor, text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryEditRequest {
    pub summary_ref: String,
    pub base: Vec<u8>,
    pub edits: Vec<SummaryEdit>,
}

/// The generator must have read this keep memo before producing its anchored ops.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryPatchRequest {
    pub summary_ref: String,
    pub base: Vec<u8>,
    pub keep: String,
    pub edits: Vec<SummaryEdit>,
    pub read_refs: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SummaryForkView {
    pub record: ForkRecord,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SummaryProposalView {
    pub bundle: ProposalBundle,
    pub forks: Vec<SummaryForkView>,
    pub receipts: Vec<TextReceipt>,
}

/// The sources admitted by this invocation, not caller-asserted actor identities.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SummaryMutationResult {
    pub proposal: SummaryProposalView,
    pub read_refs: Vec<String>,
}
