//! Core half of `scope_summary::public_types`: its store-layer items live in `oneiron_store::scope_summary::public_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::scope_summary::public_types::*;

use crate::entity_doc::{Birth, ForkRecord, ProposalBundle, TextAnchor, TextReceipt};
use serde::{Deserialize, Serialize};

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
/// It names a conversation `scope` or NOTEs by id (`note_refs`), never both.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryCreateRequest {
    #[serde(default)]
    pub scope: Option<SummaryScope>,
    /// NOTEs to summarize, by id (FIX 5757): each one the caller reads. The
    /// summary stands alone, in no conversation, and lands on no turn.
    #[serde(default)]
    pub note_refs: Vec<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub land_on: Option<String>,
    #[serde(default)]
    pub as_record: bool,
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
