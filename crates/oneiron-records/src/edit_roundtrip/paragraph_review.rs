//! Moved from `crates/oneiron/src/edit_roundtrip/paragraph_review.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_docedit::docx_body::DocxStoryScope;
use oneiron_store::model_decision::AnswerContract;
use oneiron_verb_wire::edit_roundtrip::slides_review::SlideReviewLabels;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::HashSet;

/// One answered paragraph, bound to its native comment and the exact source
/// version. Settlement keeps it with the consume-once receipt. Its hashes
/// are hex on a JSON wire (FIX 9342).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParagraphJudgment {
    /// The paragraph's stable block id: the comment's target.
    pub block: String,
    /// The actual native story, omitted for the main body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<DocxStoryScope>,
    /// Hash of the paragraph text the call read, which the comment quotes.
    #[serde(with = "oneiron_docedit::hex_digest")]
    pub text_hash: [u8; 32],
    /// The shared ladder's decision and receipt.
    pub decision: TypedDecision,
    /// The immutable primitive selected by the question version for this run.
    pub answer_contract: AnswerContract,
    pub comment: String,
    pub author: String,
    /// Runtime display words pinned so settle can recheck comment semantics.
    pub labels: SlideReviewLabels,
    #[serde(with = "oneiron_docedit::hex_digest")]
    pub frontier: [u8; 32],
    pub judged_version: Option<u64>,
    /// The document's live body when it was asked: an edit to it never
    /// exported withdraws the paragraphs it changed (FIX 2115).
    #[serde(default)]
    pub judged_live: Option<oneiron_store::typed_body::live_pin::LivePin>,
}
