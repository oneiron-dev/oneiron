//! Moved from `crates/oneiron/src/scope_summary/derivation.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::scope_summary::purpose::SummaryPurpose;
use serde::Deserialize;
use serde::Serialize;

/// An exact input version, including the document frontier and the full
/// witnessed-text pin (child set, authors, revisions and stream finality).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummarySourceVersion {
    pub id: String,
    pub entity_type: Option<u8>,
    pub learned_at: Option<u64>,
    pub revision: Option<[u8; 32]>,
    pub record_hash: Option<[u8; 32]>,
    pub frontier: Option<Vec<u8>>,
    pub projected_text: Option<[u8; 32]>,
}

/// Retained birth envelope: input content, instruction/model parameters,
/// request trigger, exact source versions and the prior artifact, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryDerivation {
    pub request: Vec<u8>,
    pub trigger: [u8; 16],
    pub content_hash: [u8; 32],
    pub params_hash: [u8; 32],
    pub instruction: String,
    pub model: String,
    pub policy_frontier: [u8; 32],
    pub sources: Vec<SummarySourceVersion>,
    pub previous: Option<String>,
    pub recorded_at: u64,
    pub generated_text_hash: [u8; 32],
    pub generated_keep_hash: [u8; 32],
    /// A session summary's source set (FIX 7509): its sitting and its TURNs,
    /// sorted and once each, under one domain-separated hash. `None` for
    /// every other summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_set: Option<[u8; 32]>,
    /// A session summary's lines as generated, each with the TURNs it came
    /// from (FIX 7509), bound to `generated_text_hash`: an edited body's
    /// lines are its editor's. `None` for every other summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_sources: Option<Vec<SummaryLineSources>>,
}

/// One line of a session summary as generated (FIX 7509): half-open Unicode
/// scalar offsets into the generated text, and the full ids of the TURNs the
/// line came from, each one the call read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryLineSources {
    pub output_start: usize,
    pub output_end: usize,
    pub turn_refs: Vec<String>,
    /// The exact slices a paged sitting's line cites by part (FIX 7509
    /// P7b), in citation order; empty, and not written, for a line citing
    /// whole TURNs only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_spans: Vec<SummaryLineSpan>,
}

/// One slice of a TURN a paged session summary's line came from (FIX 7509
/// P7b): byte offsets, MESSAGE-local when `message` is set, else into the
/// TURN's own text. The revisions those bytes were read at are the
/// derivation's `sources`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryLineSpan {
    pub turn: String,
    pub message: Option<String>,
    pub start: usize,
    pub end: usize,
}

/// The summary's own document metadata. `keep` is read before every generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeSummaryMetadata {
    pub purpose: SummaryPurpose,
    pub keep: String,
    pub derivation: SummaryDerivation,
}
