//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/identity/evidence.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::maintenance::identity::MentionProvenance;
use crate::tagging::verbs::DerivationEnvelopeView;
use crate::tagging::verbs::TaggedMentionView;
use serde::Deserialize;
use serde::Serialize;

/// The existing owner choice, with the later records that support it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityAnswerEvidenceRequest {
    pub ask: String,
    pub choice: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMentionState {
    Unresolved,
    Candidates,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityResolutionView {
    /// The ask answered, or the same span key for a saved context-hint resolution.
    pub ask: String,
    pub target_ref: String,
    pub source: String,
    /// Present only when the resolution's transaction revalidated an owner proof.
    pub owner_ref: Option<String>,
    pub owner_evidence_refs: Vec<String>,
    pub resolved_at: u64,
    /// The mention before resolution: its span, candidates and model confidences.
    pub original: TaggedMentionView,
    pub original_provenance: DerivationEnvelopeView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityMentionView {
    pub mention: MentionProvenance,
    pub name: String,
    pub state: IdentityMentionState,
    pub candidate_refs: Vec<String>,
    pub target_ref: Option<String>,
    pub current: TaggedMentionView,
    pub provenance: DerivationEnvelopeView,
    pub resolution: Option<IdentityResolutionView>,
}
