//! Moved from `crates/oneiron/src/skill_hub/admission.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Durable ruling with both actual scores, exact consent, content and source.
/// IDs are canonical hex strings to keep this envelope transport-neutral.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HubAdmissionReceipt {
    pub receipt_id: String,
    pub candidate: String,
    pub content_hash: String,
    pub binding: String,
    pub consent_digest: String,
    pub publisher: String,
    pub publisher_grant: String,
    pub hub_id: String,
    pub hub_ref: String,
    pub evidence_skill: String,
    pub held_out_digest: String,
    pub held_out_count: usize,
    pub before: f32,
    pub after: f32,
    pub accepted: bool,
    /// Immutable revision of the skill that scored this candidate.
    pub judge_revision: String,
    /// Read projection of the replacement fence; original scores stay intact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displaced_by_revision: Option<String>,
    pub at: u64,
}
