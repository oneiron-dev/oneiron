//! Moved from `crates/oneiron/src/llm/decision/questions/artifact_refresh.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::llm::decision::questions::records::*;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::llm::decision::questions::artifact_refresh::unit_receipts::ArtifactUnitReceipt;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::Duration;
use std::time::Instant;

/// Whether `units` names a selection a standing question can ask.
pub fn validate_artifact_units(units: &ArtifactUnits) -> Result<()> {
    Selection::resolve(&units.selection).map(|_| ())
}

/// One ask a standing artifact question made of one artifact, read back by its principal
/// (`vault.questions.answers`): the head it asked and where its answers stand. Every
/// logged ask stays (FIX 2337); a later ask of the same artifact replaces only an ask
/// stamped before asks were logged, which names no `ask_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAskRecord {
    pub artifact: EntityId,
    /// The question version that asked.
    pub question_version: u32,
    /// The artifact's head version the ask read.
    pub artifact_version: u64,
    pub asked_at: u64,
    /// The proposal its answers were held under for Keep; none when no unit was answered.
    #[serde(default)]
    pub proposal_ref: Option<String>,
    pub standing: ArtifactAskStanding,
    /// The logged ask's own id; none on an ask stamped before asks were logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_id: Option<EntityId>,
    /// The kind of error that stopped a failed ask, which held nothing, by its stable
    /// wire name (FIX 9177); none when the ask completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
    /// For a wake's re-ask of withdrawn answers, the proposal they were withdrawn from
    /// (FIX 9174); none for the question's own ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_proposal_ref: Option<String>,
    /// Whether this ask was logged with its ref details left out (FIX 9419): its refs
    /// did not pass the secret scan, so it names no proposal, and a completed one's
    /// standing is [`ArtifactAskStanding::DetailsOmitted`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub details_omitted: bool,
    /// Every unit the ask left without an answer, with its receipt (FIX 9913),
    /// whether or not it held a proposal; an answered unit's decision rides
    /// the proposal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<ArtifactUnitReceipt>,
    /// First selected sheet row left unfinished; this ask did not cover
    /// the whole selection. No receipt is invented for the suffix.
    pub next_sheet_row: Option<u32>,
}

/// Where one artifact ask's answers stand, by the same walk the next ask's baseline takes:
/// the ask's own proposal and every wake's re-ask of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ArtifactAskStanding {
    /// No unit was answered, so nothing was held.
    Unanswered,
    /// The proposal, or a wake's re-ask of it, waits for Keep.
    Waiting,
    /// Nothing waits, and a Keep of the proposal or of a re-ask moved the artifact to
    /// `version`.
    Kept { version: u64 },
    /// Nothing waits and no Keep moved the artifact: the answers were discarded, or an edit
    /// withdrew them.
    Closed,
    /// The ask failed and held nothing (FIX 9177): the record's `failed` names its error's
    /// kind. A completed ask that answered no unit is [`Self::Unanswered`].
    Failed,
    /// The ask was logged with its ref details left out (FIX 9419): it names no proposal,
    /// so where its answers stand is not read here.
    DetailsOmitted,
}
