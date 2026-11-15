//! Moved from `crates/oneiron/src/blob_artifact/deck_doors.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_docedit::edit::transaction::Digest;
use oneiron_docedit::edit::transaction::IdMarks;
use oneiron_docedit::edit::wire::DeckIdentityAmbiguity;
use oneiron_docedit::edit::wire::DeckSlideInspection;
use oneiron_docedit::edit::wire::DeckTransactionRefusal;
use oneiron_docedit::pptx_comments::PptxInspection;
use oneiron_store::blob_artifact::deck_inspection::DeckRejectionInspection;
use serde::Deserialize;
use serde::Serialize;

/// One PPTX version to inspect: `version`, or the head when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckInspectRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub version: Option<u64>,
}

/// One PPTX version's native edit targets and, apart, its comment identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckInspectionView {
    pub artifact_id: EntityId,
    pub version: u64,
    /// BLAKE3 of this version's bytes: the `base` a transaction over it
    /// names. A transaction over an older version refuses `base_changed`.
    pub base: Digest,
    /// The deck's managed native-id history joined with the marks this
    /// version shows; a transaction's new ids go above them.
    pub marks: IdMarks,
    /// Every slide in presentation order, each shape with the content
    /// fingerprint a step's `expected` names. Duplicate ids are kept.
    pub slides: Vec<DeckSlideInspection>,
    /// Duplicate identity evidence, reported and never repaired.
    pub ambiguities: Vec<DeckIdentityAmbiguity>,
    /// The comment inspection. Its fingerprints are the comment writer's
    /// own hash (the one a slide review checks), not an edit's `expected`.
    pub comments: DeckCommentInspection,
}

/// The comment inspection of the same bytes, or why the comment inspector
/// refused a package the deck view read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeckCommentInspection {
    Inspected { inspection: PptxInspection },
    Refused { reason: String },
}

/// A refused deck transaction: the refusal by name, beside the base read as
/// a deck (FIX 4486) and the corruption-gate report the editor wrote for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckProposeRejection {
    pub inspection: DeckRejectionInspection,
    pub report: DeckRejectionReport,
    /// Why it refused: a `step` refusal names the step's index and verb and
    /// its canon refusal (`target_changed`, `ambiguous_anchor`, ...).
    pub refusal: DeckTransactionRefusal,
}

/// The corruption-gate report: `ok` is the conjunction of its checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckRejectionReport {
    pub ok: bool,
    pub checks: Vec<DeckRejectionCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckRejectionCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}
