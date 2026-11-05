//! The native deck edit door's typed wire (DOOR-142 A, ARCH-0077 "Edit target
//! choice"): `vault.artifacts.inspect_deck`, the read an edit is addressed
//! from, and the typed rejection `vault.artifacts.propose_deck` answers a
//! refused transaction with.
//!
//! An inspection reads one version through the caller's file sight, as its
//! units do, and returns what the organ reads: each slide part and native
//! slide and shape id with the content fingerprints a transaction step
//! expects, every duplicate identity the deck view reports, the managed
//! native-id marks, and, apart, the comment inspection with its own
//! fingerprints. It mints no id and computes no fingerprint of its own.

use oneiron_docedit::edit::transaction::{Digest, IdMarks};
use oneiron_docedit::edit::wire::{
    DeckIdentityAmbiguity, DeckSlideInspection, DeckTransactionRefusal, inspect_deck,
};
use oneiron_docedit::pptx_comments::PptxInspection;
use oneiron_docedit::retained_opc::Package;
use serde::{Deserialize, Serialize};

use crate::blob_artifact::deck_inspection::DeckRejectionInspection;
use crate::blob_artifact::office_address::OfficeFormat;
use crate::entity_doc::document_resources::document_refused;
use crate::entity_doc::document_resources::document_resources;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

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
