//! Deck outline keeps, design records, emission inputs and outcomes.

use std::collections::BTreeMap;

use oneiron_docedit::design_plan::CompileError;
use oneiron_docedit::emit::{EmitError, Names};
use oneiron_docedit::fonts::FontError;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Error;
use crate::write_envelope::WriteActor;
use crate::write_envelope::provenance::made_by::MadeByTrigger;

/// One blob artifact version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactVersionRef {
    pub artifact: EntityId,
    pub version: u64,
}

/// A person's keep of an outline: the frontier, the exact outline bytes with
/// drift mapped at keep, and their hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeptOutline {
    pub note: EntityId,
    pub frontier: Vec<u8>,
    /// The kept version as the design plan binds it: the frontier in hex.
    pub version: String,
    pub bytes: Vec<u8>,
    pub content_hash: [u8; 32],
    pub kept_by: EntityId,
    pub kept_at: u64,
    /// What the engine observed of each pin it can address at the keep,
    /// outside the bytes and their hash (FIX 9813, 9814).
    #[serde(default)]
    pub evidence: Vec<EvidenceObservation>,
}

/// Whether a keep still describes its outline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutlineFreshness {
    Fresh,
    NotKept,
    /// The note changed after the keep.
    Edited,
    /// Cited evidence moved: these pins, in document order, map differently.
    EvidenceMoved {
        pins: Vec<usize>,
    },
}

/// A cited CLAIM's lifecycle as the engine observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CitedClaimLifecycle {
    Active,
    Superseded,
    Retracted,
}

/// What the engine observed of one evidence pin it can address: a note
/// document span, with or without a cited CLAIM (FIX 9813, 9814).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceObservation {
    /// The pin, in document order, as [`OutlineFreshness::EvidenceMoved`]
    /// counts them.
    pub pin: usize,
    /// The cited document's frontier; `None` once it no longer resolves.
    pub source_frontier: Option<Vec<u8>>,
    /// The cited CLAIM's lifecycle; `None` when the pin names none or it no
    /// longer reads.
    pub lifecycle: Option<CitedClaimLifecycle>,
    /// Whether the span still maps onto live characters with its quote.
    pub mapped: bool,
}

/// One pin whose evidence changed since the keep: what the keep saw, and
/// what the engine sees now. It is reported, never a keep to make again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceChange {
    pub kept: EvidenceObservation,
    pub now: EvidenceObservation,
}

/// One design direction: a template and what the kept outline becomes on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignDirection {
    pub template: ArtifactVersionRef,
    /// BLAKE3 of the template version's bytes.
    pub template_hash: [u8; 32],
    pub outcome: DirectionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectionOutcome {
    Plan {
        slides: Vec<DirectionSlide>,
        /// Optional blocks the plan leaves out.
        omitted: Vec<String>,
        /// Estimates a real face measured, and those the em rule made.
        measured: usize,
        estimated: usize,
    },
    /// Pages no layout rung holds: another template or a design change.
    Ask { pages: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DirectionSlide {
    pub page: String,
    pub layout: String,
    /// The ladder step that made the slide; `None` is the capability match.
    pub fallback: Option<String>,
}

/// The design spec linked to one kept outline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignSpec {
    pub note: EntityId,
    /// The keep the directions were compiled from.
    pub content_hash: [u8; 32],
    pub directions: Vec<DesignDirection>,
}

/// The receipt of one created deck.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckCreationRecord {
    pub artifact: EntityId,
    pub version: u64,
    pub content_hash: [u8; 32],
    /// Born-from: the kept outline.
    pub outline: EntityId,
    pub outline_version: String,
    pub outline_hash: [u8; 32],
    pub template: ArtifactVersionRef,
    pub template_hash: [u8; 32],
    /// Bound image inputs, keyed by the outline's asset id.
    pub asset_inputs: BTreeMap<String, CreatedInput>,
    /// Font inputs loaded for layout, not proof that each face was used.
    pub font_inputs: Vec<CreatedInput>,
    pub run_ref: String,
    pub made_by: Option<EntityId>,
    pub slides: Vec<CreatedSlide>,
    pub write_set: Vec<String>,
    pub omitted: Vec<String>,
    /// Units whose fit emission cannot decide: `(slide, block, shape)`.
    pub fit_unverified: Vec<(String, String, u32)>,
    pub estimates: Vec<CreatedEstimate>,
    pub created_at: u64,
}

/// One pinned creation input's stored identity and provenance kind.
/// This records the input, not its license or permission for reuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CreatedInput {
    pub source: ArtifactVersionRef,
    pub content_hash: [u8; 32],
    pub provenance_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CreatedSlide {
    pub part: String,
    pub sld_id: u32,
    pub page: String,
    pub layout: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CreatedEstimate {
    pub block: String,
    pub need: i64,
    pub room: i64,
    /// The face that measured it; `None` for the em rule.
    pub font: Option<String>,
}

/// One creation run.
#[derive(Debug, Clone)]
pub struct DeckCreateRequest<'a> {
    pub outline: EntityId,
    pub template: ArtifactVersionRef,
    /// Brief asset id to the held PNG, JPEG or SVG version it binds.
    pub assets: &'a BTreeMap<String, ArtifactVersionRef>,
    /// Font files (TrueType, OpenType or collections) to measure text with.
    pub fonts: &'a [ArtifactVersionRef],
    pub names: Names<'a>,
    /// The new artifact's name.
    pub name: &'a str,
    pub run_ref: &'a str,
    pub made_by: Option<EntityId>,
    /// The task or ask the creation answers: the deck's born-from.
    pub trigger: Option<MadeByTrigger>,
    pub actor: WriteActor,
}

#[derive(Debug, Clone)]
pub enum DeckCreateOutcome {
    Created(Box<DeckCreationRecord>),
    /// Pages no rung holds; nothing was written.
    Ask {
        pages: Vec<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum DeckCreateError {
    #[error(transparent)]
    Vault(#[from] Error),
    #[error("the outline is not usable: {0}")]
    Outline(&'static str),
    #[error(transparent)]
    Compile(#[from] CompileError),
    #[error(transparent)]
    Emit(#[from] EmitError),
    #[error(transparent)]
    Font(#[from] FontError),
}
