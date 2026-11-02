//! Typed outline approval, design and emission doors over the native deck engine.
mod operations;
pub mod outline;
pub mod plan;

use crate::edit_roundtrip::deck_create::{
    ArtifactVersionRef, DeckCreationRecord, DesignSpec, EvidenceChange, KeptOutline,
    OutlineFreshness,
};
use crate::provenance::made_by::MadeByTrigger;
use outline::DeckOutline;
use plan::DeckPlanView;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckOutlineProposeRequest {
    pub outline: DeckOutline,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckOutlineRefRequest {
    pub outline_ref: String,
    /// Why an agent needs the lifted secrets the outline's texts hold: with
    /// it, the response reads whole once a grant covers their keys, for this
    /// read alone, and its ask goes to the owner otherwise (FIX 9605).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckOutlineSettleRequest {
    pub outline_ref: String,
    /// The exact NOTE frontier the person read before Keep or Decline.
    pub expected_frontier: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckOutlineView {
    pub outline_ref: String,
    pub frontier: Vec<u8>,
    pub outline: DeckOutline,
    pub kept: Option<KeptOutline>,
    pub freshness: OutlineFreshness,
    /// Why `kept` is left out although the outline has a keep. The current
    /// outline still answers; only the frozen keep is withheld.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_omission: Option<KeptOutlineOmissionReason>,
    /// The kept outline's cited evidence that changed since the keep without
    /// making it stale: a CLAIM's lifecycle, a source's frontier, a span the
    /// engine maps differently (FIX 9813, 9814). Reported, never a keep to
    /// make again; empty whenever `kept` is left out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_changed: Vec<EvidenceChange>,
    /// How the response presents the lifted secrets its texts hold.
    #[serde(default)]
    pub presentation: DeckPresentation,
}

/// How a deck outline or design response presents the lifted secrets its
/// texts hold (OF-067, FIX 9605).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DeckPresentation {
    /// Every text as stored: the owner reads it so, a granted agent that said
    /// why, and any reader of texts that hold no lifted key.
    #[default]
    Whole,
    /// Each lifted key reads as its handle (`[secret sc12]`). A kept
    /// outline's `bytes` are then this masked copy; its `version` and
    /// `content_hash` stay the stored keep's, which a design or creation
    /// binds.
    Masked,
}

/// Why an outline read leaves out its kept outline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeptOutlineOmissionReason {
    /// A source the kept outline cites does not resolve under this credential.
    SourcesUnreadable,
    /// The kept outline's frozen bytes do not parse into sources.
    InvalidFrozenOutline,
    /// A reader masked from lifted keys: the outline changed after its keep,
    /// and its text at the keep is no longer in the NOTE's history, so the
    /// keys the keep may hold are unknown (FIX 9605).
    KeysUnknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckOutlineDeclined {
    pub outline_ref: String,
    pub declined: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckKeepBinding {
    pub version: String,
    pub content_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckDesignRequest {
    pub outline_ref: String,
    pub kept: DeckKeepBinding,
    pub templates: Vec<ArtifactVersionRef>,
    #[serde(default)]
    pub assets: BTreeMap<String, ArtifactVersionRef>,
    #[serde(default)]
    pub fonts: Vec<ArtifactVersionRef>,
    /// Why an agent needs the lifted secrets the plans hold, as
    /// [`DeckOutlineRefRequest::why`] (FIX 9605).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckDesignView {
    pub spec: DesignSpec,
    /// One validated plan per direction; an Ask has no plan.
    pub plans: Vec<Option<DeckPlanView>>,
    /// Each direction's fallback questions, with options and fit shortfalls.
    pub decisions: Vec<Vec<plan::DeckDesignDecision>>,
    /// How the response presents the lifted secrets its texts hold.
    #[serde(default)]
    pub presentation: DeckPresentation,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckEmissionNames {
    pub text: String,
    pub table: String,
    pub chart: String,
    pub picture: String,
    pub figure: String,
    pub sheet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckEmissionRequest {
    pub outline_ref: String,
    pub kept: DeckKeepBinding,
    pub template: ArtifactVersionRef,
    #[serde(default)]
    pub assets: BTreeMap<String, ArtifactVersionRef>,
    #[serde(default)]
    pub fonts: Vec<ArtifactVersionRef>,
    pub names: DeckEmissionNames,
    pub name: String,
    pub run_ref: String,
    #[serde(default)]
    pub trigger: Option<MadeByTrigger>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeckEmissionOutcome {
    Created { record: Box<DeckCreationRecord> },
    Ask { pages: Vec<String> },
}
