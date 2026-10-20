//! Typed outline approval, design and emission doors over the native deck engine.
mod operations;
pub mod outline;
pub mod plan;

use crate::edit_roundtrip::deck_create::{
    ArtifactVersionRef, DeckCreationRecord, DesignSpec, KeptOutline, OutlineFreshness,
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
}

/// Why an outline read leaves out its kept outline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeptOutlineOmissionReason {
    /// A source the kept outline cites does not resolve under this credential.
    SourcesUnreadable,
    /// The kept outline's frozen bytes do not parse into sources.
    InvalidFrozenOutline,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckDesignView {
    pub spec: DesignSpec,
    /// One validated plan per direction; an Ask has no plan.
    pub plans: Vec<Option<DeckPlanView>>,
    /// Each direction's fallback questions, with options and fit shortfalls.
    pub decisions: Vec<Vec<plan::DeckDesignDecision>>,
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
