//! Moved from `crates/oneiron/src/office_body/pptx/verbs.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_docedit::edit::Preset;
use oneiron_docedit::live::ApproveScope;
use oneiron_docedit::live::DeckDiff;
use oneiron_docedit::live::ExportProfile;
use oneiron_docedit::live::Gate;
use oneiron_docedit::live::GeometryProps;
use oneiron_docedit::live::Landing;
use oneiron_docedit::live::LandingReceipt;
use oneiron_docedit::live::NodeId;
use oneiron_docedit::live::NodeKind;
use oneiron_docedit::live::NodePayload;
use oneiron_docedit::live::OracleReceipt;
use oneiron_docedit::live::TextBody;
use oneiron_docedit::live::deck_export::PROJECTOR_VERSION;
use oneiron_docedit::live::effect_receipt;
use serde::Deserialize;
use serde::Serialize;

/// `vault.artifacts.body.deck.merge`: land a reviewed deck fork, naming the
/// head and the fork frontier the review read. The fork lands up to
/// `reviewed_fork`; work appended to it after the review stays on the open
/// fork for the next review (FIX 9992). `scope` is the approval it lands
/// under (this fork alone when absent); `landing` merges onto the head, or
/// switches the head to the fork's deck.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckForkMergeRequest {
    pub artifact_ref: String,
    pub fork_ref: String,
    pub reviewed_head: Vec<u8>,
    /// The review's `fork_head`: the fork's frontier the review read.
    pub reviewed_fork: Vec<u8>,
    #[serde(default)]
    pub scope: Option<ApproveScope>,
    #[serde(default)]
    pub landing: Option<Landing>,
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

/// `vault.artifacts.body.deck.export`: project the deck at its head, and
/// land it as the artifact's next version when the export gate is open.
/// While it is closed, the projection waits beside the artifact as a
/// proposal under `run_ref`, for a person to keep or discard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckExportRequest {
    pub artifact_ref: String,
    pub run_ref: String,
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
    /// Ceilings for compiling new or replaced live pictures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphics: Option<oneiron_docedit::graphic::GraphicLimits>,
}

/// `vault.artifacts.body.deck.gate`: one export profile's gate (the default
/// profile when absent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckGateRequest {
    #[serde(default)]
    pub profile: Option<String>,
}

/// `vault.artifacts.body.deck.oracle`: the deck oracle's receipt for its
/// profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckOracleRequest {
    pub receipt: OracleReceipt,
}
