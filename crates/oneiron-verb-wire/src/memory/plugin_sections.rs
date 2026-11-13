//! Moved from `crates/oneiron/src/memory/plugin_sections.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::memory::plugin_sections::install::PluginSectionInstallOutcome;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::skill_source::HubRef;
use serde::Deserialize;
use serde::Serialize;

/// Which exact skill bytes one manifest proposal is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PluginSectionTargetInput {
    /// An already-imported skill, Candidate or Active.
    ExistingSkill {
        /// The skill entity.
        skill_ref: EntityId,
    },
    /// An uninstalled pinned hub package; no byte is written before consent.
    HubPackage {
        /// The pinned hub ref the package is fetched at.
        hub_ref: HubRef,
        /// The preallocated ref the consented import lands at.
        target_skill_ref: EntityId,
    },
}

/// `vault.packs.sections.propose`'s input: one typed manifest, its exact
/// target, and the conversation turn that initiated the offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionProposeRequest {
    pub manifest: SectionManifestEnvelope,
    pub target: PluginSectionTargetInput,
    /// The initiating turn, as an opaque ref string.
    pub turn_ref: String,
}

/// `vault.packs.sections.list`'s input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionListRequest {
    /// Pending proposals on this page (default 256). A page size, not a cap:
    /// a larger request is served in full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// The `next_cursor` of the previous page; none starts at the oldest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// One install still awaiting owner consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionPendingRow {
    pub claim_ref: String,
    pub pack_id: String,
    pub section_id: String,
    pub label: String,
    /// `conversation` or `dreamer_suggestion`.
    pub origin: String,
    pub awaiting_owner_consent: bool,
    /// Why a fitted offer asks: what it requests that its caller does not
    /// hold. None for an offer no fit evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis: Option<String>,
    /// Every permission the fit evaluated; empty for an offer no fit
    /// evaluated.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// One admitted plugin section and the exact manifest it was granted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionAdmittedRow {
    pub claim_ref: String,
    pub section_id: String,
    pub manifest: SectionManifestEnvelope,
}

/// `vault.packs.sections.grant`'s input. A still-proposed claim is settled
/// through its review handle; an already-approved one (settled through
/// `vault.claims.settle`) grants with no handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionGrantRequest {
    /// The install claim (32 hex).
    pub claim_ref: String,
    /// The handle `vault.claims.review` returned for exactly this claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_id: Option<String>,
}

/// What one grant concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginSectionGrantState {
    /// The section is admitted and renders.
    Admitted,
    /// The supplying skill is not Active yet; a later rebuild admits the
    /// section once the existing skill doors activate it.
    PendingActivation,
}

/// `vault.packs.sections.grant`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionGrant {
    pub claim_ref: String,
    pub state: PluginSectionGrantState,
    /// The section, when it was admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
    /// The supplying skill (32 hex).
    pub skill_ref: String,
    /// The Settlement receipt (`gate:<hex>`), when this grant settled the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_receipt_ref: Option<String>,
    /// The exact manifest that was granted.
    pub manifest: SectionManifestEnvelope,
}

/// `vault.packs.sections.revoke`'s input: one install claim, or every live
/// install claim of one section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionRevokeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
}

/// `vault.packs.sections.revoke`'s answer: the retracted install claims.
/// Their sections and advertised verbs vanish from the next rebuild; the
/// supplying skill itself stays installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
    pub claim_refs: Vec<String>,
    pub revoked: u32,
}

/// `vault.packs.sections.suggest`'s input: one typed workflow-pattern
/// notice, and the pinned hub ref whose catalog the pass reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSectionSuggestRequest {
    pub hub_ref: HubRef,
    /// The run that observed the pattern.
    pub run_id: String,
    /// The digest window the suggestion belongs to.
    pub digest_window: String,
    /// Stable typed pattern key (the state family a pack serves), never prose.
    pub pattern_key: String,
    /// Owner-facing narration of the observation; never parsed.
    pub summary: String,
    /// Entities the observation rests on; the claim's evidence.
    pub evidence_refs: Vec<EntityId>,
    pub observed_at: u64,
}

/// What one suggestion pass concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginSectionSuggestionState {
    /// The owner switched suggestions off; no catalog was consulted.
    Disabled,
    /// The catalog offered nothing for this pattern.
    NoMatch,
    /// This exact suggestion was already put to the owner.
    SuppressedDuplicate,
    /// One install claim now awaits owner consent.
    Proposed,
}

/// `vault.packs.sections.suggest`'s answer: an attributed proposal at most.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSectionSuggestion {
    pub state: PluginSectionSuggestionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// The owner's plugin-suggestion knob as `vault.packs.sections.suggestions.get`
/// and `.set` answer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PluginSuggestionsView {
    pub enabled: bool,
}

/// `vault.packs.sections.suggestions.set`'s input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSuggestionsSetRequest {
    pub enabled: bool,
}
pub mod install;
