//! Moved from `crates/oneiron/src/ingest/resolution.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

// ===========================================================================
// ARCH-0024 candidate scoring / ranking / routing waterfall
//
// The scoring input is EFFECTIVE confidence — stored claim confidence composed
// with the provider's `actor.confidence_prior` — never the stored column. That
// is the whole point of the leg: a provider the vault has learned to distrust
// must not out-rank a modest claim from one it trusts, and reading
// `ClaimBody::confidence` directly here would silently restore the old,
// provider-blind ordering.
//
// Signal producers supply stored evidence claims. Mention resolution and the
// typed owner mention door share this waterfall; selecting an archived subject
// restores that same record in the scoring transaction and mints nothing.
// ===========================================================================

/// One entity-resolution candidate: a subject, plus the provider-attributed
/// confidence CLAIM that argues for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityResolutionCandidate {
    /// The entity this candidate proposes the mention resolves to.
    pub subject: EntityId,
    /// The `provider.enrichment` CLAIM whose effective confidence scores it.
    pub confidence_claim_ref: EntityId,
}

/// The ARCH-0024 routing bands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityResolutionRoute {
    /// At or above the configured soft-link boundary — link outright.
    HardLink,
    /// Below the configured soft-link boundary — link, but verify asynchronously.
    SoftLink,
    /// Below the configured low soft-link boundary — link weakly, verify asynchronously.
    SoftLinkLow,
    /// Below the configured provisional boundary, or no candidates — resolve to nothing here.
    ProvisionalEntity,
}

/// A candidate with the effective confidence the waterfall scored it at.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScoredEntityResolutionCandidate {
    /// The candidate with its subject projected to the canonical Active head.
    pub candidate: EntityResolutionCandidate,
    /// Stored confidence composed with the provider's active prior.
    pub effective_confidence: f32,
}

/// The waterfall's verdict for one mention.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntityResolutionWaterfallDecision {
    /// Every authority-admissible candidate, scored and ranked best-first.
    pub ranked: Vec<ScoredEntityResolutionCandidate>,
    /// Surfaceable claims excluded by the stricter `claim_consolidatable` gate.
    pub claims_suppressed: usize,
    /// The chosen subject; `None` for [`EntityResolutionRoute::ProvisionalEntity`].
    pub selected: Option<EntityId>,
    /// The top effective confidence; `None` for the provisional route.
    pub selected_effective_confidence: Option<f32>,
    /// Which band the top score fell in.
    pub route: EntityResolutionRoute,
    /// Whether the route demands asynchronous verification.
    pub requires_async_verification: bool,
}

/// A mention's already-produced evidence, not a manual archive restore.
/// The waterfall validates every confidence claim against its subject and
/// provider. An empty or provisional result mints no entity.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityMentionRequest {
    pub candidates: Vec<EntityResolutionCandidate>,
    #[serde(default)]
    pub high_collision_mention: bool,
}
