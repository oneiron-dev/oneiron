//! Moved from `crates/oneiron/src/memory/claim_stale.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_contracts::gate::ReadFilterInput;
use serde::Deserialize;
use serde::Serialize;

/// One demotion rung, as the caller names it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimDemoteActionInput {
    /// Lower the claim_of edge weight in place.
    Decay {
        /// The new claim_of weight; never above the current one.
        new_claim_of_weight: f32,
    },
    /// Supersede with a successor at a lower confidence.
    Weaken {
        /// The successor's confidence; never above the current one.
        new_confidence: f32,
    },
    /// Mark the claim stale in place: retrieval stops surfacing it
    /// unless a read's applied filter includes stale claims.
    Stale,
}

/// `vault.claims.demote` input: one claim, one rung.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimDemoteRequest {
    /// Claim short ref or 32-hex id.
    pub claim_ref: String,
    /// The rung to apply.
    pub action: ClaimDemoteActionInput,
}

/// One applied demotion: the rung now carried and the claim carrying it.
/// A weakening supersedes, so its `claim_ref` is the successor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimDemoteView {
    /// 32-hex id of the claim that now carries the rung.
    pub claim_ref: String,
    /// Short-id ref, when assigned.
    pub short_ref: Option<String>,
    /// `decayed`, `weakened` or `stale`.
    pub rung: String,
    /// Whether the carrying claim is stale.
    pub stale: bool,
    /// Receipt ref for this demotion.
    pub receipt_ref: String,
}

/// `vault.claims.list_filtered` input: the list selectors plus the
/// caller's retrieval filter.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimFilteredListRequest {
    /// Restrict to claims on this subject (short-id ref or hex).
    #[serde(default)]
    pub subject_ref: Option<String>,
    /// Restrict to this predicate.
    #[serde(default)]
    pub predicate: Option<String>,
    /// Restrict to this lifecycle (`active`/`superseded`/`retracted`).
    #[serde(default)]
    pub lifecycle: Option<String>,
    /// Maximum results (required; no unbounded scans).
    pub limit: usize,
    /// Caller retrieval filter; met with the actor ceiling.
    #[serde(default)]
    pub filter: Option<ReadFilterInput>,
}

/// `vault.claims.read_filtered` input: one claim under a caller filter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimFilteredReadRequest {
    /// Claim short ref or 32-hex id.
    pub claim_ref: String,
    /// Caller retrieval filter; met with the actor ceiling.
    #[serde(default)]
    pub filter: Option<ReadFilterInput>,
}
