//! Moved from `crates/oneiron/src/verbs/share.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::share_travel::TravelChoice;
use serde::Deserialize;
use serde::Serialize;

/// `vault.shares.create`'s input: the brief, its recipient, the most the view
/// may show, and what born-with text travels.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareCreateRequest {
    /// The share's id, as 32 hex: the one a pending decision named, to land
    /// it after approval. A fresh id when absent.
    #[serde(default)]
    pub share_id: Option<String>,
    /// Who may read the brief, as 32 hex; every view authenticates as them.
    pub recipient: String,
    /// The stored brief shared: its NOTE document reference.
    pub brief_ref: String,
    /// The most WORLDs the view may show, as 32 hex each.
    #[serde(default)]
    pub world_refs: Vec<String>,
    /// The most FACETs the view may show, as 32 hex each.
    #[serde(default)]
    pub facet_refs: Vec<String>,
    /// Whether an unscoped dimension may pass.
    #[serde(default)]
    pub include_unscoped: bool,
    /// Exclusive expiry, Unix seconds; none keeps the share until revoked.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// The born-with text that travels: `prompt`, `why`, `keep`,
    /// `intent_prompt`. None sends a brief's default, which is nothing.
    #[serde(default)]
    pub travel: Option<TravelChoice>,
    /// The saved mention `recipient` came from, when the agent named the
    /// person (OF-123): the share refuses while it is unsettled, so settle it
    /// with `self.identity.settle` first.
    #[serde(default)]
    pub mention: Option<crate::dreamer_runner::maintenance::identity::MentionProvenance>,
}

/// `vault.shares.create`'s answer: the admitted share and what travels with
/// it, fixed in the transaction that admitted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareCreated {
    pub share_id: String,
    pub recipient: String,
    pub brief_ref: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub travel: TravelChoice,
}

/// A link for one admitted share's recipient. The recipient's class and
/// credential lifetime are explicit; redemption fixes only its connection key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareViewLinkRequest {
    pub share_ref: String,
    pub actor_class: String,
    pub slip_lifetime_secs: u64,
}

/// `vault.shares.revoke`'s input: the share to stop.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareRevokeRequest {
    /// The share's id, as 32 hex: the `share_id` `vault.shares.create`
    /// answered.
    pub share_ref: String,
}

/// A viewer's own narrowing of a shared brief. It only takes away: the view
/// shows what the share's maximum, this narrowing and the viewer's live
/// authority all admit. A dimension left empty here shows nothing of it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareViewNarrowing {
    /// The WORLDs to keep, as 32 hex each.
    #[serde(default)]
    pub world_refs: Vec<String>,
    /// The FACETs to keep, as 32 hex each.
    #[serde(default)]
    pub facet_refs: Vec<String>,
    /// Whether an unscoped dimension may still pass.
    #[serde(default)]
    pub include_unscoped: bool,
}

/// `vault.shares.view`'s input: the share to open, and an optional
/// narrowing. The viewer is never named here: it is the caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareViewRequest {
    /// The share's id, as 32 hex.
    pub share_ref: String,
    #[serde(default)]
    pub narrowing: Option<ShareViewNarrowing>,
}

/// A citation handle is the pair returned by a shared view: its `share_ref`
/// and one citation's `claim_ref`. It carries no authority and stores no quote.
/// Each follow reopens that share under this caller's live read scope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefCitationFollowRequest {
    pub share_ref: String,
    pub claim_ref: String,
    #[serde(default)]
    pub narrowing: Option<ShareViewNarrowing>,
}
