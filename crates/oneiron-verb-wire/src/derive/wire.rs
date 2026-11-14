//! Moved from `crates/oneiron/src/derive/wire.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A row an item names: `{"stored": "<id>"}` for a stored row, or
/// `{"local": "<name>"}` for the row an earlier item of the batch creates.
/// Only a claim, a settlement, a SameAs and a topology item create a row
/// that can be named; a stored row is always named as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeriveRef {
    /// A stored row, by id.
    Stored(EntityId),
    /// The row an earlier item of the batch creates, by that item's local
    /// name.
    Local(String),
}

/// A derived claim.
/// The engine stamps Observed when cited user TURNs meet the preference bar; the caller never supplies a source.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveClaimInput {
    /// The item's name inside its batch.
    pub local: String,
    pub predicate: String,
    /// What the claim is about.
    pub subject: DeriveRef,
    pub value: serde_json::Value,
    /// In `[0, 1]`; a number outside it is refused, never clamped.
    #[schemars(range(min = 0.0, max = 1.0))]
    pub confidence: f64,
    /// The rows it was derived from. A stored one names its version in the
    /// request's `sources`.
    pub evidence: Vec<DeriveRef>,
}

/// Evidence for a stored claim.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveEvidenceInput {
    /// The item's name inside its batch.
    pub local: String,
    /// The claim the evidence supports.
    pub head: DeriveRef,
    /// The supporting rows: TURNs, cited whole, or admissible claims. A
    /// stored one names its version in the request's `sources`.
    pub sources: Vec<DeriveRef>,
}

/// A supersession: the claim `new` replaces the claim `old`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveSupersedeInput {
    /// The item's name inside its batch.
    pub local: String,
    pub new: DeriveRef,
    pub old: DeriveRef,
}

/// An answer to one open conflict: `{"keep": <ref>}`, `"hold_both"` or
/// `"dismiss"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeriveSettlementInput {
    /// This member stands; each other live member is superseded by it.
    Keep(DeriveRef),
    /// Every member stays active.
    HoldBoth,
    /// The marker named no real contradiction.
    Dismiss,
}

/// A settlement of the open conflict `marker`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveSettleInput {
    /// The item's name inside its batch.
    pub local: String,
    /// The open conflict's marker.
    pub marker: DeriveRef,
    pub settlement: DeriveSettlementInput,
}

/// The strength signals an archive was scored by, each in `[0, 1]`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveStrengthSignals {
    pub type_prior: f64,
    pub frequency: f64,
    pub recency: f64,
    pub diversity: f64,
}

/// A reversible archive of the caller's own weak claim.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveArchiveInput {
    /// The item's name inside its batch.
    pub local: String,
    /// The claim to archive.
    pub claim: DeriveRef,
    pub signals: DeriveStrengthSignals,
    /// Its score: below the owner's strength policy row, or refused.
    pub score: f64,
    /// The stored observation row's pin, as the reader
    /// `vault.consolidation.strength.observations.page` served it.
    pub observation_pin: String,
    /// The effective strength policy's pin, as the same reader served it.
    pub policy_pin: String,
    /// The effective scoring config's pin, as the same reader served it.
    pub config_pin: String,
}

/// A SameAs between two claims. It lands as the link's proposed status
/// claim; the edge is applied only under the owner's standing grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveSameAsInput {
    /// The item's name inside its batch.
    pub local: String,
    pub source: DeriveRef,
    pub target: DeriveRef,
}

/// One item's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeriveItemView {
    /// The item's name inside its batch.
    pub local: String,
    /// The item's kind.
    pub kind: String,
    /// Whether it landed. A refused item wrote nothing.
    pub landed: bool,
    /// The rows it wrote or changed.
    pub rows: Vec<EntityId>,
    /// The approval a claim item landed at: `auto` or `proposed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    /// The item's receipt in the gate decision ledger, hex: a refusal's, or
    /// the one naming the grant a landed item was judged by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// A refused item's reason tokens.
    pub reasons: Vec<String>,
}

/// `vault.derive.commit`'s answer: the batch and each item's outcome, in
/// batch order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeriveCommitView {
    /// The batch's id: what `vault.derive.revert` names.
    pub batch: EntityId,
    pub items: Vec<DeriveItemView>,
}

/// `vault.derive.revert`: one batch to take back. The verb has two callers.
/// An agent names the live run it attached to and reverts its own batch,
/// while its derive verdict stands. The vault's owner names no run and
/// reverts any batch under the owner's own proof.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveRevertInput {
    /// The batch, as `vault.derive.commit` answered it.
    pub batch: EntityId,
    /// The opaque attachment of the caller's own live run, as
    /// `self.run.attach` returned it to this same credential. Absent for the
    /// vault's owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_run: Option<String>,
}

/// An item a revert left standing, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeriveLeftItemView {
    /// The item's name inside its batch.
    pub local: String,
    /// Why it stands: a row it landed changed since, its kind has no
    /// inverse here, or its inverse refused.
    pub reason: String,
}

/// `vault.derive.revert`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeriveRevertView {
    pub batch: EntityId,
    /// The items undone, by local name, in the order they were undone.
    pub reverted: Vec<String>,
    /// The items left standing.
    pub left: Vec<DeriveLeftItemView>,
    /// The revert's receipt in the gate decision ledger, hex.
    pub receipt: String,
}
