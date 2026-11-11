//! The wire form of the derivation verbs (untangle 6.7d): what a caller of
//! `vault.derive.commit` and `vault.derive.revert` sends and reads.
//!
//! A request names items, and the versions of the stored sources they cite,
//! and nothing about who commits them: no field carries an actor, a run, an
//! attempt, a source class, an approval or a lineage, and an unknown field is
//! refused. The engine stamps all of those from the caller's held live run
//! ([`super::DerivationStamp`]).
//!
//! A person's `about` lines are not a wire item: the engine's own executor
//! lands them.
//!
//! A PsychProfile item has no wire form yet: no verb carries a PsychProfile,
//! so its first caller defines one.

use serde::{Deserialize, Serialize};

use super::batch::{
    DerivationBatch, DerivationItem, DerivedArchive, DerivedClaim, DerivedEvidence, DerivedSameAs,
    DerivedSettle, DerivedSettlement, DerivedSupersede, DerivedTopology, ItemRef,
};
use super::commit::{DerivationReceipt, ItemOutcome};
use super::revert::DeriveRevertReceipt;
use crate::EntityId;
use crate::dreamer_consolidation::selection::StrengthSignals;
use crate::memory::{MemoryError, MemoryResult};
use crate::snapshot_read::SourceVersion;
use crate::verbs::IdentityProposedOp;

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

impl From<DeriveRef> for ItemRef {
    fn from(named: DeriveRef) -> Self {
        match named {
            DeriveRef::Stored(id) => Self::Stored(id),
            DeriveRef::Local(name) => Self::Local(name),
        }
    }
}

fn refs(named: Vec<DeriveRef>) -> Vec<ItemRef> {
    named.into_iter().map(ItemRef::from).collect()
}

/// A derived claim.
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

/// An identity-topology judgment under the caller's own `topology_seal`
/// Grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveTopologyInput {
    /// The item's name inside its batch.
    pub local: String,
    /// The judgment: a merge, split or facet.
    pub operation: IdentityProposedOp,
    /// The caller's own `topology_seal` Grant.
    pub grant: EntityId,
    /// Whether the judgment asks to take effect now rather than wait as a
    /// proposal.
    #[serde(default)]
    pub apply: bool,
}

/// One wire item: `{"kind": "<kind>", "spec": {...}}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "spec",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DeriveItemInput {
    Claim(DeriveClaimInput),
    Evidence(DeriveEvidenceInput),
    Supersede(DeriveSupersedeInput),
    Settle(DeriveSettleInput),
    SameAs(DeriveSameAsInput),
    Topology(DeriveTopologyInput),
    Archive(DeriveArchiveInput),
}

impl DeriveItemInput {
    fn into_item(self) -> MemoryResult<DerivationItem> {
        Ok(match self {
            Self::Claim(claim) => {
                if !(0.0..=1.0).contains(&claim.confidence) {
                    return Err(MemoryError::bad_request(
                        "a derived claim's confidence is a number from 0 to 1",
                    ));
                }
                DerivationItem::Claim(DerivedClaim {
                    local: claim.local,
                    predicate: claim.predicate,
                    subject: claim.subject.into(),
                    value: claim.value,
                    // In range, so the narrowing loses only precision.
                    confidence: claim.confidence as f32,
                    evidence: refs(claim.evidence),
                })
            }
            Self::Evidence(evidence) => DerivationItem::Evidence(DerivedEvidence {
                local: evidence.local,
                head: evidence.head.into(),
                sources: refs(evidence.sources),
            }),
            Self::Supersede(supersede) => DerivationItem::Supersede(DerivedSupersede {
                local: supersede.local,
                new: supersede.new.into(),
                old: supersede.old.into(),
            }),
            Self::Settle(settle) => DerivationItem::Settle(DerivedSettle {
                local: settle.local,
                marker: settle.marker.into(),
                settlement: match settle.settlement {
                    DeriveSettlementInput::Keep(kept) => DerivedSettlement::Keep(kept.into()),
                    DeriveSettlementInput::HoldBoth => DerivedSettlement::HoldBoth,
                    DeriveSettlementInput::Dismiss => DerivedSettlement::Dismiss,
                },
            }),
            Self::SameAs(same_as) => DerivationItem::SameAs(DerivedSameAs {
                local: same_as.local,
                source: same_as.source.into(),
                target: same_as.target.into(),
            }),
            Self::Topology(topology) => DerivationItem::Topology(DerivedTopology {
                local: topology.local,
                op: topology.operation.into_engine()?,
                grant: topology.grant,
                apply: topology.apply,
            }),
            Self::Archive(archive) => DerivationItem::Archive(DerivedArchive {
                local: archive.local,
                claim: archive.claim.into(),
                signals: StrengthSignals {
                    type_prior: archive.signals.type_prior,
                    frequency: archive.signals.frequency,
                    recency: archive.signals.recency,
                    diversity: archive.signals.diversity,
                },
                score: archive.score,
            }),
        })
    }
}

/// `vault.derive.commit`: one batch of derived items.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveCommitInput {
    /// The items, in the order they stage: an item names only stored rows
    /// and rows of items before it.
    pub items: Vec<DeriveItemInput>,
    /// The version of every stored source the items cite, as the caller's
    /// read served it. A source that moved or is withheld since aborts the
    /// whole batch.
    #[serde(default)]
    pub sources: Vec<SourceVersion>,
}

impl DeriveCommitInput {
    /// The engine's batch for this request.
    ///
    /// # Errors
    ///
    /// A bad request for an item the wire form does not admit.
    pub fn into_batch(self) -> MemoryResult<DerivationBatch> {
        Ok(DerivationBatch {
            items: self
                .items
                .into_iter()
                .map(DeriveItemInput::into_item)
                .collect::<MemoryResult<_>>()?,
            sources: self.sources,
        })
    }
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

impl From<DerivationReceipt> for DeriveCommitView {
    fn from(receipt: DerivationReceipt) -> Self {
        Self {
            batch: receipt.batch,
            items: receipt
                .items
                .into_iter()
                .map(|item| {
                    let (landed, rows, approval, receipt, reasons) = match item.outcome {
                        ItemOutcome::Landed {
                            rows,
                            approval,
                            receipt,
                        } => (
                            true,
                            rows,
                            approval.map(|approval| approval.as_str().to_owned()),
                            receipt.map(|receipt| receipt.to_hex()),
                            Vec::new(),
                        ),
                        ItemOutcome::Refused { reasons, receipt } => {
                            (false, Vec::new(), None, Some(receipt.to_hex()), reasons)
                        }
                    };
                    DeriveItemView {
                        local: item.local,
                        kind: item.kind.to_owned(),
                        landed,
                        rows,
                        approval,
                        receipt,
                        reasons,
                    }
                })
                .collect(),
        }
    }
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

impl From<DeriveRevertReceipt> for DeriveRevertView {
    fn from(receipt: DeriveRevertReceipt) -> Self {
        Self {
            batch: receipt.batch,
            reverted: receipt.reverted,
            left: receipt
                .left
                .into_iter()
                .map(|(local, reason)| DeriveLeftItemView { local, reason })
                .collect(),
            receipt: crate::entity_id::bytes_to_hex_lower(&receipt.receipt),
        }
    }
}

impl crate::Vault {
    /// `vault.derive.revert` as the vault's owner: any batch, under the
    /// owner's proof, which the revert validates again in its own write.
    ///
    /// # Errors
    ///
    /// An owner proof that no longer holds, a batch that is not recorded,
    /// and the vault's.
    pub fn derive_revert_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        batch: EntityId,
    ) -> MemoryResult<DeriveRevertView> {
        let actor = owner.revalidate(self)?;
        let reverter = crate::write_envelope::WriteActor::new(actor, crate::EdgeActorClass::Human);
        Ok(self.derive_revert(reverter, Some(owner), batch)?.into())
    }
}
