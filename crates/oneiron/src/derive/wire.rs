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
    DerivationBatch, DerivationItem, DerivedArchive, DerivedClaim, DerivedEvidence, DerivedPerson,
    DerivedSameAs, DerivedSettle, DerivedSettlement, DerivedSupersede, DerivedTopology, ItemRef,
};
use super::commit::{DerivationReceipt, ItemOutcome};
use super::revert::DeriveRevertReceipt;
use crate::EntityId;
use crate::dreamer_consolidation::selection::StrengthSignals;
use crate::memory::{MemoryError, MemoryResult};
use crate::snapshot_read::SourceVersion;
use crate::verbs::IdentityProposedOp;

#[doc(hidden)]
pub use oneiron_verb_wire::derive::wire::{
    DeriveArchiveInput, DeriveClaimInput, DeriveCommitView, DeriveEvidenceInput, DeriveItemView,
    DeriveLeftItemView, DeriveRef, DeriveRevertInput, DeriveRevertView, DeriveSameAsInput,
    DeriveSettleInput, DeriveSettlementInput, DeriveStrengthSignals, DeriveSupersedeInput,
};

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

/// A PERSON named in TURNs the caller reads: the engine derives its id,
/// checks that the name is a bounded span of the words a TURN serves, and
/// mints it where those words are read. The request names no id, target,
/// audience or body.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DerivePersonInput {
    /// The item's name inside its batch.
    pub local: String,
    /// The person's name, as the TURNs spell it.
    pub name: String,
    /// The stored TURNs that name the person, each with its version in the
    /// batch's `sources`.
    pub evidence: Vec<DeriveRef>,
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
    Person(DerivePersonInput),
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
                observation_pin: archive.observation_pin,
                policy_pin: archive.policy_pin,
                config_pin: archive.config_pin,
            }),
            Self::Person(person) => DerivationItem::Person(DerivedPerson {
                local: person.local,
                name: person.name,
                evidence: refs(person.evidence),
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
