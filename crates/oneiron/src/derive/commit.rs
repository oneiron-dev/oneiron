//! One derivation commit: every item staged in a savepoint of one write, and
//! the batch recorded beside them.

use std::collections::{BTreeMap, BTreeSet};

use super::batch::{DerivationBatch, DerivationItem, DerivationStamp, ItemRef};
use super::record::{AppliedEdge, DerivationBatchRecord, ItemRecord, put_batch_in_txn};
use crate::claim::ClaimApprovalStatus;
use crate::error::Result;
use crate::store::{GateDecisionContext, GateDecisionId, GateDecisionRecord};
use crate::{EntityId, Vault};

/// What one item came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemOutcome {
    /// It landed.
    Landed {
        /// The rows it wrote or changed.
        rows: Vec<EntityId>,
        /// The approval a claim item landed at.
        approval: Option<ClaimApprovalStatus>,
        /// For an item the derive verdict judged, the receipt naming the
        /// grant it was judged by.
        receipt: Option<GateDecisionId>,
    },
    /// It was refused.
    Refused {
        /// The refusal's reason tokens.
        reasons: Vec<String>,
        /// The refusal's receipt in the gate decision ledger.
        receipt: GateDecisionId,
    },
}

/// One item's outcome, by its name inside the batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemReceipt {
    /// The item's name inside its batch.
    pub local: String,
    /// The item's kind.
    pub kind: &'static str,
    /// What it came to.
    pub outcome: ItemOutcome,
}

/// What a derivation commit did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationReceipt {
    /// The batch's id, under which [`Vault::derive_batch`] reads it.
    pub batch: EntityId,
    /// Each item's outcome, in batch order.
    pub items: Vec<ItemReceipt>,
}

/// Where an item stages: its batch, the commit's stamp and its clock.
pub(super) struct ItemContext<'s> {
    pub(super) batch: EntityId,
    pub(super) stamp: &'s DerivationStamp,
    /// The write's recorded clock, Unix seconds.
    pub(super) now: u64,
    /// The row each landed item of the batch so far created, by local name.
    landed: BTreeMap<String, EntityId>,
}

impl ItemContext<'_> {
    /// The row `named` is: a stored row, or the row an earlier item created.
    /// [`DerivationBatch::validate`] checked that a local name is an earlier
    /// item's, and the commit refuses an item naming a refused one before it
    /// stages.
    pub(super) fn resolve(&self, named: &ItemRef) -> Result<EntityId> {
        match named {
            ItemRef::Stored(id) => Ok(*id),
            ItemRef::Local(name) => {
                self.landed
                    .get(name)
                    .copied()
                    .ok_or(crate::error::Error::InvariantViolation(
                        "a derivation item names an unlanded item",
                    ))
            }
        }
    }
}

impl Vault {
    /// Commits `batch` for `stamp` in `txn` (untangle 6.7a): each item stages
    /// in a savepoint and gets its own verdict; a refused item keeps its
    /// refusal receipt and lands nothing; an item that names a refused item
    /// is refused (`derive.dependency_refused`). The batch record lists every
    /// item's outcome.
    ///
    /// # Errors
    ///
    /// A malformed batch, and storage errors: either aborts the whole write.
    pub(crate) fn derive_commit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        stamp: &DerivationStamp,
        batch: &DerivationBatch,
    ) -> Result<DerivationReceipt> {
        batch.validate()?;
        super::sources::recheck_in_txn(self, txn, stamp, batch)?;
        let mut context = ItemContext {
            batch: EntityId::now(),
            stamp,
            now: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            landed: BTreeMap::new(),
        };
        let mut refused: BTreeSet<String> = BTreeSet::new();
        let mut items = Vec::with_capacity(batch.items.len());
        let mut applied_edges = Vec::with_capacity(batch.items.len());
        for item in &batch.items {
            let names_refused = item
                .refs()
                .into_iter()
                .any(|named| matches!(named, ItemRef::Local(name) if refused.contains(name)));
            let mut applied_edge = None;
            let outcome = if names_refused {
                let reasons = vec![super::DEPENDENCY_REFUSED.to_owned()];
                let receipt = refusal_receipt_in_txn(self, txn, &context, None, &reasons)?;
                ItemOutcome::Refused { reasons, receipt }
            } else {
                match item {
                    DerivationItem::Claim(claim) => {
                        super::claim::stage_in_txn(self, txn, &context, claim)?
                    }
                    DerivationItem::Evidence(evidence) => {
                        super::evidence::stage_in_txn(self, txn, &context, evidence)?
                    }
                    DerivationItem::Supersede(supersede) => {
                        super::supersede::stage_in_txn(self, txn, &context, supersede)?
                    }
                    DerivationItem::Settle(settle) => {
                        super::settle::stage_in_txn(self, txn, &context, settle)?
                    }
                    DerivationItem::SameAs(same_as) => {
                        // The item owns the edge only when it created it: an
                        // edge that stood before is another writer's.
                        let source = context.resolve(&same_as.source)?;
                        let target = context.resolve(&same_as.target)?;
                        let stood =
                            super::revert::same_as_edge_revision_in(self, txn, source, target)?
                                .is_some();
                        let outcome =
                            super::link::stage_same_as_in_txn(self, txn, &context, same_as)?;
                        if !stood && matches!(outcome, ItemOutcome::Landed { .. }) {
                            applied_edge =
                                super::revert::same_as_edge_revision_in(self, txn, source, target)?
                                    .map(|revision| AppliedEdge {
                                        source,
                                        target,
                                        revision,
                                    });
                        }
                        outcome
                    }
                    DerivationItem::Topology(topology) => {
                        super::link::stage_topology_in_txn(self, txn, &context, topology)?
                    }
                    DerivationItem::PersonAbout(about) => {
                        super::artifact::stage_about_in_txn(self, txn, &context, about)?
                    }
                    DerivationItem::PsychProfile(profile) => {
                        super::artifact::stage_profile_in_txn(self, txn, &context, profile)?
                    }
                    DerivationItem::Archive(archive) => {
                        super::archive::stage_in_txn(self, txn, &context, archive)?
                    }
                }
            };
            match &outcome {
                ItemOutcome::Landed { rows, .. } => {
                    // A name stands only for a row its item created.
                    if item.creates_row()
                        && let Some(row) = rows.first()
                    {
                        context.landed.insert(item.local().to_owned(), *row);
                    }
                }
                ItemOutcome::Refused { .. } => {
                    refused.insert(item.local().to_owned());
                }
            }
            applied_edges.push(applied_edge);
            items.push(ItemReceipt {
                local: item.local().to_owned(),
                kind: item.kind(),
                outcome,
            });
        }
        let read: &heed::RoTxn<'_> = txn;
        let revisions = items
            .iter()
            .map(|item| match &item.outcome {
                ItemOutcome::Landed { rows, .. } => rows
                    .iter()
                    .map(|row| super::revert::row_revision_in(self, read, item.kind, *row))
                    .collect::<Result<Vec<_>>>(),
                ItemOutcome::Refused { .. } => Ok(Vec::new()),
            })
            .collect::<Result<Vec<_>>>()?;
        put_batch_in_txn(
            self,
            txn,
            context.batch,
            &batch_record(stamp, context.now, &items, revisions, applied_edges),
        )?;
        Ok(DerivationReceipt {
            batch: context.batch,
            items,
        })
    }

    /// [`Self::derive_commit_in_txn`] in a write of its own.
    ///
    /// # Errors
    ///
    /// As [`Self::derive_commit_in_txn`].
    pub fn derive_commit(
        &self,
        stamp: &DerivationStamp,
        batch: &DerivationBatch,
    ) -> Result<DerivationReceipt> {
        self.with_write_txn_grouped(|txn| self.derive_commit_in_txn(txn, stamp, batch))
    }
}

/// Appends the refusal receipt of one item of the batch in `context`: an
/// engine record in the gate's decision ledger, naming the actor, the
/// refused row (`about`, when the item minted or names one), the reason
/// tokens and the policy frontier the item was judged under. Its diff
/// handle is the batch's id, which links the receipt to the batch record.
/// The grant is what judged it, as [`crate::gate::derive_grant_ref_in_txn`]
/// names it in this same writer.
pub(super) fn refusal_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    about: Option<EntityId>,
    reasons: &[String],
) -> Result<GateDecisionId> {
    let frontier = crate::gate::resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()?;
    let grant_ref =
        crate::gate::derive_grant_ref_in_txn(&vault.store, txn, context.stamp.actor.entity_ref())?;
    let record = item_receipt(context, about, "deny", reasons, grant_ref, frontier);
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(record.decision_id)
}

/// Appends the receipt of one landed item the derive verdict judged
/// (settlement, supersession, artifact, archive): the grant it was judged
/// by and the frontier it was judged under, beside the item's reason
/// tokens.
pub(super) fn allowance_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    about: Option<EntityId>,
    reasons: &[String],
    allowance: &crate::gate::DeriveAllowance,
) -> Result<GateDecisionId> {
    let record = item_receipt(
        context,
        about,
        "approved",
        reasons,
        Some(allowance.grant_ref.clone()),
        allowance.frontier,
    );
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(record.decision_id)
}

fn item_receipt(
    context: &ItemContext<'_>,
    about: Option<EntityId>,
    outcome: &str,
    reasons: &[String],
    grant_ref: Option<String>,
    frontier: [u8; 32],
) -> GateDecisionRecord {
    let actor = context.stamp.actor;
    GateDecisionRecord {
        version: crate::store::GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::now(),
        created_at: context.now,
        outcome: outcome.to_owned(),
        reason_codes: reasons.to_vec(),
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: actor.actor_class().gate_actor_class().to_owned(),
        actor_ref: Some(actor.entity_ref().to_hex()),
        content_kind: super::DERIVE_ITEM_CONTENT_KIND.to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: about.map(|id| *id.as_bytes()),
        grant_ref,
        diff_handle: context.batch.as_bytes().to_vec(),
        read_frontier_hash: frontier,
        context: GateDecisionContext::default(),
        redacted_at: None,
    }
}

fn batch_record(
    stamp: &DerivationStamp,
    committed_at: u64,
    items: &[ItemReceipt],
    revisions: Vec<Vec<[u8; 32]>>,
    applied_edges: Vec<Option<AppliedEdge>>,
) -> DerivationBatchRecord {
    DerivationBatchRecord {
        actor: stamp.actor.entity_ref(),
        actor_class: stamp.actor.actor_class().gate_actor_class().to_owned(),
        run: stamp.run.clone(),
        committed_at,
        items: items
            .iter()
            .zip(revisions)
            .zip(applied_edges)
            .map(|((item, revisions), applied_edge)| match &item.outcome {
                ItemOutcome::Landed {
                    rows,
                    approval,
                    receipt,
                } => ItemRecord {
                    local: item.local.clone(),
                    kind: item.kind.to_owned(),
                    landed: true,
                    rows: rows.clone(),
                    approval: approval.map(|approval| approval.as_str().to_owned()),
                    reasons: Vec::new(),
                    receipt: receipt.map(GateDecisionId::as_bytes),
                    revisions,
                    applied_edge,
                },
                ItemOutcome::Refused { reasons, receipt } => ItemRecord {
                    local: item.local.clone(),
                    kind: item.kind.to_owned(),
                    landed: false,
                    rows: Vec::new(),
                    approval: None,
                    reasons: reasons.clone(),
                    receipt: Some(receipt.as_bytes()),
                    revisions,
                    applied_edge,
                },
            })
            .collect(),
    }
}
