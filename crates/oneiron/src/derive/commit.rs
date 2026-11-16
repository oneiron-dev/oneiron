//! One derivation commit: every item staged in a savepoint of one write, and
//! the batch recorded beside them.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::batch::{DerivationBatch, DerivationItem, DerivationStamp, ItemRef};
use super::record::{AppliedEdge, DerivationBatchRecord, ItemRecord, put_batch_in_txn};
use crate::claim::ClaimApprovalStatus;
use crate::error::Result;
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::{GateDecisionId, GateReceipt, PolicyBasis, ReceiptActor};
use crate::{EntityId, Vault};
use oneiron_contracts::RecordedSeconds;

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
    /// Whether this commit is an extraction attempt binding's: only then are
    /// landed claims recorded as attempt outputs, rows marked as the
    /// attempt's, and imported evidence landed held.
    pub(super) extraction_binding_commit: bool,
    /// The admitted write-gate auto-checker of this commit, set only by the
    /// extraction binding's entry: one turn serves the whole commit. Every other
    /// entry passes none.
    pub(super) auto_checker: Option<&'s crate::llm::BoundedAutoChecker>,
    /// The row each landed item of the batch so far created, by local name.
    landed: BTreeMap<String, EntityId>,
    /// The gate receipts whose metrics wait for the commit: the staged grants', and
    /// under a lent checker the landings'. The commit counts them only after its write
    /// commits. Never counted inside.
    pub(super) post_commit_receipts: RefCell<Vec<crate::gate::RecordedClaimGateDecision>>,
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
    /// Commits `batch` for `stamp` in `txn`: each item stages in a savepoint
    /// and gets its own verdict. A refused item keeps its receipt and lands
    /// nothing; an item naming a refused item is refused in turn. The batch
    /// record lists every outcome. Returns the gate receipts whose metrics wait for the
    /// commit, for the caller to count only after its write commits; never counts them
    /// inside. It lends no checker, so what it returns is still only the staged grants'.
    ///
    /// # Errors
    ///
    /// A malformed batch or a storage error aborts the whole write.
    pub(crate) fn derive_commit_in_txn_with_grant_receipts(
        &self,
        txn: &mut heed::RwTxn<'_>,
        stamp: &DerivationStamp,
        batch: &DerivationBatch,
    ) -> Result<(
        DerivationReceipt,
        Vec<crate::gate::RecordedClaimGateDecision>,
    )> {
        self.derive_commit_in_txn_with_binding_mark(txn, stamp, batch, false, None)
    }

    /// The caller-owned commit with its binding mark: an extraction attempt
    /// binding's commit marks its rows as the attempt's and records its
    /// landed claims as attempt outputs. Existing host and stamp doors leave
    /// the mark off. `auto_checker` is that binding's admitted checker, or none.
    /// The gate receipts whose metrics wait for the commit are returned: the staged
    /// grants', and under a lent checker the landings'.
    pub(crate) fn derive_commit_in_txn_with_binding_mark(
        &self,
        txn: &mut heed::RwTxn<'_>,
        stamp: &DerivationStamp,
        batch: &DerivationBatch,
        extraction_binding_commit: bool,
        auto_checker: Option<&crate::llm::BoundedAutoChecker>,
    ) -> Result<(
        DerivationReceipt,
        Vec<crate::gate::RecordedClaimGateDecision>,
    )> {
        let max_items = super::setting_keys::BATCH_MAX_ITEMS
            .read_in_txn(self, txn, &[], None)?
            .value
            .0;
        batch.validate(usize::try_from(max_items).unwrap_or(usize::MAX))?;
        super::sources::recheck_in_txn(self, txn, stamp, batch)?;
        let mut context = ItemContext {
            batch: EntityId::now(),
            stamp,
            now: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            extraction_binding_commit,
            auto_checker,
            landed: BTreeMap::new(),
            post_commit_receipts: RefCell::new(Vec::new()),
        };
        let mut unavailable_names: BTreeSet<String> = BTreeSet::new();
        let mut items = Vec::with_capacity(batch.items.len());
        let mut applied_edges = Vec::with_capacity(batch.items.len());
        for item in &batch.items {
            let names_unavailable = item.refs().into_iter().any(
                |named| matches!(named, ItemRef::Local(name) if unavailable_names.contains(name)),
            );
            let mut applied_edge = None;
            let outcome = if names_unavailable {
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
                    DerivationItem::Conflict(conflict) => {
                        super::conflict::stage_in_txn(self, txn, &context, conflict)?
                    }
                    DerivationItem::Candidate(candidate) => {
                        super::candidate::stage_in_txn(self, txn, &context, candidate)?
                    }
                    DerivationItem::ConflictResolution(resolution) => {
                        super::conflict_resolution::stage_in_txn(self, txn, &context, resolution)?
                    }
                    DerivationItem::Person(person) => {
                        super::person::stage_in_txn(self, txn, &context, person)?
                    }
                }
            };
            match &outcome {
                ItemOutcome::Landed { rows, approval, .. } => {
                    // An attached candidate created support, not a named claim.
                    if matches!(item, DerivationItem::Candidate(_)) && approval.is_none() {
                        unavailable_names.insert(item.local().to_owned());
                    } else if item.creates_row()
                        && let Some(row) = rows.first()
                    {
                        context.landed.insert(item.local().to_owned(), *row);
                    }
                }
                ItemOutcome::Refused { .. } => {
                    unavailable_names.insert(item.local().to_owned());
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
        let receipts = context.post_commit_receipts.take();
        Ok((
            DerivationReceipt {
                batch: context.batch,
                items,
            },
            receipts,
        ))
    }

    /// [`Self::derive_commit_in_txn_with_grant_receipts`] in a write of its own.
    ///
    /// # Errors
    ///
    /// As [`Self::derive_commit_in_txn_with_grant_receipts`].
    pub fn derive_commit(
        &self,
        stamp: &DerivationStamp,
        batch: &DerivationBatch,
    ) -> Result<DerivationReceipt> {
        let (receipt, post_commit_receipts) = self.with_write_txn_grouped(|txn| {
            self.derive_commit_in_txn_with_grant_receipts(txn, stamp, batch)
        })?;
        for post_commit_receipt in &post_commit_receipts {
            post_commit_receipt.record_metrics(&self.store.diagnostics.gate);
        }
        Ok(receipt)
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
    let receipt = item_receipt(
        context,
        about,
        GateReceiptOutcome::Deny,
        reasons,
        grant_ref,
        frontier,
    );
    Ok(vault
        .store
        .record_gate_receipt_in_txn(txn, receipt)?
        .decision_id)
}

/// Appends the receipt of one landed item the derive verdict judged
/// (settlement, supersession, artifact, archive, person): the grant it was
/// judged by and the frontier it was judged under, beside the item's reason
/// tokens.
pub(super) fn allowance_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    about: Option<EntityId>,
    reasons: &[String],
    allowance: &crate::gate::DeriveAllowance,
) -> Result<GateDecisionId> {
    let receipt = item_receipt(
        context,
        about,
        GateReceiptOutcome::Approved,
        reasons,
        Some(allowance.grant_ref.clone()),
        allowance.frontier,
    );
    Ok(vault
        .store
        .record_gate_receipt_in_txn(txn, receipt)?
        .decision_id)
}

/// The Gate receipt draft of one item of the batch in `context`: the
/// batch's actor decided `outcome` for `reasons`, about `about`, judged by
/// `grant_ref` under `frontier`, at the batch's time. Its diff handle is the
/// batch's id. The store mints the id.
fn item_receipt(
    context: &ItemContext<'_>,
    about: Option<EntityId>,
    outcome: GateReceiptOutcome,
    reasons: &[String],
    grant_ref: Option<String>,
    frontier: [u8; 32],
) -> GateReceipt {
    let mut receipt = GateReceipt::with_reasons(
        outcome,
        super::DERIVE_ITEM_CONTENT_KIND,
        reasons.to_vec(),
        ReceiptActor::Row(context.stamp.actor),
        context.batch.as_bytes().to_vec(),
        PolicyBasis::frontier(frontier),
    );
    receipt.about = about;
    receipt.grant_ref = grant_ref;
    receipt.decided_at = Some(RecordedSeconds::from_secs(context.now));
    receipt
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
