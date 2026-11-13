//! A queue entry's receipts (FIX 4338, CODE-CUSTODY-03): its admission
//! when the queue accepts it, a waiting entry included, and its completion
//! when it reaches a terminal state. Each is an engine-owned reserved CLAIM
//! that the shared save writer keeps in the transaction that stores the
//! batch, so owner calls, a run's entry and the automatic driver are
//! receipted alike, after every admission check the writer makes.
//!
//! Each id is hashed from the queue's object store and the batch digest, in
//! its own domain. The digest and the queue sequence are evidence in a
//! receipt, never its ref. Green advanced is success; rolled back,
//! quarantined with its failing group, and cancelled are their own
//! outcomes. No earlier state completes an entry: a landed head is not
//! green. A batch of ids the vault holds no receipted proposal for is a
//! trusted low-level batch and is not receipted.

use rmpv::Value;

use super::batch_index::{BatchIndexKind, store_indexed_batches_in_txn};
use super::{BatchState, MergeBatch, MergeQueue};
use crate::claim::ClaimBody;
use crate::codebase::entity_id_from_hash_material;
use crate::error::{Error, Result};
use crate::repo_mutation::proposal::{
    proposal_admission_receipt_in_txn, put_receipt_once_in_txn, receipt_body, receipt_field,
    stored_receipt_in_txn,
};
use crate::{EntityId, Vault};

/// The predicate of a queue entry's admission receipt.
pub(crate) const QUEUE_ADMISSION_PREDICATE: &str = "repo.queue_admission";

/// The predicate of a queue entry's terminal completion receipt.
pub(crate) const QUEUE_COMPLETION_PREDICATE: &str = "repo.queue_completion";

const QUEUE_ADMISSION_DOMAIN: &[u8] = b"oneiron:repo-queue-admission:v1";
const QUEUE_COMPLETION_DOMAIN: &[u8] = b"oneiron:repo-queue-completion:v1";

/// The id of `domain`'s receipt of batch `batch` of the queue of `store`.
fn receipt_id(domain: &[u8], store: &str, batch: &str) -> Result<EntityId> {
    entity_id_from_hash_material(domain, &[store.as_bytes(), batch.as_bytes()])
}

/// The outcome a terminal `state` completes an entry with; `None` before.
const fn completion_outcome(state: BatchState) -> Option<&'static str> {
    match state {
        BatchState::GreenAdvanced => Some("green_advanced"),
        BatchState::RolledBack => Some("rolled_back"),
        BatchState::Quarantined => Some("quarantined"),
        BatchState::Cancelled => Some("cancelled"),
        BatchState::Superseded => Some("superseded"),
        BatchState::Queued
        | BatchState::Staged
        | BatchState::Ready
        | BatchState::Landing
        | BatchState::HeadAdvanced
        | BatchState::RollingBack => None,
    }
}

/// Whether `body` is a `predicate` receipt of batch `batch` of `store`.
fn check_queue_receipt(body: &ClaimBody, predicate: &str, store: &str, batch: &str) -> Result<()> {
    if body.predicate != predicate
        || receipt_field(&body.value, "store").and_then(Value::as_str) != Some(store)
        || receipt_field(&body.value, "batch").and_then(Value::as_str) != Some(batch)
    {
        return Err(Error::CorruptedIndex("queue receipt binding differs"));
    }
    Ok(())
}

/// A batch's receipts, each read and checked (FIX 4338).
#[derive(Debug, Clone, Default)]
pub(crate) struct QueueBatchReceipts {
    /// Its `repo.queue_admission` receipt.
    pub(crate) admission: Option<EntityId>,
    /// Its `repo.queue_completion` receipt, once terminal.
    pub(crate) completion: Option<EntityId>,
    /// Each proposal's submission admission receipt, in batch order, as the
    /// queue admission bound them; empty without one.
    pub(crate) proposals: Vec<EntityId>,
}

/// A proposal's retained queue failure (FIX 4364): the terminal batch that
/// failed it and that batch's completion receipt.
pub(crate) struct QueueProposalFailure {
    pub(crate) batch: String,
    pub(crate) completion: EntityId,
    /// `quarantined` or `rolled_back`.
    pub(crate) outcome: &'static str,
    /// The quarantined failing group, or every proposal rolled back.
    pub(crate) group: Vec<String>,
}

impl MergeQueue<'_> {
    /// Keeps the receipts one save of `batch` makes, in its writer `txn`,
    /// before the batch row is put: its queue admission while none is
    /// stored, then its completion once its state is terminal. A later save
    /// of a terminal batch finds its completion and writes nothing; another
    /// outcome there is a concurrent write.
    ///
    /// # Errors
    /// A stored receipt that binds another fact, or a store failure.
    pub(super) fn record_batch_receipts_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        batch: &MergeBatch,
    ) -> Result<()> {
        let store = self.repo.identity().as_hex();
        let admission = receipt_id(QUEUE_ADMISSION_DOMAIN, &store, &batch.id)?;
        let admitted = match stored_receipt_in_txn(self.vault, txn, &admission)? {
            Some(body) => {
                check_queue_receipt(&body, QUEUE_ADMISSION_PREDICATE, &store, &batch.id)?;
                true
            }
            None => self.admit_batch_in_txn(txn, &store, admission, batch)?,
        };
        let (true, Some(outcome)) = (admitted, completion_outcome(batch.state)) else {
            return Ok(());
        };
        let completion = receipt_id(QUEUE_COMPLETION_DOMAIN, &store, &batch.id)?;
        if let Some(body) = stored_receipt_in_txn(self.vault, txn, &completion)? {
            check_queue_receipt(&body, QUEUE_COMPLETION_PREDICATE, &store, &batch.id)?;
            if receipt_field(&body.value, "outcome").and_then(Value::as_str) != Some(outcome) {
                return Err(Error::ConcurrentWrite(
                    "a queue entry already completed with another outcome",
                ));
            }
            return Ok(());
        }
        self.complete_batch_in_txn(txn, &store, admission, completion, outcome, batch)
    }

    /// Writes `batch`'s queue admission `id` in `txn` when every proposal it
    /// holds is stored with a checked submission admission receipt; whether
    /// it did. It binds the object store, the batch, each proposal with its
    /// receipt in batch order, the baseline, expected head and green, and a
    /// run entry's work, TASK, declaration, predecessors and sequence. No
    /// host path and no actor is kept.
    fn admit_batch_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        store: &str,
        id: EntityId,
        batch: &MergeBatch,
    ) -> Result<bool> {
        let mut members = Vec::with_capacity(batch.proposals.len());
        for proposal in &batch.proposals {
            let Ok(proposal) = EntityId::from_hex(&proposal.id) else {
                return Ok(false);
            };
            let Some(row) = self.vault.repo_proposal_in_txn(txn, proposal)? else {
                return Ok(false);
            };
            let Some(receipt) = proposal_admission_receipt_in_txn(self.vault, txn, &row)? else {
                return Ok(false);
            };
            members.push((proposal, receipt));
        }
        let Some(&(subject, _)) = members.first() else {
            return Ok(false);
        };
        let hex = |id: EntityId| Value::from(id.to_hex());
        let mut fields = vec![
            ("schema_version", Value::from(1)),
            ("store", Value::from(store)),
            ("batch", Value::from(batch.id.as_str())),
            (
                "proposals",
                Value::Array(
                    members
                        .iter()
                        .map(|(proposal, receipt)| {
                            Value::Map(vec![
                                ("proposal".into(), hex(*proposal)),
                                ("admission".into(), hex(*receipt)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("baseline", Value::from(batch.baseline_id.as_str())),
            ("expected_head", Value::from(batch.expected_head.as_str())),
            ("base_green", Value::from(batch.base_green.as_str())),
        ];
        if let Some(order) = &batch.run_order {
            fields.push((
                "run",
                Value::Map(vec![
                    ("work".into(), hex(order.work)),
                    ("task".into(), hex(order.task)),
                    (
                        "declaration".into(),
                        order.declaration.map_or(Value::Nil, hex),
                    ),
                    (
                        "predecessors".into(),
                        Value::Array(
                            order
                                .predecessors
                                .iter()
                                .map(|predecessor| {
                                    Value::Map(vec![
                                        ("task".into(), hex(predecessor.task)),
                                        ("declaration".into(), hex(predecessor.declaration)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                    ("sequence".into(), Value::from(order.sequence)),
                ]),
            ));
        }
        let body = receipt_body(QUEUE_ADMISSION_PREDICATE, subject, fields)?;
        put_receipt_once_in_txn(self.vault, txn, id, &body, self.vault.now_recorded_at())?;
        Ok(true)
    }

    /// Writes `batch`'s completion `id` with `outcome` in `txn`: its queue
    /// admission, proposals, landed head, full staged tree, stored verdicts,
    /// each member's mutation seq, and the quarantined group. No proposal
    /// bytes, host path or check output is copied; a checker receipt stays
    /// behind the verdict that binds it.
    fn complete_batch_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        store: &str,
        admission: EntityId,
        id: EntityId,
        outcome: &str,
        batch: &MergeBatch,
    ) -> Result<()> {
        let mut mutations = Vec::new();
        for proposal in &batch.proposals {
            let seq = match EntityId::from_hex(&proposal.id) {
                Ok(listed) => self
                    .vault
                    .repo_proposal_in_txn(txn, listed)?
                    .and_then(|row| row.operation_seq),
                Err(_) => None,
            };
            if let Some(seq) = seq {
                mutations.push(Value::Array(vec![
                    Value::from(proposal.id.as_str()),
                    Value::from(seq),
                ]));
            }
        }
        let text = |text: Option<&str>| text.map_or(Value::Nil, Value::from);
        let mut fields = vec![
            ("schema_version", Value::from(1)),
            ("store", Value::from(store)),
            ("batch", Value::from(batch.id.as_str())),
            ("admission", Value::from(admission.to_hex())),
            ("outcome", Value::from(outcome)),
            (
                "proposals",
                Value::Array(
                    batch
                        .proposals
                        .iter()
                        .map(|proposal| Value::from(proposal.id.as_str()))
                        .collect(),
                ),
            ),
            ("landed_head", text(batch.landed_head.as_deref())),
            (
                "tested_tree",
                text(batch.paths.last().map(|path| path.tree.as_str())),
            ),
            (
                "verdicts",
                Value::Array(
                    batch
                        .paths
                        .iter()
                        .filter_map(|path| path.verdict.as_deref())
                        .chain(batch.slow_verdict.as_deref())
                        .map(Value::from)
                        .collect(),
                ),
            ),
            ("mutations", Value::Array(mutations)),
        ];
        if batch.state == BatchState::Superseded {
            fields.push((
                "superseded_by",
                self.superseding_batch_in_txn(txn, store, batch)?,
            ));
        }
        if let Some(quarantine) = &batch.quarantine {
            fields.push((
                "quarantine",
                Value::Map(vec![
                    (
                        "proposals".into(),
                        Value::Array(
                            quarantine
                                .proposal_ids
                                .iter()
                                .map(|proposal| Value::from(proposal.as_str()))
                                .collect(),
                        ),
                    ),
                    ("failing_mask".into(), Value::from(quarantine.failing_mask)),
                    ("verdict".into(), Value::from(quarantine.verdict.as_str())),
                ]),
            ));
        }
        let body = receipt_body(QUEUE_COMPLETION_PREDICATE, admission, fields)?;
        put_receipt_once_in_txn(self.vault, txn, id, &body, self.vault.now_recorded_at())
    }

    /// What a Superseded `batch`'s completion names (QUEUE Q1 = A): the
    /// green reconciliation successor its overlap link resolved to, and
    /// that successor's own `green_advanced` completion receipt. A trusted
    /// low-level successor has no receipt, so only its batch is named.
    ///
    /// # Errors
    /// A link that names no green successor, or a successor completion
    /// with another outcome.
    fn superseding_batch_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        store: &str,
        batch: &MergeBatch,
    ) -> Result<Value> {
        let successor = batch
            .drive
            .as_ref()
            .and_then(|drive| drive.overlap.as_ref())
            .filter(|link| link.superseded)
            .and_then(|link| link.resolution_batch.as_deref())
            .ok_or(Error::InvariantViolation(
                "a superseded queue entry names no green successor",
            ))?;
        let completion = receipt_id(QUEUE_COMPLETION_DOMAIN, store, successor)?;
        let receipt = match stored_receipt_in_txn(self.vault, txn, &completion)? {
            Some(body) => {
                check_queue_receipt(&body, QUEUE_COMPLETION_PREDICATE, store, successor)?;
                if receipt_field(&body.value, "outcome").and_then(Value::as_str)
                    != Some("green_advanced")
                {
                    return Err(Error::ConcurrentWrite(
                        "a superseding queue entry completed with another outcome",
                    ));
                }
                Value::from(completion.to_hex())
            }
            None => Value::Nil,
        };
        Ok(Value::Map(vec![
            ("batch".into(), Value::from(successor)),
            ("completion".into(), receipt),
        ]))
    }

    /// `batch`'s receipts, each read and checked (FIX 4338): its admission
    /// and the proposal receipts it bound, and its completion once terminal.
    ///
    /// # Errors
    /// A stored receipt that binds another batch, or a store failure.
    pub(crate) fn batch_receipts(&self, batch: &MergeBatch) -> Result<QueueBatchReceipts> {
        let txn = self.vault.store.env.read_txn()?;
        let store = self.repo.identity().as_hex();
        let admission = receipt_id(QUEUE_ADMISSION_DOMAIN, &store, &batch.id)?;
        let Some(body) = stored_receipt_in_txn(self.vault, &txn, &admission)? else {
            return Ok(QueueBatchReceipts::default());
        };
        check_queue_receipt(&body, QUEUE_ADMISSION_PREDICATE, &store, &batch.id)?;
        let proposals = admitted_proposals(&body, batch)?;
        let completion = receipt_id(QUEUE_COMPLETION_DOMAIN, &store, &batch.id)?;
        let completion = match stored_receipt_in_txn(self.vault, &txn, &completion)? {
            Some(body) => {
                check_queue_receipt(&body, QUEUE_COMPLETION_PREDICATE, &store, &batch.id)?;
                Some(completion)
            }
            None => None,
        };
        Ok(QueueBatchReceipts {
            admission: Some(admission),
            completion,
            proposals,
        })
    }
}

/// The submission admission receipts the queue admission `body` bound,
/// checked against `batch`'s proposals in order.
fn admitted_proposals(body: &ClaimBody, batch: &MergeBatch) -> Result<Vec<EntityId>> {
    let differs = || Error::CorruptedIndex("queue admission receipt proposals differ");
    let listed = receipt_field(&body.value, "proposals")
        .and_then(Value::as_array)
        .ok_or_else(differs)?;
    if listed.len() != batch.proposals.len() {
        return Err(differs());
    }
    listed
        .iter()
        .zip(&batch.proposals)
        .map(|(entry, proposal)| {
            let named = receipt_field(entry, "proposal").and_then(Value::as_str);
            match receipt_field(entry, "admission").and_then(Value::as_str) {
                Some(admission) if named == Some(proposal.id.as_str()) => {
                    EntityId::from_hex(admission)
                }
                _ => Err(differs()),
            }
        })
        .collect()
}

/// The retained queue failure of `proposal` in the queue of object store
/// `store`, read in `txn` (FIX 4364): a receipted terminal batch that
/// quarantined it in its failing group, or rolled it back. `None` while a
/// batch holding it is live or reached green; a survivor of a quarantine,
/// a cancelled entry and a superseded one are no failure of it.
///
/// # Errors
/// A stored receipt that binds another batch, or a store failure.
pub(crate) fn proposal_queue_failure_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    store: &str,
    proposal: EntityId,
) -> Result<Option<QueueProposalFailure>> {
    let id = proposal.to_hex();
    let mut failure = None;
    for batch in
        store_indexed_batches_in_txn(&vault.store, txn, store, BatchIndexKind::Proposal, &id)?
    {
        let (outcome, group) = match (batch.state, &batch.quarantine) {
            (BatchState::Quarantined, Some(quarantine))
                if quarantine.proposal_ids.contains(&id) =>
            {
                ("quarantined", quarantine.proposal_ids.clone())
            }
            (BatchState::RolledBack, _) => (
                "rolled_back",
                batch
                    .proposals
                    .iter()
                    .map(|listed| listed.id.clone())
                    .collect(),
            ),
            (BatchState::Quarantined | BatchState::Cancelled | BatchState::Superseded, _) => {
                continue;
            }
            _ => return Ok(None),
        };
        let completion = receipt_id(QUEUE_COMPLETION_DOMAIN, store, &batch.id)?;
        let Some(body) = stored_receipt_in_txn(vault, txn, &completion)? else {
            continue;
        };
        check_queue_receipt(&body, QUEUE_COMPLETION_PREDICATE, store, &batch.id)?;
        if failure.is_none() {
            failure = Some(QueueProposalFailure {
                batch: batch.id.clone(),
                completion,
                outcome,
                group,
            });
        }
    }
    Ok(failure)
}
