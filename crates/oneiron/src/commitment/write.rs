//! Vault commitment write verbs over the gated claim path.

use crate::ports::EntityStoreRead;
use std::sync::atomic::Ordering;

use crate::batch::{ApplyOpsGateMode, BatchOp, EntityMetadataHeader, apply_ops_with_gate_mode};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

use super::codec::commitment_claim_candidate_from_body;
use super::{
    CommitmentRecord, CommitmentStatus, PREDICATE_COMMITMENT_RECORD, commitment_claim_candidate,
    decode_commitment_claim, decode_commitment_value,
};

/// Whether a status change mints a successor claim carrying the new status and
/// supersedes its predecessor through the claim lifecycle (FIX 9726), rather
/// than rewriting the value under the predecessor's id.
///
/// The commitment, schedule, wake, close, memory, receipt and deep-link
/// readers follow a commitment to the head of that chain
/// ([`Vault::commitment_head_in_txn`]), and the batched lapse stages its
/// successors in the batch's own transaction. A predecessor superseded before
/// its occurred start (a scheduled instance closed before its due window)
/// closes at that start.
pub(super) const STATUS_CHANGE_MINTS_SUCCESSOR: bool = true;

impl Vault {
    /// The head of a commitment's status chain: `id` itself, or the
    /// `commitment.record` claim that superseded it carrying the same promise
    /// under its next status, followed to the end.
    ///
    /// A replacement that changes the promise itself (a series edit) is a
    /// different commitment and is not followed.
    pub(crate) fn commitment_head_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<EntityId> {
        let Some(mut record) = self
            .get_claim_in_txn(txn, id)?
            .and_then(|body| decode_commitment_claim(&body).ok().flatten())
        else {
            return Ok(*id);
        };
        let mut head = *id;
        let mut seen = std::collections::HashSet::from([head]);
        'chain: loop {
            for successor in
                self.port_edge_peers(txn, &head, EdgeDirection::In, EdgeKind::Supersedes)?
            {
                let successor = successor?;
                let Some(next) = self
                    .get_claim_in_txn(txn, &successor)?
                    .and_then(|body| decode_commitment_claim(&body).ok().flatten())
                else {
                    continue;
                };
                if same_promise(&record, &next) && seen.insert(successor) {
                    head = successor;
                    record = next;
                    continue 'chain;
                }
            }
            return Ok(head);
        }
    }

    /// The commitment whose status `id` continues: the `commitment.record`
    /// claim `id` superseded carrying the same promise under its previous
    /// status. `None` for a commitment's first id and for a replacement that
    /// changed the promise itself.
    pub(crate) fn commitment_predecessor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityId>> {
        let Some(record) = self
            .get_claim_in_txn(txn, id)?
            .and_then(|body| decode_commitment_claim(&body).ok().flatten())
        else {
            return Ok(None);
        };
        for predecessor in
            self.port_edge_peers(txn, id, EdgeDirection::Out, EdgeKind::Supersedes)?
        {
            let predecessor = predecessor?;
            if self
                .get_claim_in_txn(txn, &predecessor)?
                .and_then(|body| decode_commitment_claim(&body).ok().flatten())
                .is_some_and(|prior| same_promise(&prior, &record))
            {
                return Ok(Some(predecessor));
            }
        }
        Ok(None)
    }

    /// Writes a new open `commitment.record` claim using the gated claim
    /// candidate path. `valid_time` is the due/active valid-time; `learned_at`
    /// is the transaction-time.
    pub fn put_commitment_claim(
        &self,
        id: &EntityId,
        record: &CommitmentRecord,
        envelope: &WriteEnvelope,
        valid_time: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if record.status != CommitmentStatus::Open {
            return Err(Error::InvalidClaimBody(
                "new commitment status must be open",
            ));
        }
        let candidate = commitment_claim_candidate(record)?
            .with_validity(Some(valid_time.start), Some(valid_time.end));
        self.apply_commitment_candidate(id, candidate, envelope, valid_time, learned_at)
    }

    /// Reads a `commitment.record` claim at the head of its status chain, so
    /// the status is the commitment's current one. Missing claims return
    /// `Ok(None)`; non-commitment CLAIM entities fail typed.
    pub fn get_commitment_claim(&self, id: &EntityId) -> Result<Option<CommitmentRecord>> {
        let txn = self.store.env.read_txn()?;
        let head = self.commitment_head_in_txn(&txn, id)?;
        let Some(body) = self.get_claim_in_txn(&txn, &head)? else {
            return Ok(None);
        };
        decode_commitment_claim(&body)?
            .ok_or(Error::InvalidClaimBody(
                "claim predicate is not commitment.record",
            ))
            .map(Some)
    }

    /// Marks an open commitment fulfilled through the gated write path.
    pub fn fulfill_commitment(
        &self,
        id: &EntityId,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        self.update_commitment_status(id, CommitmentStatus::Fulfilled, envelope, learned_at)
    }

    /// Marks an open commitment released through the gated write path.
    pub fn release_commitment(
        &self,
        id: &EntityId,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        self.update_commitment_status(id, CommitmentStatus::Released, envelope, learned_at)
    }

    /// Marks an open commitment lapsed through the gated write path.
    ///
    /// The single-row twin of the batched gap-decay sweep (CMT-4, ONE-1541):
    /// same predicate, lifecycle and transition checks as the other three
    /// status verbs, and the same one-transaction ground-then-rewrite shape.
    /// A sweep closing MANY overdue instances at once uses the crate-private
    /// batch op instead so the selected set is all-or-nothing.
    pub fn lapse_commitment(
        &self,
        id: &EntityId,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        self.update_commitment_status(id, CommitmentStatus::Lapsed, envelope, learned_at)
    }

    /// Marks an open commitment superseded through the gated write path.
    pub fn supersede_commitment(
        &self,
        id: &EntityId,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        self.update_commitment_status(id, CommitmentStatus::Superseded, envelope, learned_at)
    }

    fn update_commitment_status(
        &self,
        id: &EntityId,
        next: CommitmentStatus,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            self.update_commitment_status_in_txn(wtxn, id, next, envelope, learned_at, None)
        })
    }

    /// The status writer shared by the native lifecycle and credential-bound
    /// doors. Target, transition, evidence and Gate are judged in this writer.
    ///
    /// With [`STATUS_CHANGE_MINTS_SUCCESSOR`], the new status is a successor
    /// claim that supersedes `id` in this transaction, and a retry that finds
    /// the chain already closed with `next` writes nothing.
    pub(crate) fn update_commitment_status_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        next: CommitmentStatus,
        envelope: &WriteEnvelope,
        learned_at: u64,
        evidence: Option<rmpv::Value>,
    ) -> Result<()> {
        if STATUS_CHANGE_MINTS_SUCCESSOR {
            let head = self.commitment_head_in_txn(wtxn, id)?;
            if head != *id
                && let Some(body) = self.get_claim_in_txn(wtxn, &head)?
                && decode_commitment_claim(&body)?.is_some_and(|record| record.status == next)
            {
                return Ok(());
            }
        }
        let body = self.require_named_claim_target_active_in(wtxn, id)?;
        if body.predicate != PREDICATE_COMMITMENT_RECORD {
            return Err(Error::InvalidClaimBody(
                "claim predicate is not commitment.record",
            ));
        }
        let raw = self
            .store
            .port_entity_record(wtxn, id)?
            .map(|row| row.encode())
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(raw.as_ref())
            .ok_or(Error::CorruptedIndex("entity header"))?;
        let mut record = decode_commitment_value(&body.value)?;
        if !record.status.can_transition_to(next) {
            return Err(Error::InvalidClaimBody(
                "commitment status transition requires open source status",
            ));
        }
        record.status = next;
        let mut candidate = commitment_claim_candidate_from_body(&body, &record)?;
        if let Some(evidence) = evidence {
            candidate = candidate.with_evidence(evidence);
        }
        let occurred = TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        };
        if !STATUS_CHANGE_MINTS_SUCCESSOR {
            return apply_commitment_ops(
                self, wtxn, *id, candidate, envelope, occurred, learned_at,
            );
        }
        // The predecessor keeps the status it held; the successor carries the
        // new one, and the lifecycle closes and links the two together.
        let successor = EntityId::now();
        apply_commitment_ops(
            self, wtxn, successor, candidate, envelope, occurred, learned_at,
        )?;
        self.supersede_claim_in_txn(wtxn, &successor, id, learned_at)
    }

    fn apply_commitment_candidate(
        &self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.port_entity_record(&wtxn, id)?.is_some() {
            return Err(Error::InvalidClaimBody(
                "commitment claim id already exists",
            ));
        }
        apply_commitment_ops(
            self, &mut wtxn, *id, candidate, envelope, occurred, learned_at,
        )?;
        wtxn.commit()?;
        Ok(())
    }
}

/// Whether two records are one promise: everything but the status agrees.
fn same_promise(record: &CommitmentRecord, next: &CommitmentRecord) -> bool {
    record.obligor == next.obligor
        && record.beneficiary == next.beneficiary
        && record.content == next.content
        && record.schedule == next.schedule
        && record.strength == next.strength
        && record.birth_provenance == next.birth_provenance
}

fn apply_commitment_ops(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    candidate: ClaimCandidate,
    envelope: &WriteEnvelope,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    apply_ops_with_gate_mode(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![
            BatchOp::ClaimCandidate {
                id,
                candidate: Box::new(candidate),
                envelope: envelope.clone(),
                occurred,
                learned_at,
                internal_lexical_query_hint: false,
            },
            BatchOp::ReconcileLexicalQueryHints {
                source: id,
                keep: Vec::new(),
            },
        ],
        vault.text_index_trusted.load(Ordering::Acquire),
        ApplyOpsGateMode::new(true, true).with_source_in_gate_input(),
    )
}
