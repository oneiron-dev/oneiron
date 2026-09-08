//! Vault commitment write verbs over the gated claim path.

use std::sync::atomic::Ordering;

use crate::batch::{ApplyOpsGateMode, BatchOp, EntityMetadataHeader, apply_ops_with_gate_mode};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

use super::codec::commitment_claim_candidate_from_body;
use super::{
    CommitmentRecord, CommitmentStatus, PREDICATE_COMMITMENT_RECORD, commitment_claim_candidate,
    decode_commitment_claim, decode_commitment_value,
};

impl Vault {
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

    /// Reads a `commitment.record` claim. Missing claims return `Ok(None)`;
    /// non-commitment CLAIM entities fail typed.
    pub fn get_commitment_claim(&self, id: &EntityId) -> Result<Option<CommitmentRecord>> {
        let Some(body) = self.get_claim(id)? else {
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
        let mut wtxn = self.store.env.write_txn()?;
        // Ground the named target and rewrite it in one transaction.
        let body = self.require_named_claim_target_active_in(&wtxn, id)?;
        if body.predicate != PREDICATE_COMMITMENT_RECORD {
            return Err(Error::InvalidClaimBody(
                "claim predicate is not commitment.record",
            ));
        }
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
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

        let candidate = commitment_claim_candidate_from_body(&body, &record)?;
        apply_commitment_ops(
            self,
            &mut wtxn,
            *id,
            candidate,
            envelope,
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at,
        )?;
        wtxn.commit()?;
        Ok(())
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
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
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
