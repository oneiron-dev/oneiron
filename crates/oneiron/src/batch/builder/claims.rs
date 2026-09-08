//! Claim-candidate builder doors plus the gap-decay op constructor.

use super::super::*;
use super::BatchBuilder;

use rmpv::Value;

use crate::affect::{AffectTriggerValue, affect_trigger_claim_candidate};
use crate::claim::{PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

impl BatchBuilder<'_> {
    /// Adds a claim candidate write stamped by a [`WriteEnvelope`].
    pub fn claim_candidate(
        mut self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = reject_family_owned_candidate(&candidate)
        {
            self.validation_error = Some(e);
        }
        self.ops.push(BatchOp::ClaimCandidate {
            id: *id,
            candidate: Box::new(candidate),
            envelope: envelope.clone(),
            occurred,
            learned_at,
            internal_lexical_query_hint: false,
        });
        self.ops.push(BatchOp::ReconcileLexicalQueryHints {
            source: *id,
            keep: Vec::new(),
        });
        self
    }

    /// Adds a claim candidate and capped prospective-query lexical hints.
    pub fn claim_candidate_with_lexical_hints(
        mut self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
        hints: &[&str],
    ) -> Self {
        push_claim_candidate_with_lexical_hints(
            &mut self.ops,
            &mut self.validation_error,
            id,
            candidate,
            envelope,
            occurred,
            learned_at,
            hints,
        );
        self
    }

    /// Adds an `affect.trigger` claim candidate.
    pub fn affect_trigger_claim(
        self,
        id: &EntityId,
        value: AffectTriggerValue,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        self.claim_candidate(
            id,
            affect_trigger_claim_candidate(value),
            envelope,
            occurred,
            learned_at,
        )
    }

    /// Adds a `conflict.open` claim candidate.
    #[expect(
        clippy::too_many_arguments,
        reason = "conflict helper mirrors claim_candidate writer context"
    )]
    pub fn conflict_open_claim(
        self,
        id: &EntityId,
        subject: EntityId,
        value: Value,
        confidence: f32,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        self.claim_candidate(
            id,
            conflict_claim_candidate(PREDICATE_CONFLICT_OPEN, subject, value, confidence),
            envelope,
            occurred,
            learned_at,
        )
    }

    /// Adds a `conflict.resolved` claim candidate.
    #[expect(
        clippy::too_many_arguments,
        reason = "conflict helper mirrors claim_candidate writer context"
    )]
    pub fn conflict_resolved_claim(
        self,
        id: &EntityId,
        subject: EntityId,
        value: Value,
        confidence: f32,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        self.claim_candidate(
            id,
            conflict_claim_candidate(PREDICATE_CONFLICT_RESOLVED, subject, value, confidence),
            envelope,
            occurred,
            learned_at,
        )
    }

    /// Queues the all-or-nothing Open→Lapsed transition of `ids` (CMT-4,
    /// ONE-1541).
    ///
    /// Crate-private: the ONLY caller is
    /// `commitment_lifecycle::lapse_overdue_commitments`, which has already
    /// classified the status-unfiltered overdue candidates and is passing the
    /// Open ones. `learned_at` is the sweep instant, which is the ONE place a
    /// lifecycle time comes from the sweep rather than from a terminal claim
    /// header: this write IS the transition.
    ///
    /// Duplicate ids are collapsed in input order so the gate preflight and
    /// the apply arm agree on exactly one decision per instance.
    pub(crate) fn commitment_gap_decay(
        mut self,
        ids: &[EntityId],
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Self {
        let mut seen = std::collections::HashSet::with_capacity(ids.len());
        let ids: Vec<EntityId> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
        self.ops.push(BatchOp::CommitmentGapDecay {
            ids,
            envelope: envelope.clone(),
            learned_at,
        });
        self
    }
}
