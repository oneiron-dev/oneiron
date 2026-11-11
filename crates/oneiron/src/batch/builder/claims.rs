//! Claim-candidate builder doors plus the gap-decay op constructor.

use super::super::*;
use super::BatchBuilder;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::write_envelope::affect_trigger::{AffectTriggerValue, affect_trigger_claim_candidate};
use crate::write_envelope::claim_predicate::{
    PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED,
};
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

    /// Appends lexical hints for an existing head, skipping ids already present.
    pub(crate) fn append_lexical_hints_for_existing_head(
        mut self,
        txn: &heed::RoTxn<'_>,
        head: &EntityId,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
        hints: &[String],
    ) -> crate::error::Result<Self> {
        let head_body = self
            .vault
            .get_claim_in_txn(txn, head)?
            .ok_or(crate::error::Error::EntityNotFound)?;
        let mut hint_scope = head_body.scope.clone();
        if let Some(Value::Map(entries)) = hint_scope.as_mut() {
            entries.retain(|(key, _)| key.as_str() != Some("evidence_taint"));
            for (key, value) in entries {
                let stamp = match key.as_str() {
                    Some("facet" | "facet_ref" | "facetRef") => head_body.scope_facet,
                    Some("scopeProjectId") => head_body.scope_project,
                    _ => continue,
                };
                *value = match value {
                    Value::Binary(_) => Value::Binary(stamp.as_bytes().to_vec()),
                    Value::String(_) => Value::from(stamp.to_hex()),
                    _ => continue,
                };
            }
        }
        let hint_strs: Vec<&str> = hints.iter().map(String::as_str).collect();
        let normalized = match crate::write_envelope::claim_body::lexical_query_hint::normalize_lexical_query_hints(
            &hint_strs,
        ) {
            Ok(normalized) => normalized,
            Err(err) => {
                if self.validation_error.is_none() {
                    self.validation_error = Some(err);
                }
                Vec::new()
            }
        };
        let normalized = if envelope.machine_signature().is_some() {
            Vec::new()
        } else {
            normalized
        };
        let hint_envelope = envelope.for_lexical_hint();
        for hint in normalized {
            let hint_id = match lexical_query_hint_claim_id(head, &hint) {
                Ok(hint_id) => hint_id,
                Err(err) => {
                    if self.validation_error.is_none() {
                        self.validation_error = Some(err);
                    }
                    continue;
                }
            };
            if crate::ports::EntityStoreRead::port_entity_present(&self.vault.store, txn, &hint_id)?
            {
                continue;
            }
            let mut hint_candidate = ClaimCandidate::new(
                crate::write_envelope::claim_body::lexical_query_hint::PREDICATE_LEXICAL_QUERY_HINT,
                crate::write_envelope::claim_body::ClaimSubject::Entity(*head),
                crate::write_envelope::claim_body::lexical_query_hint::encode_lexical_query_hint_value(
                    head, &hint,
                ),
                1.0,
            )
            .with_stale(true)
            .with_relationships(head_body.rel.clone())
            .with_scope_stamps(head_body.scope_facet, head_body.scope_project);
            if let Some(world) = head_body.world {
                hint_candidate = hint_candidate.with_world(world);
            }
            if let Some(scope) = hint_scope.clone() {
                hint_candidate = hint_candidate.with_scope(scope);
            }
            hint_candidate = hint_candidate.with_initial_claim_of_weight(None)?;
            self.ops.push(BatchOp::ClaimCandidate {
                id: hint_id,
                candidate: Box::new(hint_candidate),
                envelope: hint_envelope.clone(),
                occurred,
                learned_at,
                internal_lexical_query_hint: true,
            });
            self.ops.push(BatchOp::Text {
                id: hint_id,
                fields: vec![("query_hint".to_owned(), hint)],
            });
        }
        Ok(self)
    }
}
