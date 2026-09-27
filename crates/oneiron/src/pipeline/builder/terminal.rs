use super::*;
use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeRecord, decode_coping_outcome_claim,
    validate_coping_outcome_claim_structure,
};
use crate::claim::claim_surfaceable;
use crate::error::{Error, Result};
use crate::pipeline::corpus_filter::claim_matches_corpus;
use crate::pipeline::types::{
    DreamerWorkingSet, DreamerWorkingSetBudget, DreamerWorkingSetCursor,
    DreamerWorkingSetStopReason, PendingVectorEmbedding, RetrievalWithPendingVectors,
    RetrievalWithTelemetry,
};

impl PipelineBuilder<'_> {
    pub fn prior_successful_coping_strategies(
        self,
        affected_person: &EntityId,
        limit: usize,
    ) -> Result<Vec<CopingOutcomeRecord>> {
        let corpus_scope = self.corpus_scope.clone().canonicalize()?;
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut records = Vec::new();
        for claim_id in self.vault.claims_for_subject(affected_person)? {
            let Some(body) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != COPING_OUTCOME_PREDICATE || !claim_surfaceable(&body) {
                continue;
            }
            if !claim_matches_corpus(&corpus_scope, &body)? {
                continue;
            }
            validate_coping_outcome_claim_structure(&body)?;
            let Some(value) = decode_coping_outcome_claim(&body)? else {
                continue;
            };
            if !value.successful() {
                continue;
            }
            records.push(CopingOutcomeRecord {
                claim_id,
                learned_at: self.vault.get_learned_at(&claim_id)?,
                valid_from: body.valid_from.ok_or(Error::InvalidClaimBody(
                    "coping.outcome valid_from is required",
                ))?,
                valid_to: body.valid_to,
                value,
            });
        }
        records.sort_by(|a, b| {
            b.learned_at
                .cmp(&a.learned_at)
                .then_with(|| b.claim_id.as_bytes().cmp(a.claim_id.as_bytes()))
        });
        records.truncate(limit);
        Ok(records)
    }

    pub fn run(self) -> Result<Vec<ScoredEntity>> {
        Ok(self.run_with_telemetry()?.value)
    }

    pub fn run_with_telemetry(self) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        let output = self.run_for_pack()?;
        Ok(RetrievalWithTelemetry {
            retrieval_quality: output.retrieval_quality,
            value: output.scores,
            run_id: output.telemetry_run_id,
        })
    }

    pub fn run_with_pending_vectors(
        self,
    ) -> Result<RetrievalWithPendingVectors<Vec<ScoredEntity>>> {
        #[cfg(feature = "sync")]
        let vault = self.vault;
        // K6: the enqueue arm is BASE-ONLY. A session surfacing returns its
        // pending vectors to the caller for inline handling and never writes
        // a `pe:` marker or an embed job row — there is no overlay `pe:`
        // keyspace, so redirecting is not an option and skipping is the rule.
        // Absence of an overlay is not permission to persist: anonymous
        // routes discard all writes. Only an explicit Base route enqueues.
        #[cfg(feature = "sync")]
        let enqueue = self
            .session
            .is_none_or(crate::off_record::SessionRetrievalTelemetry::writes_to_base);
        let output = self.run_for_pack()?;
        let pending_vector_ids = pending_vector_ids(&output.pending_vectors);
        #[cfg(feature = "sync")]
        if enqueue {
            crate::embed::enqueue_pending_embedding_jobs(
                vault,
                &pending_vector_ids,
                crate::embed::EMBED_PRIORITY_SURFACED_HOT,
            )?;
        }
        Ok(RetrievalWithPendingVectors {
            retrieval_quality: output.retrieval_quality,
            value: output.scores,
            pending_vector_ids,
            pending_vectors: output.pending_vectors,
            run_id: output.telemetry_run_id,
        })
    }

    pub fn run_dreamer_working_set(
        mut self,
        cursor: DreamerWorkingSetCursor,
        budget: DreamerWorkingSetBudget,
        page_limit: usize,
    ) -> Result<DreamerWorkingSet> {
        if page_limit == 0 {
            return Err(Error::InvalidConfig(
                "dreamer working-set page_limit must be greater than zero".to_owned(),
            ));
        }

        let remaining = budget.max_items().saturating_sub(cursor.offset());
        if remaining == 0 {
            return Ok(DreamerWorkingSet {
                retrieval_quality: Default::default(),
                cursor,
                next_cursor: None,
                budget,
                rows: Vec::new(),
                stop_reason: Some(DreamerWorkingSetStopReason::BudgetExhausted),
                telemetry_run_id: None,
            });
        }

        let ingress_limit = page_limit.min(remaining);
        let page_end = cursor.offset().saturating_add(ingress_limit);
        let lookahead = usize::from(page_end < budget.max_items());
        let fetch_limit = page_end.saturating_add(lookahead);
        self.result_limit = fetch_limit;

        let output = self.run_for_pack()?;
        let loaded = output.scores.len();
        let rows: Vec<_> = output
            .scores
            .into_iter()
            .skip(cursor.offset())
            .take(ingress_limit)
            .collect();
        let next_offset = cursor.offset().saturating_add(rows.len());
        let budget_exhausted = next_offset >= budget.max_items();
        let stop_reason = if budget_exhausted {
            Some(DreamerWorkingSetStopReason::BudgetExhausted)
        } else if loaded <= next_offset {
            Some(DreamerWorkingSetStopReason::EndOfWorkingSet)
        } else {
            None
        };
        let next_cursor = stop_reason
            .is_none()
            .then(|| DreamerWorkingSetCursor::from_offset(next_offset));

        Ok(DreamerWorkingSet {
            retrieval_quality: output.retrieval_quality,
            cursor,
            next_cursor,
            budget,
            rows,
            stop_reason,
            telemetry_run_id: output.telemetry_run_id,
        })
    }
}

fn pending_vector_ids(pending: &[PendingVectorEmbedding]) -> Vec<EntityId> {
    pending.iter().map(|pending| pending.id).collect()
}
