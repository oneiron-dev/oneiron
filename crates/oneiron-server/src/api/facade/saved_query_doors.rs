//! The manual saved-query evaluation host door: `self.saved_query.evaluate`.
//!
//! The other five `self.saved_query.*` verbs are plain verb-table rows over
//! the caller's bound `Memory`. Evaluation is not: a rubric judge runs on
//! this server's own model seats, under the query owner's budget line and
//! decision ladder, as the saved-query sweep binds it
//! (`saved_query_sweep::manual_evaluation`). The door acts only for the
//! query's owner — the caller the facade resolved from the presented
//! credential — and the evaluation reads through that owner's own read,
//! never the viewer's, exactly as a sweep wake does.
use std::sync::Arc;

use oneiron::campaign::surface::{
    SavedQueryEntityReceipt, SavedQueryEvaluateRequest, SavedQueryEvaluationReceipt,
    saved_query_memo_receipt,
};
use oneiron::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::saved_query::{
    SWEEP_CANDIDATE_TYPE, VerdictMemoKey, read_saved_query, sweep_owner_read, verdict_memo,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `self.saved_query.evaluate`: one bounded manual evaluation of a saved
/// query the caller owns, answering one verdict/memo receipt per visited
/// entity.
pub(crate) async fn self_saved_query_evaluate(
    server: &Arc<SyncServer>,
    _auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SavedQueryEvaluateRequest,
) -> MemoryResult<SavedQueryEvaluationReceipt> {
    const VERB: &str = "self.saved_query.evaluate";
    let moved = Arc::clone(server);
    tokio::task::spawn_blocking(move || evaluate(&moved, caller.0, &input))
        .await
        .map_err(|_| internal(VERB))?
}

fn evaluate(
    server: &SyncServer,
    caller: EntityId,
    input: &SavedQueryEvaluateRequest,
) -> MemoryResult<SavedQueryEvaluationReceipt> {
    let vault = server.vault();
    let record = read_saved_query(vault, caller, input.query_ref)
        .map_err(MemoryError::from)?
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                "no saved query the caller owns by that ref",
                &["Call self.saved_query.create first, or check the query ref."],
            )
        })?;
    let read = sweep_owner_read(
        vault,
        record.definition.owner_actor,
        record.definition.owner_actor_class,
    )
    .map_err(MemoryError::from)?
    .ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the saved query's owner has no usable read now",
            &["Restore the owner's read, then evaluate again."],
        )
    })?;
    let now = vault.now_recorded_at();
    let candidates = if input.candidates.is_empty() {
        let wake = usize::try_from(record.definition.eval.max_entities_per_wake)
            .unwrap_or(usize::MAX)
            .max(1);
        vault
            .entities_by_type_page(SWEEP_CANDIDATE_TYPE, input.after.as_ref(), wake)
            .map_err(MemoryError::from)?
    } else {
        input.candidates.clone()
    };
    let (visits, resume_after) =
        crate::saved_query_sweep::manual_evaluation(server, &record, &read, &candidates, now)
            .map_err(MemoryError::from)?;
    let mut memo_hits = 0_u32;
    let mut judges_run = 0_u32;
    let mut outcomes = Vec::with_capacity(visits.len());
    for (entity_ref, outcome, visit) in &visits {
        if outcome.memo_hit {
            memo_hits = memo_hits.saturating_add(1);
        }
        if visit.judge_ran {
            judges_run = judges_run.saturating_add(1);
        }
        let memo = verdict_memo(
            vault,
            &VerdictMemoKey {
                query_ref: record.query_ref,
                entity_ref: *entity_ref,
                evidence_hash: outcome.evidence_hash,
            },
        )
        .map_err(MemoryError::from)?
        .as_ref()
        .map(saved_query_memo_receipt);
        outcomes.push(SavedQueryEntityReceipt {
            entity_ref: *entity_ref,
            verdict: outcome.decision.verdict,
            why: outcome.decision.why.clone(),
            evidence_hash: hex_lower(&outcome.evidence_hash),
            memo_hit: outcome.memo_hit,
            judge_ran: visit.judge_ran,
            memo,
        });
    }
    Ok(SavedQueryEvaluationReceipt {
        query_ref: record.query_ref,
        owner_actor: record.definition.owner_actor,
        definition_version: record.definition.definition_version,
        evaluated: u32::try_from(visits.len()).unwrap_or(u32::MAX),
        memo_hits,
        judges_run,
        resume_after,
        outcomes,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
