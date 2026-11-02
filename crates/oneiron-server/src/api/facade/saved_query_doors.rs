//! `self.saved_query.evaluate`, under the caller's own credential.
//!
//! The query must belong to that caller. Evaluation reuses the sweep's host
//! binding and the engine's staged evaluator; this door only pages candidates
//! and maps its exact memo and measurement receipts to the public wire shape.
use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::campaign::surface::{
    SavedQueryEntityReceipt, SavedQueryEvaluateRequest, SavedQueryEvaluationReceipt,
    saved_query_memo_receipt,
};
use oneiron::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::saved_query::SWEEP_CANDIDATE_TYPE;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Checks the caller's credential and actor before a verb hook may fire.
pub(super) fn admits(server: &SyncServer, auth: &CoreAuth) -> MemoryResult<()> {
    let (actor, class) =
        super::facade_actor(server, auth).map_err(|error| error.into_memory_error())?;
    crate::api::credential_memory(server.vault(), Some(auth), actor, class)
        .at(auth.locality())
        .read_key()
        .map(drop)
}

/// One bounded manual evaluation; no owner or read authority comes from input.
pub(crate) async fn self_saved_query_evaluate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SavedQueryEvaluateRequest,
) -> MemoryResult<SavedQueryEvaluationReceipt> {
    const VERB: &str = "self.saved_query.evaluate";
    admits(server, auth)?;
    if !input.candidates.is_empty() && input.after.is_some() {
        return Err(MemoryError::bad_request(
            "after pages people only; omit candidates when using it",
        ));
    }
    let (server, auth) = (Arc::clone(server), auth.clone());
    super::clock_ingress::run_blocking(move || evaluate(&server, &auth, caller, &input))
        .await
        .map_err(|_| internal(VERB))?
}

fn evaluate(
    server: &SyncServer,
    auth: &CoreAuth,
    (actor, class): (EntityId, EdgeActorClass),
    input: &SavedQueryEvaluateRequest,
) -> MemoryResult<SavedQueryEvaluationReceipt> {
    let vault = server.vault();
    let memory = crate::api::credential_memory(vault, Some(auth), actor, class).at(auth.locality());
    let record = memory.saved_query_read(input.query_ref)?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "no saved query the caller owns by that ref",
            &["Call self.saved_query.create first, or check the query ref."],
        )
    })?;
    let read = memory.read_key()?;
    let now = vault.now_recorded_at();
    let candidates = if input.candidates.is_empty() {
        let wake =
            usize::try_from(record.definition.eval.max_entities_per_wake).unwrap_or(usize::MAX);
        vault
            .entities_by_type_page(
                SWEEP_CANDIDATE_TYPE,
                input.after.as_ref(),
                wake.saturating_add(1),
            )
            .map_err(MemoryError::from)?
    } else {
        let mut seen = BTreeSet::new();
        input
            .candidates
            .iter()
            .copied()
            .filter(|id| seen.insert(*id))
            .collect()
    };
    let (visits, resume_after) =
        crate::saved_query_sweep::manual_evaluation(server, &record, &read, &candidates, now)
            .map_err(MemoryError::from)?;
    let mut memo_hits = 0_u32;
    let mut judges_run = 0_u32;
    let mut outcomes = Vec::with_capacity(visits.len());
    for (entity_ref, evaluated) in visits {
        let outcome = evaluated.outcome;
        if outcome.memo_hit {
            memo_hits = memo_hits.saturating_add(1);
        }
        if evaluated.visit.judge_ran {
            judges_run = judges_run.saturating_add(1);
        }
        outcomes.push(SavedQueryEntityReceipt {
            entity_ref,
            verdict: outcome.decision.verdict,
            why: outcome.decision.why,
            evidence_hash: outcome
                .evidence_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            memo_hit: outcome.memo_hit,
            judge_ran: evaluated.visit.judge_ran,
            memo: evaluated.memo.as_ref().map(saved_query_memo_receipt),
            judge: evaluated.judge,
        });
    }
    Ok(SavedQueryEvaluationReceipt {
        query_ref: record.query_ref,
        owner_actor: record.definition.owner_actor,
        definition_version: record.definition.definition_version,
        evaluated: u32::try_from(outcomes.len()).unwrap_or(u32::MAX),
        memo_hits,
        judges_run,
        resume_after,
        outcomes,
    })
}
