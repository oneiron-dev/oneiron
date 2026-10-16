//! `ai.verdict` (ARCH-0076): a caller's own typed question through the
//! host's decision ladder. The SDK host door and any other server caller
//! (a fact hook's host) run it through [`run_verdict`], so one question
//! family, one evidence rule and one clock serve them all.
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::llm::decision::catalogue::AI_VERDICT;
use oneiron::llm::decision::{AnswerContract, DecisionRung, MAX_DECISION_STATE_BYTES};
use oneiron::memory::{MEMORY_CODE_INTERNAL, Memory, MemoryError, MemoryResult};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::task_verb::sdk::{AI_VERDICT_DEADLINE_MS, AiVerdict, AiVerdictRequest};

use crate::server::SyncServer;

/// Asks `request` through the host's ladder for `principal`, under one clock
/// started here. Each evidence ref is read under `reader`, the caller's own
/// scoped read: a ref it cannot read is refused as a missing one is, and the
/// providers read the views it can in the call's state, beside the caller's
/// own `state`. The dial climbs from the first filled rung to the request's
/// ceiling (`big` when absent); a verdict never queues an owner ask.
///
/// Every model rung blocks on the server's runtime: call this on a blocking
/// thread.
pub(crate) fn run_verdict(
    server: &SyncServer,
    principal: EntityId,
    reader: &Memory<'_>,
    request: &AiVerdictRequest,
) -> MemoryResult<AiVerdict> {
    let started = Instant::now();
    oneiron::memory::caps::check_deadline_ms(request.deadline_ms)?;
    oneiron::memory::caps::check_batch_len("evidence", request.evidence.len())?;
    let ceiling = request.ceiling.unwrap_or(DecisionRung::Big);
    if ceiling == DecisionRung::Human {
        return Err(MemoryError::bad_request_with(
            "ai.verdict never queues an owner ask",
            &["Name a ceiling below human, or ask the owner through ask."],
        ));
    }
    let contract = if request.options.is_empty() {
        AnswerContract::Noul
    } else {
        AnswerContract::Choice {
            options: request.options.clone(),
        }
    };
    let key = serde_json::to_vec(&contract).map_err(|_| internal())?;
    let question = AI_VERDICT
        .question(&[key.as_slice()], request.question.clone(), contract)
        .map_err(|_| {
            MemoryError::bad_request_with(
                "the question does not make a typed question",
                &[
                    "Word it in 1 to 16384 bytes, with at most 64 distinct options of 1 to 256 bytes each.",
                ],
            )
        })?;
    let views = if request.evidence.is_empty() {
        Vec::new()
    } else {
        reader.hydrate(&request.evidence)?.value
    };
    let evidence = views
        .iter()
        .map(|view| EntityId::from_hex(&view.id_hex))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| internal())?;
    let state = serde_json::json!({
        "state": request.state.clone().unwrap_or(serde_json::Value::Null),
        "evidence": views
            .iter()
            .map(|view| serde_json::json!({
                "ref": view.id_hex,
                "kind": view.kind,
                "body": view.body,
            }))
            .collect::<Vec<_>>(),
    });
    if serde_json::to_vec(&state).map_or(true, |bytes| bytes.len() > MAX_DECISION_STATE_BYTES) {
        return Err(MemoryError::bad_request_with(
            format!(
                "the state and the evidence views pass the ladder's {MAX_DECISION_STATE_BYTES}-byte state"
            ),
            &["Name fewer or smaller evidence refs, or a smaller state."],
        ));
    }
    let host = server.decision_host();
    let budget = Duration::from_millis(request.deadline_ms.unwrap_or(AI_VERDICT_DEADLINE_MS));
    let decision = host
        .ladder()
        .ladder()
        .run(
            &question,
            principal,
            &evidence,
            &state,
            host.dial(ceiling),
            &host.bands(),
            request.reversibility.into(),
            &RetrievalDeadline::hard(started, budget),
        )
        .map_err(|error| {
            MemoryError::bad_request_with(
                format!("ai.verdict: {error}"),
                &["Change the question, its options or its state as the ladder asks."],
            )
        })?;
    Ok(decision.into())
}

fn internal() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "ai.verdict did not finish on this server",
        &["Report this decision-ladder failure."],
    )
}
