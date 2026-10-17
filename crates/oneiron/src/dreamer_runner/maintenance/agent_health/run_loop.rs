//! `loop` over an agent run's own calls. An agent-def dispatch runs as a code
//! run keyed by its attempt id, so the run's bridge calls are that attempt's
//! calls, in order. A run holds no MCP credential and leaves no call receipt:
//! this is the per-attempt join the receipt ledger cannot make.

use rmpv::Value;

use super::{
    AgentHealthCounter, Attempts, DialBook, Dispatches, Finding, entity, same_inputs, settled,
    task_of,
};
use crate::attempt_queue::AttemptState;
use crate::code_run::SelfEffect;
use crate::self_heal::AgentHealthSignal;
use crate::{Result, Vault};

/// `loop`: identical `(effect, request)` bridge calls in a row in one
/// attempt's run, with no other call and no new input between (an equal
/// action digest, [`same_inputs`]). A repeated wait is a wait, not a loop.
/// Judged over live attempts and those settled in the lookback.
pub(super) fn run_loop_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
    since: u64,
) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        let live = matches!(record.state, AttemptState::Leased | AttemptState::Paused);
        if !live && !(settled(record.state) && record.updated_at >= since) {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let Some(run) = vault.get_code_run_replay_record(&attempt)? else {
            continue;
        };
        let repeats = book.of(Some(dispatch)).loop_repeats;
        let calls = &run.bridge_calls;
        let mut start = 0;
        while start < calls.len() {
            let first = &calls[start];
            let end = calls[start..]
                .iter()
                .position(|call| {
                    call.effect != first.effect
                        || call.request != first.request
                        || !same_inputs(
                            call.action_digest.as_deref(),
                            first.action_digest.as_deref(),
                        )
                })
                .map_or(calls.len(), |offset| start + offset);
            let streak = &calls[start..end];
            start = end;
            if (streak.len() as u64) < repeats
                || matches!(
                    first.effect,
                    SelfEffect::TasksWait | SelfEffect::TasksWaitSet
                )
            {
                continue;
            }
            let mut counter = Vec::new();
            if streak.iter().any(|call| call.outcome != first.outcome) {
                counter.push(AgentHealthCounter::ResultsChanged);
            }
            if streak.iter().all(|call| refused(&call.outcome)) {
                counter.push(AgentHealthCounter::RefusedCalls);
            }
            let count = streak.len() as i64;
            out.push(Finding {
                subject: dispatch.actor,
                signal: AgentHealthSignal::Loop,
                task: task_of(record),
                attempt: Some(record.id),
                evidence: vec![attempt],
                window: (
                    first.started_at_ms / 1000,
                    streak[streak.len() - 1].finished_at_ms / 1000,
                ),
                actual: count,
                dial: repeats as i64,
                measured: count,
                counter,
                confession: None,
                blocked: false,
            });
        }
    }
    Ok(out)
}

/// A denied or failed call, by its recorded outcome's `kind`.
pub(super) fn refused(outcome: &Value) -> bool {
    let Value::Map(entries) = outcome else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key.as_str() == Some("kind") && matches!(value.as_str(), Some("denied" | "failed"))
    })
}
