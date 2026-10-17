//! `failed_check_repeat` (agent-mind §3.4): the same tool run fails the same
//! way again. A run's bridge call is one tool run with its canonical request,
//! and a call receipt one call with its request digest, so an equal action
//! on equal arguments is the same run. The same way is the failure's content,
//! not only its kind: a bridge call's whole stored outcome, and a receipt's
//! refusal code with its content digest (`call_refusal_digest`). A file
//! edited between two runs that changes what the check says is a new
//! failure. Other calls may come between, unlike `loop`; a success of that
//! run, or a different failure, starts the count again.

use std::collections::BTreeMap;

use rmpv::Value;

use super::{
    Attempts, DialBook, Dispatches, Finding, entity, live_attempt, run_loop, settled, task_of,
};
use crate::attempt_queue::AttemptState;
use crate::receipt::{CallOutcome, CallReceipt};
use crate::self_heal::AgentHealthSignal;
use crate::{EntityId, Result, Vault};

/// One run's current streak of equal failures.
struct Streak<T> {
    failure: T,
    from: u64,
    to: u64,
    count: u64,
    evidence: Vec<EntityId>,
}

/// Each attempt's run, then each agent's call receipts, held against the
/// `health.check.fails` dial.
pub(super) fn check_repeat_findings(
    vault: &Vault,
    calls: &BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>>,
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
        let fails = book.of(Some(dispatch)).check_fails;
        let mut streaks: BTreeMap<Vec<u8>, Streak<&Value>> = BTreeMap::new();
        let mut done = Vec::new();
        for call in &run.bridge_calls {
            let mut key = format!("{:?}\0", call.effect).into_bytes();
            if rmpv::encode::write_value(&mut key, &call.request).is_err() {
                continue;
            }
            let failed = run_loop::refused(&call.outcome);
            let (from, to) = (call.started_at_ms / 1000, call.finished_at_ms / 1000);
            let again = failed
                && streaks
                    .get(&key)
                    .is_some_and(|streak| streak.failure == &call.outcome);
            if again {
                if let Some(streak) = streaks.get_mut(&key) {
                    streak.to = to;
                    streak.count += 1;
                }
                continue;
            }
            done.extend(streaks.remove(&key));
            if failed {
                streaks.insert(
                    key,
                    Streak {
                        failure: &call.outcome,
                        from,
                        to,
                        count: 1,
                        evidence: Vec::new(),
                    },
                );
            }
        }
        done.extend(streaks.into_values());
        for streak in done.into_iter().filter(|streak| streak.count >= fails) {
            out.push(finding(
                dispatch.actor,
                task_of(record),
                Some(record.id),
                vec![attempt],
                (streak.from, streak.to),
                streak.count,
                fails,
            ));
        }
    }
    for (actor, rows) in calls {
        let attempt = live_attempt(*actor, dispatched, attempts);
        let fails = book.for_attempt(dispatched, attempt).check_fails;
        let mut streaks: BTreeMap<(&str, &str), Streak<(&String, &Option<String>)>> =
            BTreeMap::new();
        let mut done = Vec::new();
        for (id, row) in rows {
            let key = (row.verb.as_str(), row.request_digest.as_str());
            // The refusal's kind and its content; `None` once it answered.
            let failure = match &row.outcome {
                CallOutcome::Refused { code } => Some((code, &row.result_digest)),
                CallOutcome::Ok => None,
            };
            let again = failure.is_some_and(|failure| {
                streaks
                    .get(&key)
                    .is_some_and(|streak| streak.failure == failure)
            });
            if again {
                if let Some(streak) = streaks.get_mut(&key) {
                    streak.to = row.at;
                    streak.count += 1;
                    streak.evidence.push(*id);
                }
                continue;
            }
            done.extend(streaks.remove(&key));
            if let Some(failure) = failure {
                streaks.insert(
                    key,
                    Streak {
                        failure,
                        from: row.at,
                        to: row.at,
                        count: 1,
                        evidence: vec![*id],
                    },
                );
            }
        }
        done.extend(streaks.into_values());
        for streak in done.into_iter().filter(|streak| streak.count >= fails) {
            out.push(finding(
                *actor,
                None,
                attempt,
                streak.evidence,
                (streak.from, streak.to),
                streak.count,
                fails,
            ));
        }
    }
    Ok(out)
}

fn finding(
    subject: EntityId,
    task: Option<EntityId>,
    attempt: Option<crate::attempt_queue::AttemptId>,
    evidence: Vec<EntityId>,
    window: (u64, u64),
    count: u64,
    fails: u64,
) -> Finding {
    Finding {
        subject,
        signal: AgentHealthSignal::FailedCheckRepeat,
        task,
        attempt,
        evidence,
        window,
        actual: count as i64,
        dial: fails as i64,
        measured: count as i64,
        counter: Vec::new(),
        confession: None,
        blocked: false,
    }
}
