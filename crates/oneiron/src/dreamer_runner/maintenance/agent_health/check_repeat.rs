//! `failed_check_repeat` (agent-mind §3.4): the same check fails again on
//! the same inputs. A run's bridge call is one tool run, and a call receipt
//! one call; each states an action digest over its action, its request and
//! the input versions captured before it ran (OF-568). Calls group by their
//! logical check, the action on equal arguments, and a streak holds while
//! each run of that check fails with the same known digest the same way:
//! its whole stored outcome, or its refusal code with its content digest
//! (`call_refusal_digest`). An input edited between two runs changes the
//! digest and starts the count again; a run whose inputs were not captured
//! is never a repeat. Other calls may come between, unlike `loop`; a success
//! of that check, or a different failure, starts the count again. Call
//! receipts count within one call stream (`call_evidence`, OF-568 L4): the
//! calls that name one attempt at one generation, whose card names that
//! attempt's TASK, or those that name none, whose card names no TASK.
//!
//! A run's shadow type checks count too: each step's stored report states
//! its action digest over the program, each declaration file and the checker
//! at its pin, so the digest is the logical check. A streak holds while the
//! check reports the same error diagnostics, as recorded, on that digest.

use std::collections::BTreeMap;

use rmpv::Value;

use super::call_evidence::CallStream;
use super::{Attempts, DialBook, Dispatches, Finding, entity, run_loop, settled, task_of};
use crate::attempt_queue::AttemptState;
use crate::receipt::CallOutcome;
use crate::self_heal::AgentHealthSignal;
use crate::{EntityId, Result, Vault};

/// One logical check's current streak of equal failures on equal inputs.
struct Streak<T> {
    /// The runs' action digest and their failure.
    failure: T,
    from: u64,
    to: u64,
    count: u64,
    evidence: Vec<EntityId>,
}

/// Where the executor stores a step's shadow check report:
/// `executor/repl/{seq:06}.code-check.json` (`code_check_output_path`).
const CHECK_REPORT_DIR: &str = "executor/repl/";
const CHECK_REPORT_SUFFIX: &str = ".code-check.json";

/// The step a stored output reports the shadow check of, if it is one.
fn check_report_seq(path: &str) -> Option<u64> {
    path.strip_prefix(CHECK_REPORT_DIR)?
        .strip_suffix(CHECK_REPORT_SUFFIX)?
        .parse()
        .ok()
}

/// A shadow check's action digest and, when it found an error, its
/// failure: the diagnostics as recorded and how many were left out. `None`
/// when the checker crashed or its inputs were not captured.
fn check_report_failure(
    report: &serde_json::Value,
) -> Option<(&str, Option<(&serde_json::Value, &serde_json::Value)>)> {
    let digest = report.get("action_digest")?.as_str()?;
    let diagnostics = report.get("diagnostics")?;
    let failed = diagnostics.as_array()?.iter().any(|diagnostic| {
        diagnostic
            .get("category")
            .and_then(serde_json::Value::as_str)
            == Some("error")
    });
    let omitted = report
        .get("diagnostics_omitted")
        .unwrap_or(&serde_json::Value::Null);
    Some((digest, failed.then_some((diagnostics, omitted))))
}

/// Each attempt's run, its tool runs and its shadow checks, then each call
/// stream's receipts, held against the `health.check.fails` dial.
pub(super) fn check_repeat_findings(
    vault: &Vault,
    streams: &[CallStream<'_>],
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
        let mut streaks: BTreeMap<Vec<u8>, Streak<(&str, &Value)>> = BTreeMap::new();
        let mut done = Vec::new();
        for call in &run.bridge_calls {
            let mut key = format!("{:?}\0", call.effect).into_bytes();
            if rmpv::encode::write_value(&mut key, &call.request).is_err() {
                continue;
            }
            // The failure on its known inputs; `None` once it succeeded, or
            // when its inputs were not captured.
            let failure = call
                .action_digest
                .as_deref()
                .filter(|_| run_loop::refused(&call.outcome))
                .map(|digest| (digest, &call.outcome));
            let (from, to) = (call.started_at_ms / 1000, call.finished_at_ms / 1000);
            let again = failure.is_some_and(|failure| {
                streaks
                    .get(&key)
                    .is_some_and(|streak| streak.failure == failure)
            });
            if again {
                if let Some(streak) = streaks.get_mut(&key) {
                    streak.to = to;
                    streak.count += 1;
                }
                continue;
            }
            done.extend(streaks.remove(&key));
            if let Some(failure) = failure {
                streaks.insert(
                    key,
                    Streak {
                        failure,
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
        // The shadow checks, in step order. An unreadable or unfinished
        // report is no evidence either way.
        let reports: Vec<(u64, serde_json::Value)> = run
            .outputs
            .iter()
            .filter(|output| output.complete)
            .filter_map(|output| {
                let seq = check_report_seq(&output.path)?;
                let body = vault.get_code_run_raw_output(output).ok().flatten()?;
                let at = run
                    .step_checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.seq == seq)
                    .map_or(record.updated_at, |checkpoint| {
                        checkpoint.created_at_ms / 1000
                    });
                Some((at, serde_json::from_slice::<serde_json::Value>(&body).ok()?))
            })
            .collect();
        let mut streaks: BTreeMap<&str, Streak<(&serde_json::Value, &serde_json::Value)>> =
            BTreeMap::new();
        let mut done = Vec::new();
        for (at, report) in &reports {
            let Some((digest, failure)) = check_report_failure(report) else {
                continue;
            };
            let again = failure.is_some_and(|failure| {
                streaks
                    .get(digest)
                    .is_some_and(|streak| streak.failure == failure)
            });
            if again {
                if let Some(streak) = streaks.get_mut(digest) {
                    streak.to = *at;
                    streak.count += 1;
                }
                continue;
            }
            done.extend(streaks.remove(digest));
            if let Some(failure) = failure {
                streaks.insert(
                    digest,
                    Streak {
                        failure,
                        from: *at,
                        to: *at,
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
    out.extend(call_check_findings(streams, dispatched, attempts, book));
    Ok(out)
}

/// The call half: each call stream's receipts, held against the
/// `health.check.fails` dial. A live review past its lease runs it alone
/// over that lease's calls (`targeted`, FIX 8109).
pub(super) fn call_check_findings(
    streams: &[CallStream<'_>],
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for stream in streams {
        let (task, attempt) = stream.owner(dispatched, attempts);
        let fails = book.for_attempt(dispatched, attempt).check_fails;
        let mut streaks: BTreeMap<(&str, &str), Streak<(&str, &String, &Option<String>)>> =
            BTreeMap::new();
        let mut done = Vec::new();
        for (id, row) in &stream.rows {
            let key = (row.verb.as_str(), row.request_digest.as_str());
            // The refusal's kind and its content on its known inputs; `None`
            // once it answered, or when its inputs were not captured.
            let failure = match (&row.outcome, row.action_digest.as_deref()) {
                (CallOutcome::Refused { code }, Some(digest)) => {
                    Some((digest, code, &row.result_digest))
                }
                _ => None,
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
                stream.actor,
                task,
                attempt,
                streak.evidence,
                (streak.from, streak.to),
                streak.count,
                fails,
            ));
        }
    }
    out
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
        observed_brief: None,
        silence: None,
    }
}
