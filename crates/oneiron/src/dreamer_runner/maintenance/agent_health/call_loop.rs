//! `loop` over agents' call receipts, one call stream at a time
//! (`call_evidence`, OF-568 L4). A witnessed stream's card names its
//! attempt's TASK and reads that attempt's dials; an unassigned stream's
//! names none and reads the vault's. An agent run's own calls leave no
//! receipt and are judged per attempt (`run_loop`).

use std::collections::BTreeSet;

use super::call_evidence::CallStream;
use super::{AgentHealthCounter, Attempts, DialBook, Dispatches, Finding, same_inputs};
use crate::receipt::CallOutcome;
use crate::self_heal::AgentHealthSignal;

/// `loop`: one stream's identical `(verb, request_digest)` calls in a row,
/// with no other call of that stream between them and no new input: two
/// calls whose inputs were both captured repeat only on an equal action
/// digest ([`same_inputs`]).
pub(super) fn loop_findings(
    streams: &[CallStream<'_>],
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for stream in streams {
        let (task, attempt) = stream.owner(dispatched, attempts);
        let repeats = book.for_attempt(dispatched, attempt).loop_repeats;
        let rows = &stream.rows;
        let mut start = 0;
        while start < rows.len() {
            let first = &rows[start].1;
            let end = rows[start..]
                .iter()
                .position(|(_, row)| {
                    row.verb != first.verb
                        || row.request_digest != first.request_digest
                        || !same_inputs(
                            row.action_digest.as_deref(),
                            first.action_digest.as_deref(),
                        )
                })
                .map_or(rows.len(), |offset| start + offset);
            let run = &rows[start..end];
            start = end;
            if (run.len() as u64) < repeats {
                continue;
            }
            let mut counter = Vec::new();
            let results: BTreeSet<_> = run.iter().map(|(_, row)| &row.result_digest).collect();
            if results.len() > 1 {
                counter.push(AgentHealthCounter::ResultsChanged);
            }
            if run
                .iter()
                .all(|(_, row)| matches!(row.outcome, CallOutcome::Refused { .. }))
            {
                counter.push(AgentHealthCounter::RefusedCalls);
            }
            let count = run.len() as i64;
            out.push(Finding {
                subject: stream.actor,
                signal: AgentHealthSignal::Loop,
                task,
                attempt,
                evidence: run.iter().map(|(id, _)| *id).collect(),
                window: (run[0].1.at, run[run.len() - 1].1.at),
                actual: count,
                dial: repeats as i64,
                measured: count,
                counter,
                confession: None,
                blocked: false,
                observed_brief: None,
                silence: None,
            });
        }
    }
    out
}
