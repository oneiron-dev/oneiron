//! Which durable step sent each recorded model call (FIX
//! DREAMER-CALL-ATTEMPT-ID). The server logs `model request sent` at each
//! physical send with 16 hex of the plain BLAKE3 of the exact body bytes,
//! inside the sending step's `model_step` span (its attempt and 16 hex of
//! its step hash). The proxy keeps the same digest of the body it relayed,
//! so a record joins its send line by digest; nothing new goes on the wire.
//! A body that two different senders sent (two steps, or a step and a send
//! outside any step) joins neither (`ambiguous`; never picked by time). A
//! record whose body only sends outside a step carry, or that no line names
//! (a body cut off in transit), stays unattributed.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use serde_json::{Value, json};

use super::call_proxy::{self, CallRecord};

/// The `attempt` of a record whose body two different senders sent.
const AMBIGUOUS: &str = "ambiguous";

/// The attempt and the step that one send line names.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Sender {
    attempt: String,
    step: String,
}

/// Who sent one body: one step, only sends outside any step, or more than
/// one sender (two steps, or a step and a send outside a step).
#[derive(Debug, PartialEq, Eq)]
enum Senders {
    One(Sender),
    Unscoped,
    Ambiguous,
}

/// The proxy's records joined to the send lines.
pub(super) struct Attributed {
    /// Each record as JSON, with the `attempt` and `step` that sent it.
    pub(super) records: Vec<Value>,
    /// The calls' summary per attempt (`call_proxy::summary`, all the run).
    pub(super) by_attempt: Value,
    /// Records no step's send line names alone: no line names the body,
    /// or only sends outside any step did.
    pub(super) unattributed: usize,
    /// Records whose body two different senders sent.
    pub(super) ambiguous: usize,
}

/// Each sent body's digest and who sent it, from the report's `model_sends`
/// lines; a line with no step span is a send outside any step.
fn senders(sends: &Value) -> BTreeMap<String, Senders> {
    let mut by_body = BTreeMap::new();
    for line in sends.as_array().into_iter().flatten() {
        let Some(body) = line["body"].as_str() else {
            continue;
        };
        let sender = match (line["attempt"].as_str(), line["step"].as_str()) {
            (Some(attempt), Some(step)) => Senders::One(Sender {
                attempt: attempt.to_owned(),
                step: step.to_owned(),
            }),
            _ => Senders::Unscoped,
        };
        match by_body.entry(body.to_owned()) {
            Entry::Vacant(slot) => {
                slot.insert(sender);
            }
            Entry::Occupied(mut slot) => {
                if *slot.get() != sender {
                    slot.insert(Senders::Ambiguous);
                }
            }
        }
    }
    by_body
}

/// `calls` joined by body digest to the `model_sends` lines of the report.
pub(super) fn attributed(calls: &[CallRecord], sends: &Value) -> Attributed {
    let by_body = senders(sends);
    let mut records = Vec::with_capacity(calls.len());
    let mut per_attempt: BTreeMap<&str, Vec<CallRecord>> = BTreeMap::new();
    let (mut unattributed, mut ambiguous) = (0, 0);
    for call in calls {
        let mut record = json!(call);
        match by_body.get(&call.body) {
            Some(Senders::One(sender)) => {
                record["attempt"] = json!(sender.attempt);
                record["step"] = json!(sender.step);
                per_attempt
                    .entry(sender.attempt.as_str())
                    .or_default()
                    .push(call.clone());
            }
            Some(Senders::Ambiguous) => {
                record["attempt"] = json!(AMBIGUOUS);
                ambiguous += 1;
            }
            Some(Senders::Unscoped) | None => unattributed += 1,
        }
        records.push(record);
    }
    let by_attempt = per_attempt
        .into_iter()
        .map(|(attempt, calls)| {
            let summary = call_proxy::summary(&calls, 0.0, f64::INFINITY);
            (attempt.to_owned(), summary)
        })
        .collect::<serde_json::Map<_, _>>();
    Attributed {
        records,
        by_attempt: by_attempt.into(),
        unattributed,
        ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(seq: u64, start_ms: f64, end_ms: f64, body: &str) -> CallRecord {
        CallRecord {
            seq,
            start_ms,
            first_byte_ms: None,
            end_ms,
            status: 200,
            request_bytes: 10,
            response_bytes: 10,
            model: None,
            stream: false,
            messages: 1,
            schema: None,
            body: body.to_owned(),
            retry_of: None,
            extends: None,
        }
    }

    #[test]
    fn each_record_names_the_step_whose_send_line_carries_its_body() {
        let sends = json!([
            {"body": "aaaa", "attempt": "a1", "step": "s1", "bytes": 10},
            {"body": "bbbb", "attempt": "a2", "step": "s2", "bytes": 10},
            // The same step sends one body again (a fresh-connection resend).
            {"body": "aaaa", "attempt": "a1", "step": "s1", "bytes": 10},
            // Two steps send one body: neither takes it.
            {"body": "cccc", "attempt": "a1", "step": "s3", "bytes": 10},
            {"body": "cccc", "attempt": "a2", "step": "s4", "bytes": 10},
            // A send outside a durable step names no one.
            {"body": "dddd", "bytes": 10},
            // A send outside a step and a step's send carry one body:
            // neither takes it, so a2 counts none of its calls.
            {"body": "ffff", "bytes": 10},
            {"body": "ffff", "attempt": "a2", "step": "s5", "bytes": 10},
        ]);
        let calls = [
            call(1, 0.0, 100.0, "aaaa"),
            call(2, 50.0, 150.0, "bbbb"),
            call(3, 200.0, 250.0, "aaaa"),
            call(4, 300.0, 350.0, "cccc"),
            call(5, 400.0, 450.0, "dddd"),
            call(6, 500.0, 550.0, "eeee"),
            call(7, 600.0, 650.0, "ffff"),
            call(8, 700.0, 750.0, "ffff"),
        ];
        let joined = attributed(&calls, &sends);
        let named = |i: usize| {
            let record = &joined.records[i];
            (
                record["seq"].as_u64(),
                record["attempt"].as_str(),
                record["step"].as_str(),
            )
        };
        assert_eq!(named(0), (Some(1), Some("a1"), Some("s1")));
        assert_eq!(named(1), (Some(2), Some("a2"), Some("s2")));
        assert_eq!(named(2), (Some(3), Some("a1"), Some("s1")));
        assert_eq!(named(3), (Some(4), Some(AMBIGUOUS), None));
        assert_eq!(named(4), (Some(5), None, None));
        assert_eq!(named(5), (Some(6), None, None));
        assert_eq!(named(6), (Some(7), Some(AMBIGUOUS), None));
        assert_eq!(named(7), (Some(8), Some(AMBIGUOUS), None));
        assert_eq!((joined.unattributed, joined.ambiguous), (2, 3));
        let by_attempt = joined.by_attempt.as_object().expect("an object");
        assert_eq!(by_attempt.len(), 2);
        assert_eq!(by_attempt["a1"]["calls"], json!(2));
        assert_eq!(by_attempt["a1"]["sum_ms"], json!(150.0));
        assert_eq!(by_attempt["a2"]["calls"], json!(1));
    }

    #[test]
    fn no_send_lines_leave_every_record_unattributed() {
        let calls = [call(1, 0.0, 10.0, "aaaa")];
        let joined = attributed(&calls, &Value::Null);
        assert_eq!((joined.unattributed, joined.ambiguous), (1, 0));
        assert_eq!(joined.by_attempt, json!({}));
        assert_eq!(joined.records[0]["body"], json!("aaaa"));
        assert!(joined.records[0].get("attempt").is_none());
    }
}
