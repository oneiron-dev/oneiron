//! Follow one order to its end (pass 34, 14.2): ask `vault.jobs.orders.wait`, which an HTTP
//! caller is answered at once, and read each attempt's stdout and stderr with
//! `vault.jobs.logs.tail` from the key its receipt names, until the order is at an end and every
//! log it had is read whole. A signal this process took asks the issuer to cancel, once.

use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

use oneiron::EntityId;
use oneiron::work_order::{
    LOGS_TAIL_VERB, LogsTail, LogsTailStream, ORDERS_CANCEL_VERB, ORDERS_WAIT_VERB, OrderState,
    WorkOrder, WorkOrderWaitAnswer,
};
use serde_json::{Value, json};

use super::end::{EXIT_OTHER, EXIT_UNREACHED, OwnStop, order_code};
use super::transport::{CallError, VerbCall};

/// The pause between two asks while no log read waits (chosen).
pub(super) const POLL_PAUSE: Duration = Duration::from_secs(5);
/// How long one stdout read waits for bytes (chosen; the door waits at most 60 s,
/// work_order/logs_tail.rs:23).
pub(super) const TAIL_WAIT_MS: u64 = 10_000;
/// Calls in a row that may go unanswered before the booker leaves the order to run on (chosen).
pub(super) const UNREACHED_TRIES: u32 = 3;

/// What following ended with: the exit code and the end line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Followed {
    pub(super) code: i32,
    pub(super) line: String,
}

/// What a follow reads and writes through.
pub(super) struct Follow<'a> {
    pub(super) call: &'a mut dyn VerbCall,
    /// The attempts' stdout bytes.
    pub(super) out: &'a mut dyn Write,
    /// Their stderr bytes, and this command's own lines.
    pub(super) err: &'a mut dyn Write,
    /// The signal this process took, if any.
    pub(super) stop: &'a dyn Fn() -> Option<OwnStop>,
    /// Waits out a pause.
    pub(super) pause: &'a mut dyn FnMut(Duration),
    /// The machines' shown names.
    pub(super) names: &'a BTreeMap<EntityId, String>,
}

/// One attempt's two logs, read from their offsets.
#[derive(Debug)]
struct AttemptLog {
    key: String,
    stdout: StreamRead,
    stderr: StreamRead,
}

#[derive(Debug, Default)]
struct StreamRead {
    offset: u64,
    ended: bool,
    misses: u32,
}

impl AttemptLog {
    fn new(key: String) -> Self {
        Self {
            key,
            stdout: StreamRead::default(),
            stderr: StreamRead::default(),
        }
    }

    fn whole(&self) -> bool {
        self.stdout.ended && self.stderr.ended
    }
}

impl Follow<'_> {
    /// Follows `order` to its end.
    pub(super) fn order(&mut self, order: EntityId) -> Followed {
        let id = order.to_hex();
        let mut logs: Vec<AttemptLog> = Vec::new();
        let mut own_stop = None;
        let mut cancel_asked = true;
        let mut misses = 0;
        let mut seen = String::new();
        loop {
            if own_stop.is_none() {
                own_stop = (self.stop)();
            }
            if own_stop.is_some() && !cancel_asked {
                // Asked once; an unanswered ask is asked again on the next round.
                match self.call.call(ORDERS_CANCEL_VERB, &json!({ "order": id })) {
                    Ok(_) => cancel_asked = true,
                    Err(refused @ CallError::Refused { .. }) => {
                        cancel_asked = true;
                        self.say(&format!(
                            "[oneiron] order {id}: the cancel was refused: {}",
                            refused.text()
                        ));
                    }
                    Err(CallError::Unreached { .. }) => {}
                }
            }
            let asked = self.call.call(
                ORDERS_WAIT_VERB,
                &json!({ "order": id, "until": "terminal" }),
            );
            let view = match asked.map(serde_json::from_value::<WorkOrderWaitAnswer>) {
                Ok(Ok(answer)) => {
                    misses = 0;
                    answer.view
                }
                Ok(Err(error)) => {
                    return ended(
                        EXIT_OTHER,
                        &format!("the wait's answer did not read: {error}"),
                        &id,
                    );
                }
                Err(CallError::Unreached { why }) => {
                    misses += 1;
                    if misses >= UNREACHED_TRIES {
                        return Followed {
                            code: EXIT_UNREACHED,
                            line: format!(
                                "[oneiron] order {id}: the issuer stopped answering ({why}); the \
                                 order lives on: oneiron jobs follow {id}"
                            ),
                        };
                    }
                    (self.pause)(POLL_PAUSE);
                    continue;
                }
                Err(refused @ CallError::Refused { .. }) => {
                    let why = format!("the wait was refused: {}", refused.text());
                    return ended(EXIT_OTHER, &why, &id);
                }
            };
            self.say_state(&view.order, &mut seen);
            if let Some(receipt) = &view.receipt
                && !logs.iter().any(|log| log.key == receipt.key)
            {
                logs.push(AttemptLog::new(receipt.key.clone()));
            }
            let mut waited = false;
            for log in logs.iter_mut().filter(|log| !log.whole()) {
                if !log.stderr.ended {
                    self.read(&log.key, LogsTailStream::Stderr, &mut log.stderr, 0);
                }
                if !log.stdout.ended {
                    self.read(
                        &log.key,
                        LogsTailStream::Stdout,
                        &mut log.stdout,
                        TAIL_WAIT_MS,
                    );
                }
                waited = true;
            }
            if logs.iter().all(AttemptLog::whole)
                && let Some((code, what)) = order_code(&view.order, own_stop)
            {
                let host = view
                    .order
                    .attempts
                    .last()
                    .and_then(|attempt| attempt.machine)
                    .map_or_else(
                        || "no machine".to_owned(),
                        |machine| {
                            self.names
                                .get(&machine)
                                .cloned()
                                .unwrap_or_else(|| machine.to_hex())
                        },
                    );
                return Followed {
                    code,
                    line: format!("[oneiron] order {id} on {host} ended: exit {code} ({what})"),
                };
            }
            if !waited {
                (self.pause)(POLL_PAUSE);
            }
        }
    }

    /// One read of `stream` of the attempt `key` from where `read` stands, written out. A refused
    /// read leaves the stream: the order's end still decides the exit. An unanswered one is
    /// asked again, [`UNREACHED_TRIES`] times in a row at most.
    fn read(&mut self, key: &str, stream: LogsTailStream, read: &mut StreamRead, wait_ms: u64) {
        let name = match stream {
            LogsTailStream::Stdout => "stdout",
            LogsTailStream::Stderr => "stderr",
        };
        let mut input = json!({ "attempt": key, "stream": name, "offset": read.offset });
        if wait_ms > 0 {
            input["wait_ms"] = Value::from(wait_ms);
        }
        let tail = match self
            .call
            .call(LOGS_TAIL_VERB, &input)
            .map(serde_json::from_value::<LogsTail>)
        {
            Ok(Ok(tail)) => tail,
            Ok(Err(error)) => {
                self.say(&format!("[oneiron] {name} of {key} did not read: {error}"));
                read.ended = true;
                return;
            }
            Err(CallError::Unreached { why }) => {
                read.misses += 1;
                if read.misses >= UNREACHED_TRIES {
                    self.say(&format!("[oneiron] {name} of {key} is left unread: {why}"));
                    read.ended = true;
                }
                return;
            }
            Err(refused @ CallError::Refused { .. }) => {
                self.say(&format!(
                    "[oneiron] {name} of {key} is left unread: {}",
                    refused.text()
                ));
                read.ended = true;
                return;
            }
        };
        read.misses = 0;
        if let Some(gap) = tail.truncated {
            self.say(&format!(
                "[oneiron] {name} of {key}: the node's log cap dropped {} bytes",
                gap.dropped
            ));
        }
        let sink: &mut dyn Write = match stream {
            LogsTailStream::Stdout => &mut *self.out,
            LogsTailStream::Stderr => &mut *self.err,
        };
        // A closed pipe on our own output is no reason to stop following the order.
        let _ = sink.write_all(tail.bytes.as_bytes());
        let _ = sink.flush();
        read.offset = tail.next_offset;
        read.ended = tail.ended;
    }

    /// One line on stderr when the order's state or its attempts change.
    fn say_state(&mut self, order: &WorkOrder, seen: &mut String) {
        let now = match &order.state {
            OrderState::Open { blocked, .. } => {
                let mut codes: Vec<&str> = blocked.iter().map(|on| on.blocker.code()).collect();
                codes.sort_unstable();
                codes.dedup();
                format!(
                    "open, waiting on {}",
                    if codes.is_empty() {
                        "nothing named".to_owned()
                    } else {
                        codes.join(", ")
                    }
                )
            }
            OrderState::Running { attempt } => {
                let host = order
                    .attempts
                    .get(usize::from(*attempt).saturating_sub(1))
                    .and_then(|made| made.machine)
                    .map_or_else(
                        || "a machine".to_owned(),
                        |machine| {
                            self.names
                                .get(&machine)
                                .cloned()
                                .unwrap_or_else(|| machine.to_hex())
                        },
                    );
                format!("attempt {attempt} running on {host}")
            }
            _ => return,
        };
        if now != *seen {
            self.say(&format!("[oneiron] order {}: {now}", order.id.to_hex()));
            *seen = now;
        }
    }

    fn say(&mut self, line: &str) {
        let _ = writeln!(self.err, "{line}");
        let _ = self.err.flush();
    }
}

/// A follow that ended before the order did: `code` and why.
fn ended(code: i32, why: &str, id: &str) -> Followed {
    Followed {
        code,
        line: format!("[oneiron] order {id}: {why}"),
    }
}
