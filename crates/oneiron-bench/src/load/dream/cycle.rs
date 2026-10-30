//! The cycle itself: the session hints that open and end the sitting
//! (`POST /v1/ai/session`, `api/ai/mod.rs`), the Dreamer's status line
//! (`GET /v1/ai/status`), the recall loop that runs beside the cycle, and
//! the wait for the round the sitting's end enqueued.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::{Value, json};

use super::super::client::Agent;
use super::server_log::{Scan, Seen, Tail};

/// Items a recall asks for.
pub(super) const RECALL_LIMIT: usize = 20;
/// How often the wait reads the log; the status is read every fourth time.
const STEP: Duration = Duration::from_millis(500);
/// How long the Dreamer stays still before a round whose attempts all ended
/// (or, on a server without the stage lines, one that ran an attempt) counts
/// as finished.
const QUIET: Duration = Duration::from_secs(30);

/// Ms from `origin` to `at`.
pub(super) fn ms_between(origin: Instant, at: Instant) -> f64 {
    at.saturating_duration_since(origin).as_secs_f64() * 1000.0
}

/// One `/v1/ai/*` call as `agent`: a body POSTs, none GETs. The JSON
/// answer, or `<status> <code>`.
fn ai(agent: &Agent, http: &Client, url: &str, body: Option<&Value>) -> Result<Value, String> {
    let request = match body {
        Some(body) => http.post(url).json(body),
        None => http.get(url),
    };
    let response = agent.authorized(request)?.send().map_err(|e| {
        if e.is_timeout() {
            "timeout".to_owned()
        } else {
            "transport".to_owned()
        }
    })?;
    let status = response.status();
    let text = response.text().map_err(|_| "body".to_owned())?;
    let value = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
    if status.is_success() {
        return Ok(value);
    }
    let code = value["error"]["code"]
        .as_str()
        .or_else(|| value["code"].as_str())
        .unwrap_or("");
    Err(format!("{} {code}", status.as_u16()).trim().to_owned())
}

/// One session hint (`open`, `activity` or `end`) for `agent`'s sitting on
/// this machine. The server keeps it and answers 202 before the Dreamer's
/// driver applies it.
pub(super) fn hint(agent: &Agent, http: &Client, base: &str, event: &str) -> Result<(), String> {
    let url = format!("{base}/v1/ai/session");
    ai(agent, http, &url, Some(&json!({"event": event})))
        .map(drop)
        .map_err(|e| format!("session {event}: {e}"))
}

/// The Dreamer's line of `GET /v1/ai/status` (`ai_host/status.rs`
/// `WorkStatus`). The served executor counts per attempt run
/// (`ai_host/dreamer.rs` `ObservedExecutor`): `started` on each, then
/// `completed`, `unserved` or `failed`; a park, a deferral or a landing
/// counts none of them, so only `state` says nothing runs.
#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct DreamerStatus {
    pub(super) state: String,
    pub(super) reason: Option<String>,
    pub(super) started: u64,
    pub(super) completed: u64,
    pub(super) failed: u64,
    pub(super) unserved: u64,
    pub(super) last_error: Option<String>,
}

impl DreamerStatus {
    fn of(answer: &Value) -> Self {
        let line = &answer["ai"]["dreamer"];
        let count = |key: &str| line[key].as_u64().unwrap_or(0);
        Self {
            state: line["state"].as_str().unwrap_or("").to_owned(),
            reason: line["reason"].as_str().map(str::to_owned),
            started: count("started"),
            completed: count("completed"),
            failed: count("failed"),
            unserved: count("unserved"),
            // A park's debug text can quote a reply: the first 200 chars.
            last_error: line["last_error"]
                .as_str()
                .map(|e| e.chars().take(200).collect()),
        }
    }

    /// No attempt is running now.
    fn still(&self) -> bool {
        self.state != "working"
    }

    fn tallies(&self) -> (u64, u64, u64, u64) {
        (self.started, self.completed, self.failed, self.unserved)
    }
}

pub(super) fn status(agent: &Agent, http: &Client, base: &str) -> Result<DreamerStatus, String> {
    ai(agent, http, &format!("{base}/v1/ai/status"), None)
        .map(|answer| DreamerStatus::of(&answer))
        .map_err(|e| format!("ai status: {e}"))
}

/// The Dreamer's status once it runs (waiting or working), polled for up
/// to 60 s; an idle Dreamer's reason and last error are the refusal.
pub(super) fn dreamer_ready(
    agent: &Agent,
    http: &Client,
    base: &str,
) -> Result<DreamerStatus, String> {
    let started = Instant::now();
    loop {
        let now = status(agent, http, base)?;
        if now.state == "waiting" || now.state == "working" {
            return Ok(now);
        }
        if started.elapsed() >= Duration::from_secs(60) {
            return Err(format!(
                "the Dreamer is {} ({}): {}",
                now.state,
                now.reason.as_deref().unwrap_or("no reason"),
                now.last_error.as_deref().unwrap_or("no error")
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// One light recall, `RECALL_LIMIT` items, at the clock: no `as_of`, since
/// a landed claim is learned on the vault's clock, after every corpus time.
pub(super) fn recall(agent: &Agent, query: &str) -> (f64, Result<Value, String>) {
    agent.post(
        "vault.recall",
        &json!({"query": query, "effort": "light", "limit": RECALL_LIMIT}),
    )
}

/// One recall of the loop: when it started (ms since the run began), its
/// round trip, and what it answered (an error's kind only).
#[derive(Clone, Debug, Serialize)]
pub(super) struct Tick {
    pub(super) at_ms: f64,
    pub(super) ms: f64,
    pub(super) error: Option<String>,
    pub(super) items: usize,
    /// Index into the query set.
    pub(super) query: usize,
}

/// One light recall every `every`, rotating over `queries`, until `stop`.
/// A recall slower than `every` is followed at once, never by a burst.
pub(super) fn recall_loop(
    agent: &Agent,
    queries: &[String],
    every: Duration,
    origin: Instant,
    stop: &AtomicBool,
) -> Vec<Tick> {
    let mut ticks = Vec::new();
    let mut next = Instant::now();
    while !stop.load(Ordering::Relaxed) && !queries.is_empty() {
        let query = ticks.len() % queries.len();
        let at_ms = ms_between(origin, Instant::now());
        let (ms, answer) = recall(agent, &queries[query]);
        let (error, items) = match answer {
            Ok(pack) => (None, pack["items"].as_array().map_or(0, Vec::len)),
            Err(error) => (Some(error), 0),
        };
        ticks.push(Tick {
            at_ms,
            ms,
            error,
            items,
            query,
        });
        next = (next + every).max(Instant::now());
        while !stop.load(Ordering::Relaxed) {
            let left = next.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(Duration::from_millis(50)));
        }
    }
    ticks
}

/// How the wait for the round ended.
#[derive(Debug, Serialize)]
pub(super) struct Waited {
    /// `all_partitions_ended`, `ended_then_quiet`, `status_quiet` (a server
    /// without the stage lines), `dreamer_idle:<reason>`, `timeout`, or
    /// `end_refused:<error>`.
    pub(super) reason: String,
    /// When the round ended, in ms since the run began: when the bench read
    /// the last attempt's terminal line, or the last change of the status.
    pub(super) end_ms: f64,
    pub(super) status_before: DreamerStatus,
    pub(super) status_end: DreamerStatus,
    pub(super) status_reads: usize,
    pub(super) status_errors: usize,
}

impl Waited {
    pub(super) fn refused(error: String, at_ms: f64, before: DreamerStatus) -> Self {
        Self {
            reason: format!("end_refused:{error}"),
            end_ms: at_ms,
            status_end: before.clone(),
            status_before: before,
            status_reads: 0,
            status_errors: 0,
        }
    }
}

/// Whether a stage line's `outcome` ends its attempt: `landed`, `landing`
/// (stopped cleanly with its work landed) or `failed:<kind>`. A
/// `parked:<cause>` or `deferred` attempt resumes in a later pass, so the
/// cycle goes on.
pub(super) fn terminal(outcome: &str) -> bool {
    outcome == "landed" || outcome == "landing" || outcome.starts_with("failed")
}

/// Each Meso attempt's last outcome among the stage lines read at or after
/// `t0_ms`, and when the last of those lines was read. A line of another
/// scope (a Micro wake's, say) is not the round's; a line without `scope`
/// counts.
pub(super) fn outcomes(scan: &Scan, t0_ms: f64) -> (BTreeMap<String, String>, f64) {
    let mut last = BTreeMap::new();
    let mut at_ms = t0_ms;
    let meso = |seen: &&Seen| {
        seen.at_ms >= t0_ms
            && seen
                .fields
                .get("scope")
                .is_none_or(|scope| scope.eq_ignore_ascii_case("meso"))
    };
    for seen in scan.stages.iter().filter(meso) {
        let attempt = seen.fields.get("attempt").cloned().unwrap_or_default();
        let outcome = seen.fields.get("outcome").cloned().unwrap_or_default();
        last.insert(attempt, outcome);
        at_ms = at_ms.max(seen.at_ms);
    }
    (last, at_ms)
}

/// What the wait reads and decides with.
pub(super) struct Wait<'a> {
    pub(super) agent: &'a Agent,
    pub(super) http: &'a Client,
    pub(super) base: &'a str,
    pub(super) origin: Instant,
    pub(super) bound: Duration,
    /// The round plans one partition per conversation, at most.
    pub(super) conversations: usize,
}

impl Wait<'_> {
    /// Waits from `t0` (the sitting's end) until the round ends or the bound
    /// passes. Finished: every partition attempt the stage lines named
    /// ended, and either there was one per conversation or the Dreamer then
    /// stayed still for `QUIET`. A parked attempt that resumes is the same
    /// cycle. On a server without the stage lines: a pass ran after `t0`
    /// and the Dreamer then stayed still for `QUIET`.
    pub(super) fn run(
        &self,
        tail: &mut Tail,
        scan: &mut Scan,
        t0: Instant,
        before: DreamerStatus,
    ) -> Waited {
        let t0_ms = ms_between(self.origin, t0);
        let mut now_status = before.clone();
        let (mut reads, mut errors) = (0, 0);
        let mut changed = Instant::now();
        let mut changed_ms = t0_ms;
        let mut seen_lines = scan.stages.len() + scan.passes.len();
        let mut step = 0_u64;
        let (reason, end_ms) = loop {
            std::thread::sleep(STEP);
            step += 1;
            scan.read(tail, self.origin);
            if step.is_multiple_of(4) {
                reads += 1;
                match status(self.agent, self.http, self.base) {
                    Ok(read) => {
                        if read.tallies() != now_status.tallies() || read.state != now_status.state
                        {
                            changed = Instant::now();
                            changed_ms = ms_between(self.origin, changed);
                        }
                        now_status = read;
                    }
                    Err(_) => errors += 1,
                }
            }
            let lines = scan.stages.len() + scan.passes.len();
            if lines != seen_lines {
                seen_lines = lines;
                changed = Instant::now();
            }
            let (last, last_ms) = outcomes(scan, t0_ms);
            let ended = !last.is_empty() && last.values().all(|o| terminal(o));
            let quiet = changed.elapsed() >= QUIET && now_status.still();
            if ended && last.len() >= self.conversations {
                break ("all_partitions_ended".to_owned(), last_ms);
            }
            if ended && quiet {
                break ("ended_then_quiet".to_owned(), last_ms);
            }
            if !scan.observed() && quiet && now_status.started > before.started {
                break ("status_quiet".to_owned(), changed_ms);
            }
            if now_status.state == "idle" {
                let why = now_status.reason.clone().unwrap_or_default();
                break (
                    format!("dreamer_idle:{why}"),
                    ms_between(self.origin, Instant::now()),
                );
            }
            if t0.elapsed() >= self.bound {
                break (
                    "timeout".to_owned(),
                    ms_between(self.origin, Instant::now()),
                );
            }
        };
        Waited {
            reason,
            end_ms,
            status_before: before,
            status_end: now_status,
            status_reads: reads,
            status_errors: errors,
        }
    }
}
