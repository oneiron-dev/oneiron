//! Systems other than Oneiron on the lives screen (L9-36-COMPETITORS = A: this
//! is the seam; each competitor's adapter is its own row). The bench speaks
//! one small JSON protocol to an adapter that fronts the system's own SDK:
//!
//! * `POST /v1/lives/reset {store}`
//! * `POST /v1/lives/ingest {store, conversation, at, turn: {id, role, text}}` → `{system_ms?}`
//! * `POST /v1/lives/settle {store}` → `{ready}`, polled every second
//! * `POST /v1/lives/search {store, query, k, as_of}` → `{items: [{text}], system_ms?}`
//!
//! Every adapter gets the turns, conversation ids, times and texts the
//! Oneiron store gets, and the same questions at the same `as_of`. `ms` is the
//! bench's round trip; `system_ms` is the adapter's own timing of the
//! system's call, so network time sits apart from server time (ARCH-0042
//! #lives-bench). A system that never settles is reported `not_ready` with
//! its reason, and the others still run.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::super::server::loopback_url;
use super::super::stats::{Sample, Summary};
use super::corpus::{Life, Role};
use super::report::{Answer, Row, System, summarize};
use super::{Plan, say};

/// One `--system <name>=<url>`.
pub(super) struct External {
    pub(super) name: String,
    pub(super) url: reqwest::Url,
}

/// Parses `--system`'s value. An adapter is https, or plain http on loopback
/// only, with no credentials, query or fragment (the Chroma arm's rule).
pub(super) fn external(value: &str) -> Result<External, String> {
    let (name, url) = value.split_once('=').ok_or("--system is <name>=<url>")?;
    if name.is_empty()
        || name == "oneiron"
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "--system {name}: a name is letters, digits, - and _, and not `oneiron`"
        ));
    }
    let url = reqwest::Url::parse(url).map_err(|e| format!("--system {name}: {e}"))?;
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback_url(&url)))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "--system {name}: an adapter is https, or http on loopback, with no credentials, query or fragment"
        ));
    }
    Ok(External {
        name: name.to_owned(),
        url,
    })
}

fn role(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

/// One adapter and the store it fills.
struct Adapter<'a> {
    http: reqwest::blocking::Client,
    system: &'a External,
    store: String,
}

impl Adapter<'_> {
    /// POSTs `body` to `/v1/lives/<op>`; the time covers the round trip.
    fn post(&self, op: &str, body: &Value) -> (f64, Result<Value, String>) {
        let url = format!(
            "{}/v1/lives/{op}",
            self.system.url.as_str().trim_end_matches('/')
        );
        let started = Instant::now();
        let answer = self
            .http
            .post(url)
            .json(body)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    "timeout".to_owned()
                } else {
                    "transport".to_owned()
                }
            })
            .and_then(|response| {
                let status = response.status();
                let text = response.text().map_err(|_| "body".to_owned())?;
                if status.is_success() {
                    serde_json::from_str::<Value>(&text).map_err(|_| "json".to_owned())
                } else {
                    Err(status.as_u16().to_string())
                }
            });
        (started.elapsed().as_secs_f64() * 1000.0, answer)
    }

    /// Polls settle every second until the adapter says ready or `max` passes.
    fn settle(&self, max: Duration) -> Result<f64, String> {
        let started = Instant::now();
        loop {
            let (_, answer) = self.post("settle", &json!({"store": self.store}));
            match answer {
                Ok(body) if body["ready"] == true => return Ok(started.elapsed().as_secs_f64()),
                Ok(_) => {}
                Err(error) => return Err(format!("settle: {error}")),
            }
            if started.elapsed() >= max {
                return Err(format!("not ready after {} s", max.as_secs()));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

/// The adapter's items, each as its one text, in rank order.
fn texts(body: &Value) -> Vec<Vec<String>> {
    body["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["text"].as_str())
                .map(|text| vec![text.to_owned()])
                .collect()
        })
        .unwrap_or_default()
}

fn not_ready(name: &str, reason: String) -> System {
    say(&format!("{name}: not ready: {reason}"));
    System {
        name: name.to_owned(),
        status: "not_ready",
        reason: Some(reason),
        documents: 0,
        ingest: Summary::default(),
        settle_seconds: 0.0,
        drain_seconds: None,
        disk_mib: None,
        summary: Vec::new(),
        rows: Vec::new(),
    }
}

/// Ingests `lives` through `system`'s adapter into a fresh store and asks
/// their questions at every grade.
pub(super) fn measure(plan: &Plan, system: &External, lives: &[Life], store: &str) -> System {
    let http = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(http) => http,
        Err(e) => return not_ready(&system.name, format!("http client: {e}")),
    };
    let adapter = Adapter {
        http,
        system,
        store: store.to_owned(),
    };
    if let (_, Err(error)) = adapter.post("reset", &json!({"store": store})) {
        return not_ready(&system.name, format!("reset: {error}"));
    }
    let turns = lives.iter().map(|life| life.turns.len()).sum::<usize>();
    say(&format!("{}: ingest {turns} turns", system.name));
    let started = Instant::now();
    let mut samples = Vec::with_capacity(turns);
    for turn in lives.iter().flat_map(|life| &life.turns) {
        let body = json!({
            "store": store,
            "conversation": turn.conversation,
            "at": turn.at,
            "turn": {"id": turn.id, "role": role(turn.role), "text": turn.text},
        });
        let (ms, answer) = adapter.post("ingest", &body);
        samples.push(Sample {
            ms,
            error: answer.err(),
            partial: false,
            items: 1,
        });
    }
    let ingest = Summary::of(&samples, started.elapsed().as_secs_f64());
    let documents = ingest.completed;
    if documents == 0 && turns > 0 {
        return not_ready(
            &system.name,
            format!("every ingest failed: {:?}", ingest.failures),
        );
    }
    let settle_seconds = match adapter.settle(plan.settle_max) {
        Ok(seconds) => seconds,
        Err(reason) => return not_ready(&system.name, reason),
    };
    let mut rows = Vec::new();
    let mut seconds = BTreeMap::new();
    for grade in &plan.grades {
        say(&format!("{}: ask, grade {grade}", system.name));
        let started = Instant::now();
        for life in lives {
            for (set, question) in &life.questions {
                let body = json!({
                    "store": store, "query": question.question, "k": plan.limit, "as_of": life.end,
                });
                let (ms, answer) = adapter.post("search", &body);
                let answer = match answer {
                    Ok(body) => Answer {
                        ms,
                        partial: false,
                        items: texts(&body),
                        system_ms: body["system_ms"].as_f64(),
                        error: None,
                    },
                    Err(error) => Answer {
                        ms,
                        partial: false,
                        items: Vec::new(),
                        system_ms: None,
                        error: Some(error),
                    },
                };
                rows.push(Row::of(&system.name, grade, life, *set, question, answer));
            }
        }
        seconds.insert(grade.clone(), started.elapsed().as_secs_f64());
    }
    System {
        name: system.name.clone(),
        status: "measured",
        reason: None,
        documents,
        ingest: ingest.below_corpus_floor(documents),
        settle_seconds,
        drain_seconds: None,
        disk_mib: None,
        summary: summarize(&rows, &plan.grades, &seconds, documents),
        rows,
    }
}
