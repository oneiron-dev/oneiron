//! `ppr-walk-share` — share of High recall wall time in the narrowed PPR walks (UNBUILT3-06).
//! Builds a deterministic linked corpus, then times the `ppr_search_walk`/`ppr_expand_walk` spans.

use std::collections::HashMap;
use std::io::Write as _;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::memory::{
    Memory, MemoryResult, RecallEffort, RecallRequest, RecallRerank, RecallRerankHost,
    RerankDocument, RerankEgress, RerankScores, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::task_verb::sdk::{RecallDoor, recall_at_door};
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, EdgeActorClass, EdgeKind, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::Serialize;

/// Usage printed by `--help` and after a bad flag.
const USAGE: &str = "usage: oneiron-bench ppr-walk-share [--records N] [--edges-per-record K] [--cases C] [--repetitions R] [--seed S] [--out PATH]
Defaults: N=2000 K=4 C=5 R=5 S=42, out = stdout. One JSON object per timed recall, then a {\"summary\": ...} line.";

/// Generated vocabulary: `benchw000`..`benchw399`, one analyzer token each.
const VOCABULARY: usize = 400;
/// Topic clusters: each record carries its topic's word; ~30% of its edges stay in-topic.
const TOPICS: usize = 8;
/// Words per record: 12..=20.
const MIN_WORDS: usize = 12;
const MAX_WORDS: usize = 20;

/// Failures of the subcommand, mapped to [`ExitCode`] by [`run`].
#[derive(Debug, thiserror::Error)]
enum WalkShareError {
    #[error("usage requested")]
    Help,
    #[error("invalid ppr-walk-share argument: {0}")]
    Argument(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("engine error: {0}")]
    Engine(#[from] oneiron::Error),
    #[error("memory error: {0}")]
    Memory(#[from] oneiron::memory::MemoryError),
}

/// Parsed `ppr-walk-share` flags.
struct Settings {
    records: usize,
    edges_per_record: usize,
    cases: usize,
    repetitions: usize,
    seed: u64,
    out: Option<String>,
}

/// Default flags: 2000 records, 4 edges each, 5 cases, 5 repetitions, seed 42, stdout.
fn default_settings() -> Settings {
    Settings {
        records: 2000,
        edges_per_record: 4,
        cases: 5,
        repetitions: 5,
        seed: 42,
        out: None,
    }
}

/// Parses the flags by hand, like the other small subcommands.
fn parse_args(args: &[String]) -> Result<Settings, WalkShareError> {
    let mut settings = default_settings();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Err(WalkShareError::Help);
    }
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let text = value(&mut iter, flag)?;
        match flag.as_str() {
            "--records" => settings.records = positive(text, flag)?,
            "--edges-per-record" => settings.edges_per_record = positive(text, flag)?,
            "--cases" => settings.cases = positive(text, flag)?,
            "--repetitions" => settings.repetitions = positive(text, flag)?,
            "--seed" => settings.seed = unsigned(text, flag)?,
            "--out" => settings.out = Some(text.to_owned()),
            other => return Err(WalkShareError::Argument(format!("unknown flag `{other}`"))),
        }
    }
    Ok(settings)
}

/// The value after a flag; a missing value, or another flag, is an argument error.
fn value<'a>(
    iter: &mut std::slice::Iter<'a, String>,
    flag: &str,
) -> Result<&'a str, WalkShareError> {
    iter.next()
        .map(String::as_str)
        .filter(|text| !text.starts_with("--"))
        .ok_or_else(|| WalkShareError::Argument(format!("missing value for `{flag}`")))
}

/// A positive integer flag value.
fn positive(text: &str, flag: &str) -> Result<usize, WalkShareError> {
    text.parse()
        .ok()
        .filter(|count: &usize| *count > 0)
        .ok_or_else(|| {
            WalkShareError::Argument(format!("{flag} must be a positive integer, got `{text}`"))
        })
}

/// A u64 flag value.
fn unsigned(text: &str, flag: &str) -> Result<u64, WalkShareError> {
    text.parse()
        .map_err(|_| WalkShareError::Argument(format!("{flag} must be a u64, got `{text}`")))
}

/// Busy totals for the two PPR walk spans, in microseconds.
#[derive(Debug, Clone, Copy, Default)]
struct WalkTotals {
    search_us: u64,
    search_count: u64,
    expand_us: u64,
    expand_count: u64,
}

/// Which walk span an open span belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkKind {
    Search,
    Expand,
}

/// The walk kind of a span name, when it names a PPR walk span.
fn walk_kind(name: &str) -> Option<WalkKind> {
    match name {
        "ppr_search_walk" => Some(WalkKind::Search),
        "ppr_expand_walk" => Some(WalkKind::Expand),
        _ => None,
    }
}

/// One open walk span: its kind, when last entered, and busy time across enters.
struct OpenSpan {
    kind: WalkKind,
    entered_at: Option<Instant>,
    busy: Duration,
}

/// The timer's shared state: fresh ids, open spans, and per-name totals.
struct WalkTimerState {
    next_id: u64,
    open: HashMap<u64, OpenSpan>,
    totals: WalkTotals,
}

/// A [`tracing::Subscriber`] timing the two PPR walk spans, ignoring the rest. Clones share
/// state, so the installed subscriber and the [`WalkTimer::take`] handle read one.
#[derive(Clone)]
struct WalkTimer {
    state: Arc<Mutex<WalkTimerState>>,
}

impl WalkTimer {
    /// A fresh timer with zeroed totals.
    fn new() -> Self {
        let state = WalkTimerState {
            next_id: 1,
            open: HashMap::new(),
            totals: WalkTotals::default(),
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Returns the totals accumulated since the last call and resets them.
    fn take(&self) -> WalkTotals {
        std::mem::take(&mut self.lock().totals)
    }

    /// Locks the state, recovering past a poisoned mutex.
    fn lock(&self) -> std::sync::MutexGuard<'_, WalkTimerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl tracing::Subscriber for WalkTimer {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_span() && walk_kind(metadata.name()).is_some()
    }

    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if self.enabled(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut state = self.lock();
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1).max(1);
        if let Some(kind) = walk_kind(span.metadata().name()) {
            let open = OpenSpan {
                kind,
                entered_at: None,
                busy: Duration::ZERO,
            };
            state.open.insert(id, open);
        }
        tracing::span::Id::from_u64(id)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, span: &tracing::span::Id) {
        if let Some(open) = self.lock().open.get_mut(&span.into_u64()) {
            open.entered_at = Some(Instant::now());
        }
    }

    fn exit(&self, span: &tracing::span::Id) {
        if let Some(open) = self.lock().open.get_mut(&span.into_u64())
            && let Some(entered_at) = open.entered_at.take()
        {
            open.busy += entered_at.elapsed();
        }
    }

    fn try_close(&self, id: tracing::span::Id) -> bool {
        let open = self.lock().open.remove(&id.into_u64());
        let Some(open) = open else { return true };
        let us = open.busy.as_micros().min(u128::from(u64::MAX)) as u64;
        let totals = &mut self.lock().totals;
        if open.kind == WalkKind::Search {
            totals.search_us += us;
            totals.search_count += 1;
        } else {
            totals.expand_us += us;
            totals.expand_count += 1;
        }
        true
    }
}

/// A [`RecallRerankHost`] scoring each block in order, highest first, with no model latency: the
/// measured walk share is an upper bound for a recall with a real reranker.
struct StubReranker {
    lease: BudgetLease,
}

impl RecallRerankHost for StubReranker {
    fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    fn score(
        &self,
        _query: &str,
        documents: &[RerankDocument<'_>],
        _egress: &RerankEgress<'_>,
        _answer_at: Option<Instant>,
        _cancel: Option<oneiron::llm::WorkCancel>,
    ) -> MemoryResult<RerankScores> {
        Ok(RerankScores {
            scores: (0..documents.len()).map(|rank| -(rank as f32)).collect(),
            model: "bench/stub-reranker@v1".to_owned(),
            served_model: None,
        })
    }
}

/// A deterministic entity id from the corpus stream; reserved patterns retry.
fn gen_id(rng: &mut StdRng) -> EntityId {
    loop {
        let mut bytes = [0_u8; 16];
        rng.fill(&mut bytes);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
    }
}

/// Witnesses `settings.records` turns as the owner, each message in the message space `space`
/// (so a reader holding a `MessagesRead` grant on it reads them), and links them with
/// `settings.edges_per_record` `Mentions` edges each, ~30% in-topic. Returns the record texts.
/// Setup, not timed.
fn build_corpus(
    vault: &Vault,
    owner: EntityId,
    space: EntityId,
    settings: &Settings,
    rng: &mut StdRng,
) -> Result<Vec<String>, WalkShareError> {
    let vocabulary: Vec<String> = (0..VOCABULARY)
        .map(|word| format!("benchw{word:03}"))
        .collect();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let mut turns = Vec::with_capacity(settings.records);
    let mut texts = Vec::with_capacity(settings.records);
    let mut topics = Vec::with_capacity(settings.records);
    for _ in 0..settings.records {
        let topic = rng.gen_range(0..TOPICS);
        let mut text = vocabulary[topic].clone();
        for _ in 1..rng.gen_range(MIN_WORDS..=MAX_WORDS) {
            text.push(' ');
            text.push_str(&vocabulary[rng.gen_range(0..VOCABULARY)]);
        }
        let receipt = memory.witness(&WitnessTurn {
            conversation_ref: gen_id(rng).to_hex(),
            turn_ref: Some(gen_id(rng).to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(gen_id(rng).to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: text.clone(),
                parts: None,
                metadata: Some(serde_json::json!({ "rel": space.to_hex() })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
        turns.push(receipt.turn_id);
        texts.push(text);
        topics.push(topic);
    }
    let mut by_topic = vec![Vec::new(); TOPICS];
    for (index, topic) in topics.iter().enumerate() {
        by_topic[*topic].push(index);
    }
    for (index, from) in turns.iter().enumerate() {
        for _ in 0..settings.edges_per_record {
            let pool = &by_topic[topics[index]];
            let mut target = if rng.gen_range(0.0..1.0) < 0.3 {
                pool[rng.gen_range(0..pool.len())]
            } else {
                rng.gen_range(0..turns.len())
            };
            if target == index {
                target = (target + 1) % turns.len();
            }
            let weight = rng.gen_range(0.2..1.0);
            vault.put_edge(from, EdgeKind::Mentions, &turns[target], weight)?;
        }
    }
    Ok(texts)
}

/// Case queries: 2-3 words from one record's text, so each query has a lexical hit.
fn gen_queries(rng: &mut StdRng, texts: &[String], cases: usize) -> Vec<String> {
    (0..cases)
        .map(|_| {
            let words: Vec<&str> = texts[rng.gen_range(0..texts.len())].split(' ').collect();
            (0..rng.gen_range(2..=3))
                .map(|_| words[rng.gen_range(0..words.len())])
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// One timed High recall, emitted as one JSON line.
#[derive(Debug, Serialize)]
struct CallRow {
    case: usize,
    query: String,
    reader: &'static str,
    rep: usize,
    wall_us: u64,
    search_walk_us: u64,
    search_walks: u64,
    expand_walk_us: u64,
    expand_walks: u64,
    results: usize,
    error: Option<String>,
}

/// One High recall through the reranked door, timed wall-clock. A recall error is returned as a
/// string, never raised: the run goes on.
fn timed_recall(memory: &Memory<'_>, query: &str) -> (usize, Option<String>, u64) {
    let guard = BudgetGuard::new(
        "ppr-walk-share",
        10_000_000,
        BudgetExhaustionPolicy::Suspend,
    );
    let lease = match guard.admit() {
        Ok(admission) => admission.lease,
        Err(denied) => return (0, Some(format!("budget admission refused: {denied:?}")), 0),
    };
    let host = StubReranker { lease };
    let started = Instant::now();
    let outcome = recall_at_door(
        memory,
        RecallRequest {
            query: query.to_owned(),
            effort: Some(RecallEffort::High),
            limit: Some(10),
            ..RecallRequest::default()
        },
        |_| None,
        &RecallDoor {
            hyde: None,
            arrived: Instant::now(),
            on_cut: None,
            rerank: RecallRerank::Host(&host),
        },
    );
    let wall_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    match outcome {
        Ok(pack) => (pack.items.len(), None, wall_us),
        Err(error) => (0, Some(error.to_string()), wall_us),
    }
}

/// The bench core [`run`] and the smoke test share: builds the vault, corpus and readers, times
/// the High recalls, and writes one JSON line per timed call plus a summary line. The caller
/// installs `timer` ([`run`] globally, the test thread-locally); recall runs on the calling
/// thread, so either sees the walk spans.
fn run_with(
    timer: &WalkTimer,
    settings: &Settings,
    out: &mut dyn std::io::Write,
) -> Result<Vec<CallRow>, WalkShareError> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor()?;
    bind_host_owner(&vault, &test_host_issuer(), owner)?;
    let mut rng = StdRng::seed_from_u64(settings.seed);
    let agent = gen_id(&mut rng);
    vault.put_entity(
        &agent,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"ppr-walk-share agent",
    )?;
    vault.install_read_permit_for_test(WriteActor::new(agent, EdgeActorClass::Agent))?;
    // A permit alone reads no message: a message with no space is the owner's, and one in a
    // space needs a MessagesRead grant on it (the fleet bench's own setup, fleet/workload.rs).
    let space = gen_id(&mut rng);
    vault.create_access_grant(
        &gen_id(&mut rng),
        &AccessGrant {
            authority_scope: oneiron::federation::Scope::top(),
            principal_ref: agent,
            scope: AccessGrantScope::Messages { space_ref: space },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: vault.now_recorded_at(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    let texts = build_corpus(&vault, owner, space, settings, &mut rng)?;
    let queries = gen_queries(&mut rng, &texts, settings.cases);
    let readers = [
        ("owner", vault.memory(owner, EdgeActorClass::Human)),
        ("agent", vault.memory(agent, EdgeActorClass::Agent)),
    ];
    let mut rows = Vec::new();
    for (case, query) in queries.iter().enumerate() {
        for (reader, memory) in &readers {
            for rep in 0..=settings.repetitions {
                timer.take();
                let (results, error, wall_us) = timed_recall(memory, query);
                let totals = timer.take();
                if rep == 0 {
                    continue;
                }
                rows.push(CallRow {
                    case,
                    query: query.clone(),
                    reader: *reader,
                    rep,
                    wall_us,
                    search_walk_us: totals.search_us,
                    search_walks: totals.search_count,
                    expand_walk_us: totals.expand_us,
                    expand_walks: totals.expand_count,
                    results,
                    error,
                });
            }
        }
    }
    for row in &rows {
        serde_json::to_writer(&mut *out, row)?;
        out.write_all(b"\n")?;
    }
    serde_json::to_writer(&mut *out, &summary(&rows, settings))?;
    out.write_all(b"\n")?;
    Ok(rows)
}

/// Nearest-rank percentile over ascending samples; 0.0 when empty.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Median and p95 of one reader's wall times, walk shares and expand-only shares.
fn reader_summary(rows: &[CallRow], reader: &str) -> serde_json::Value {
    let mut wall = Vec::new();
    let mut share = Vec::new();
    let mut expand = Vec::new();
    for row in rows.iter().filter(|row| row.reader == reader) {
        wall.push(row.wall_us as f64);
        let walk_us = (row.search_walk_us + row.expand_walk_us) as f64;
        let wall_us = row.wall_us as f64;
        share.push(if wall_us > 0.0 {
            walk_us / wall_us
        } else {
            0.0
        });
        expand.push(if wall_us > 0.0 {
            row.expand_walk_us as f64 / wall_us
        } else {
            0.0
        });
    }
    for samples in [&mut wall, &mut share, &mut expand] {
        samples.sort_by(f64::total_cmp);
    }
    serde_json::json!({
        "calls": wall.len(),
        "wall_us": {"median": percentile(&wall, 50.0), "p95": percentile(&wall, 95.0)},
        "walk_share": {"median": percentile(&share, 50.0), "p95": percentile(&share, 95.0)},
        "expand_share": {"median": percentile(&expand, 50.0), "p95": percentile(&expand, 95.0)},
    })
}

/// The final summary line: per-reader medians, the corpus, and the stub-reranker caveat.
fn summary(rows: &[CallRow], settings: &Settings) -> serde_json::Value {
    serde_json::json!({
        "summary": {
            "owner": reader_summary(rows, "owner"),
            "agent": reader_summary(rows, "agent"),
            "corpus": {
                "records": settings.records,
                "requested_edges": settings.records.saturating_mul(settings.edges_per_record),
                "seed": settings.seed,
            },
            "note": "stub reranker (no model latency): the share is an upper bound for a recall with a real reranker. A paid High recall_at_door runs the retrieval pipeline twice per call (capture and scored passes); recall_in_session runs one pass of the same pipeline (memory/recall/admission.rs:164), so compare the share, not per-call times or walk counts. requested_edges counts edge writes; repeated pairs upsert",
        }
    })
}

/// Runs `ppr-walk-share`: installs the walk timer once per process, then drives [`run_with`].
/// `--help` exits 0; a bad flag exits 2.
pub(crate) fn run(args: &[String]) -> ExitCode {
    let settings = match parse_args(args) {
        Ok(settings) => settings,
        Err(WalkShareError::Help) => {
            let _ = writeln!(std::io::stdout().lock(), "{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error @ WalkShareError::Argument(_)) => {
            let _ = writeln!(std::io::stderr().lock(), "ppr-walk-share: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "ppr-walk-share: {error}");
            return ExitCode::FAILURE;
        }
    };
    let timer = WalkTimer::new();
    if let Err(error) = tracing::subscriber::set_global_default(timer.clone()) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "ppr-walk-share: cannot install the walk timer: {error:?}"
        );
        return ExitCode::FAILURE;
    }
    let outcome = match &settings.out {
        Some(path) => std::fs::File::create(path)
            .map_err(WalkShareError::from)
            .and_then(|mut file| run_with(&timer, &settings, &mut file)),
        None => run_with(&timer, &settings, &mut std::io::stdout().lock()),
    };
    match outcome {
        Ok(rows) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "ppr-walk-share: {} timed recalls",
                rows.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "ppr-walk-share: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N=60, K=3, C=1, R=1 over a thread-local timer: each reader has one error-free row that
    /// recalls the corpus, an expand walk ran per row, and no row's walks outlast its wall time.
    #[test]
    fn smoke_times_both_walks_within_wall() {
        let timer = WalkTimer::new();
        let settings = Settings {
            records: 60,
            edges_per_record: 3,
            cases: 1,
            repetitions: 1,
            seed: 7,
            out: None,
        };
        let mut jsonl = Vec::new();
        let rows = tracing::subscriber::with_default(timer.clone(), || {
            run_with(&timer, &settings, &mut jsonl)
        })
        .expect("the smoke run completes");
        assert_eq!(rows.len(), 2, "one timed row per reader: {rows:?}");
        for row in &rows {
            assert_eq!(row.error, None, "a row without error: {row:?}");
            assert!(
                row.search_walk_us + row.expand_walk_us <= row.wall_us,
                "walks within wall: {row:?}",
            );
            assert_ne!(row.expand_walks, 0, "an expand walk ran: {row:?}");
            assert_ne!(row.results, 0, "the reader recalls the corpus: {row:?}");
        }
        let text = String::from_utf8(jsonl).expect("utf-8 jsonl");
        assert_eq!(text.lines().count(), 3, "two rows and a summary");
        assert!(text.contains("\"summary\""), "a summary line");
    }
}
