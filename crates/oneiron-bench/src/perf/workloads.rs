//! ONE-1579 workloads: corpus, warm/cold retrieval, concurrent sessions, the
//! TCP-accept wake probe, ten-ready-children resident memory, gated writes and
//! bench-owned cache-event ingest.
//!
//! Engine boundary: every engine touch in this module goes through a PUBLIC
//! seam and nothing else. Retrieval is `Vault::search_text_with_telemetry`,
//! writes are `ClaimCandidate` + `WriteEnvelope` through
//! `BatchBuilder::claim_candidate` and `commit`, and the gate ledger is read
//! back through `Vault::gate_decisions`. `vault.rs` and `ppr.rs` retrieval
//! internals are never instrumented, and there is no raw LMDB write anywhere.
//!
//! Readiness boundary: a child is ready when, and only when, the parent's TCP
//! `accept` for it has completed. Children are spawned with all three standard
//! streams pointed at `/dev/null`, so there is no log text for this harness to
//! read even if someone later wanted to.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::report::{
    ARCH_0023B_PER_VAULT_BUDGET_MB, Cell, EvidenceKind, GATED_WRITE_PATH, GatedWriteAxis,
    Percentiles, READINESS_RULE, ReadinessSignal, ResidentMemoryAxis, RunMode, SampleSet,
    SessionCurvePoint, WakeAxis,
};

/// Embedding identity stamped on every perf vault. Bench-owned; it never
/// collides with a product vault's model id.
pub(crate) const BENCH_EMBEDDING_MODEL: &str = "bench/perf-harness@v1";
/// Predicate used by the gated-write axis. `profile.*` is an ordinary,
/// non-reserved namespace, so the write travels the public claim door.
pub(crate) const GATED_WRITE_PREDICATE: &str = "profile.bench_perf_gated_write";
/// Environment override naming the program the ready-children probes spawn.
pub(crate) const CHILD_PROGRAM_ENV: &str = "ONEIRON_BENCH_PERF_CHILD";
/// Accept poll granularity for the wake probe, in microseconds.
pub(crate) const ACCEPT_POLL_INTERVAL_US: u64 = 100;
/// Entity type used for the corpus documents and the gated-write subject.
const BENCH_ENTITY_TYPE: u8 = 1;

const VOCAB: [&str; 24] = [
    "vault",
    "recall",
    "latency",
    "session",
    "commit",
    "gate",
    "vector",
    "prefix",
    "rescore",
    "cache",
    "rung",
    "fsync",
    "cold",
    "warm",
    "child",
    "probe",
    "corpus",
    "seed",
    "sample",
    "budget",
    "curve",
    "throughput",
    "envelope",
    "candidate",
];

// ─── corpus ──────────────────────────────────────────────────────────────

/// One indexed document. The marker is a unique nonsense token planted in the
/// body so the harness owns its ground truth instead of guessing at it.
pub(crate) struct CorpusDoc {
    pub(crate) id: EntityId,
    pub(crate) marker: String,
    pub(crate) text: String,
}

/// One query plus the document it must retrieve.
pub(crate) struct CorpusQuery {
    pub(crate) text: String,
    pub(crate) expected: EntityId,
}

/// The seeded, deterministic corpus a run is measured against.
pub(crate) struct Corpus {
    pub(crate) docs: Vec<CorpusDoc>,
    pub(crate) queries: Vec<CorpusQuery>,
    /// Bench-side vectors for the precision axis. These never reach a vault.
    pub(crate) vectors: Vec<Vec<f32>>,
    pub(crate) query_vectors: Vec<Vec<f32>>,
    pub(crate) hash: String,
}

/// Builds the corpus from one seeded `StdRng` stream in a fixed order, so the
/// same seed reproduces the same corpus, the same queries and the same hash.
pub(crate) fn generate_corpus(
    seed: u64,
    docs: usize,
    queries: usize,
    dimensions: usize,
) -> Result<Corpus, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut corpus_docs = Vec::with_capacity(docs);
    let mut vectors = Vec::with_capacity(docs);
    for index in 0..docs {
        let marker = marker_token(index);
        let body = doc_text(&mut rng, &marker);
        corpus_docs.push(CorpusDoc {
            id: gen_entity_id(&mut rng)?,
            marker,
            text: body,
        });
        vectors.push(gen_vector(&mut rng, dimensions));
    }

    let mut corpus_queries = Vec::with_capacity(queries);
    let mut query_vectors = Vec::with_capacity(queries);
    for index in 0..queries {
        let anchor = if corpus_docs.is_empty() {
            0
        } else {
            (index * corpus_docs.len()) / queries.max(1)
        };
        let Some(doc) = corpus_docs.get(anchor) else {
            break;
        };
        corpus_queries.push(CorpusQuery {
            text: doc.marker.clone(),
            expected: doc.id,
        });
        query_vectors.push(perturb(&mut rng, &vectors[anchor]));
    }

    let hash = corpus_hash(&corpus_docs, &vectors);
    Ok(Corpus {
        docs: corpus_docs,
        queries: corpus_queries,
        vectors,
        query_vectors,
        hash,
    })
}

/// `qzmk` plus five base-26 letters: a unique, pure-ASCII-lowercase token that
/// survives analysis as one surface form.
fn marker_token(index: usize) -> String {
    let mut token = String::from("qzmk");
    let mut remaining = index;
    for _ in 0..5 {
        let letter = b'a' + u8::try_from(remaining % 26).unwrap_or(0);
        token.push(char::from(letter));
        remaining /= 26;
    }
    token
}

fn doc_text(rng: &mut StdRng, marker: &str) -> String {
    let mut text = String::from(marker);
    for _ in 0..8 {
        text.push(' ');
        text.push_str(VOCAB[rng.gen_range(0..VOCAB.len())]);
    }
    text
}

fn gen_entity_id(rng: &mut StdRng) -> Result<EntityId, String> {
    for _ in 0..64 {
        let mut bytes = [0_u8; 16];
        rng.fill(&mut bytes);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err("could not draw a valid entity id from the seeded stream".to_owned())
}

fn gen_vector(rng: &mut StdRng, dimensions: usize) -> Vec<f32> {
    (0..dimensions)
        .map(|_| rng.gen_range(-1.0_f32..1.0))
        .collect()
}

fn perturb(rng: &mut StdRng, base: &[f32]) -> Vec<f32> {
    base.iter()
        .map(|value| value + 0.1 * rng.gen_range(-1.0_f32..1.0))
        .collect()
}

fn corpus_hash(docs: &[CorpusDoc], vectors: &[Vec<f32>]) -> String {
    let mut hasher = blake3::Hasher::new();
    for doc in docs {
        hasher.update(doc.id.as_bytes());
        hasher.update(doc.text.as_bytes());
    }
    for vector in vectors {
        for value in vector {
            hasher.update(&value.to_le_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

// ─── vault ───────────────────────────────────────────────────────────────

/// Vault config for a perf run. Text-only: the precision axis works on the
/// bench's own vectors, so no vector or embedding row is ever written.
pub(crate) fn perf_vault_config(docs: usize, max_sessions: usize) -> VaultConfig {
    const MIB: usize = 1024 * 1024;
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some(BENCH_EMBEDDING_MODEL.to_owned());
    config.map_size = docs
        .saturating_mul(16 * 1024)
        .saturating_add(512 * MIB)
        .div_ceil(MIB)
        .saturating_mul(MIB);
    config.max_readers = u32::try_from(max_sessions.saturating_mul(2).saturating_add(64))
        .unwrap_or(1024)
        .max(128);
    config
}

/// Vault config for a ready child. Small on purpose: the child exists to be a
/// real process holding a real open vault, not to hold a corpus.
pub(crate) fn child_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some(BENCH_EMBEDDING_MODEL.to_owned());
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 16;
    config
}

/// Indexes the corpus in chunks through the public batch door.
pub(crate) fn index_corpus(vault: &Vault, corpus: &Corpus) -> Result<f64, String> {
    let started = Instant::now();
    for chunk in corpus.docs.chunks(200) {
        let mut batch = vault.batch();
        for doc in chunk {
            batch = batch
                .put(
                    &doc.id,
                    BENCH_ENTITY_TYPE,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"perf-doc",
                )
                .text(&doc.id, &[("body", doc.text.as_str())]);
        }
        batch
            .commit()
            .map_err(|error| format!("corpus index commit failed: {error}"))?;
    }
    Ok(started.elapsed().as_secs_f64() * 1e3)
}

/// One pass over every query. Latency, recall and telemetry presence are kept
/// as parallel per-query samples so no caller can collapse them.
struct QueryPass {
    latency_ms: Vec<f64>,
    recall: Vec<f64>,
    telemetry_run_ids: usize,
    errors: usize,
}

fn query_pass(vault: &Vault, corpus: &Corpus, k: usize) -> QueryPass {
    let mut pass = QueryPass {
        latency_ms: Vec::with_capacity(corpus.queries.len()),
        recall: Vec::with_capacity(corpus.queries.len()),
        telemetry_run_ids: 0,
        errors: 0,
    };
    for query in &corpus.queries {
        let started = Instant::now();
        let outcome = vault.search_text_with_telemetry(&query.text, k);
        let elapsed_ms = started.elapsed().as_secs_f64() * 1e3;
        match outcome {
            Ok(result) => {
                pass.latency_ms.push(elapsed_ms);
                if result.run_id.is_some() {
                    pass.telemetry_run_ids += 1;
                }
                let found = result.value.iter().any(|hit| hit.id == query.expected);
                pass.recall.push(if found { 1.0 } else { 0.0 });
            }
            Err(_) => pass.errors += 1,
        }
    }
    pass
}

fn sample_set(label: &'static str, pass: &QueryPass) -> SampleSet {
    SampleSet::new(
        label,
        &pass.latency_ms,
        &pass.recall,
        pass.telemetry_run_ids,
        pass.errors,
    )
}

/// COLD: the caller must hand a vault handle that has just been opened and has
/// served nothing. Nothing is pre-seeded, warmed or replayed before this call,
/// and the pass runs exactly once.
pub(crate) fn measure_cold(vault: &Vault, corpus: &Corpus, k: usize) -> SampleSet {
    sample_set("cold", &query_pass(vault, corpus, k))
}

/// WARM: `warmup_passes` discarded passes first, then one measured pass. The
/// samples never join the cold set.
pub(crate) fn measure_warm(
    vault: &Vault,
    corpus: &Corpus,
    k: usize,
    warmup_passes: usize,
) -> SampleSet {
    for _ in 0..warmup_passes {
        let _ = query_pass(vault, corpus, k);
    }
    sample_set("warm", &query_pass(vault, corpus, k))
}

// ─── concurrent sessions ─────────────────────────────────────────────────

#[derive(Default)]
struct SessionOutcome {
    latency_ms: Vec<f64>,
    errors: usize,
}

/// Walks `curve`, running `sessions` concurrent readers against ONE vault.
pub(crate) fn measure_session_curve(
    vault: &Arc<Vault>,
    corpus: &Corpus,
    k: usize,
    curve: &[usize],
    queries_per_session: usize,
) -> Vec<SessionCurvePoint> {
    let mut points = Vec::with_capacity(curve.len());
    for sessions in curve {
        points.push(session_point(
            vault,
            corpus,
            k,
            *sessions,
            queries_per_session,
        ));
    }
    points
}

fn session_point(
    vault: &Arc<Vault>,
    corpus: &Corpus,
    k: usize,
    sessions: usize,
    queries_per_session: usize,
) -> SessionCurvePoint {
    let started = Instant::now();
    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(sessions);
        for session in 0..sessions {
            let vault = Arc::clone(vault);
            handles
                .push(scope.spawn(move || {
                    session_worker(&vault, corpus, k, queries_per_session, session)
                }));
        }
        let mut joined = Vec::with_capacity(sessions);
        for handle in handles {
            joined.push(handle.join());
        }
        joined
    });
    let wall_clock_ms = started.elapsed().as_secs_f64() * 1e3;

    let mut latency_ms = Vec::with_capacity(sessions * queries_per_session);
    let mut errors = 0_usize;
    for outcome in outcomes {
        match outcome {
            Ok(outcome) => {
                latency_ms.extend_from_slice(&outcome.latency_ms);
                errors += outcome.errors;
            }
            Err(_) => errors += queries_per_session,
        }
    }
    let completed = latency_ms.len();
    SessionCurvePoint {
        sessions,
        queries: completed,
        wall_clock_ms,
        latency_ms: Cell::from_option(
            Percentiles::from_samples(&latency_ms),
            format!("no query completed at {sessions} concurrent session(s)"),
        ),
        throughput_qps: if wall_clock_ms > 0.0 && completed > 0 {
            Cell::measured(completed as f64 / (wall_clock_ms / 1e3))
        } else {
            Cell::not_ready(format!(
                "no completed query at {sessions} concurrent session(s) to derive throughput from"
            ))
        },
        errors,
    }
}

fn session_worker(
    vault: &Vault,
    corpus: &Corpus,
    k: usize,
    queries_per_session: usize,
    session: usize,
) -> SessionOutcome {
    let mut outcome = SessionOutcome::default();
    if corpus.queries.is_empty() {
        return outcome;
    }
    for step in 0..queries_per_session {
        let query = &corpus.queries[(session + step) % corpus.queries.len()];
        let started = Instant::now();
        let result = vault.search_text_with_telemetry(&query.text, k);
        let elapsed_ms = started.elapsed().as_secs_f64() * 1e3;
        match result {
            Ok(_) => outcome.latency_ms.push(elapsed_ms),
            Err(_) => outcome.errors += 1,
        }
    }
    outcome
}

// ─── TCP-accept wake probe ───────────────────────────────────────────────

/// A bound loopback listener whose completed `accept` IS the readiness signal.
///
/// The probe has no API that consumes child output: there is no log reader, no
/// stdout scan and no "sleep then assume ready" path anywhere on this type.
pub(crate) struct WakeProbe {
    listener: TcpListener,
}

/// One child that reached ready. The stream is held so the parent can keep the
/// child alive and then release it by closing the socket.
pub(crate) struct ReadyChild {
    pub(crate) elapsed_ms: f64,
    pub(crate) signal: ReadinessSignal,
    pub(crate) stream: TcpStream,
}

impl WakeProbe {
    pub(crate) fn bind() -> Result<Self, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| format!("wake probe could not bind loopback: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("wake probe could not arm its listener: {error}"))?;
        Ok(Self { listener })
    }

    pub(crate) fn addr(&self) -> Result<SocketAddr, String> {
        self.listener
            .local_addr()
            .map_err(|error| format!("wake probe has no local address: {error}"))
    }

    /// Blocks until a child connects. The elapsed time is measured from the
    /// caller's `started` instant (taken immediately before the spawn) to the
    /// completed accept — never to a log line, a sleep or a stdout token.
    pub(crate) fn wait_ready(
        &self,
        started: Instant,
        timeout: Duration,
    ) -> Result<ReadyChild, String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let elapsed_ms = started.elapsed().as_secs_f64() * 1e3;
                    stream
                        .set_nonblocking(false)
                        .map_err(|error| format!("ready stream could not be armed: {error}"))?;
                    return Ok(ReadyChild {
                        elapsed_ms,
                        signal: ReadinessSignal::TcpAccept,
                        stream,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(format!("no TCP accept within {timeout:?}"));
                    }
                    std::thread::sleep(Duration::from_micros(ACCEPT_POLL_INTERVAL_US));
                }
                Err(error) => return Err(format!("wake probe accept failed: {error}")),
            }
        }
    }
}

/// A caller-supplied child program. `{ready_addr}`, `{vault_dir}` and
/// `{hold_ms}` are substituted into each argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChildCommandPlan {
    pub(crate) program: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
}

/// Sizing for the wake and ready-children probes.
pub(crate) struct ChildSettings {
    pub(crate) samples: usize,
    pub(crate) timeout_ms: u64,
    pub(crate) hold_ms: u64,
    pub(crate) child: Option<ChildCommandPlan>,
}

/// Resolves the program the harness will spawn as its ready child.
pub(crate) fn resolve_child_program() -> Result<PathBuf, String> {
    if let Ok(pinned) = std::env::var(CHILD_PROGRAM_ENV)
        && !pinned.trim().is_empty()
    {
        return Ok(PathBuf::from(pinned.trim()));
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("the running executable is not resolvable: {error}"))?;
    let stem = executable
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_owned();
    if stem == "oneiron-bench" {
        return Ok(executable);
    }
    Err(format!(
        "the running executable `{stem}` is not the oneiron-bench binary, so the harness has no \
         ready-child program to spawn; run the built binary or set {CHILD_PROGRAM_ENV}"
    ))
}

fn child_command(
    plan: Option<&ChildCommandPlan>,
    fallback: &Path,
    addr: SocketAddr,
    vault_dir: &Path,
    hold_ms: u64,
) -> (PathBuf, Vec<String>) {
    let ready_addr = addr.to_string();
    let vault = vault_dir.display().to_string();
    let hold = hold_ms.to_string();
    match plan {
        Some(plan) => {
            let args = plan
                .args
                .iter()
                .map(|argument| {
                    argument
                        .replace("{ready_addr}", &ready_addr)
                        .replace("{vault_dir}", &vault)
                        .replace("{hold_ms}", &hold)
                })
                .collect();
            (PathBuf::from(&plan.program), args)
        }
        None => (
            fallback.to_path_buf(),
            vec![
                "perf".to_owned(),
                "wake-child".to_owned(),
                "--ready-addr".to_owned(),
                ready_addr,
                "--vault".to_owned(),
                vault,
                "--hold-ms".to_owned(),
                hold,
            ],
        ),
    }
}

/// Spawns the child with every standard stream discarded. There is no pipe to
/// read, so readiness cannot accidentally become a log-text wait.
fn spawn_child(program: &Path, args: &[String]) -> Result<Child, String> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not spawn `{}`: {error}", program.display()))
}

fn describe_child(program: &Path, args: &[String]) -> String {
    format!("{} {}", program.display(), args.join(" "))
}

/// Axis 2: spawn-to-ready latency, sampled `settings.samples` times.
pub(crate) fn measure_wake(
    root: &Path,
    settings: &ChildSettings,
    evidence_kind: EvidenceKind,
) -> WakeAxis {
    let mut samples = Vec::with_capacity(settings.samples);
    let mut errors = Vec::new();
    let mut description = None;
    // Defaulted, then overwritten by whatever the probe actually reported, so
    // the emitted signal is observed rather than asserted.
    let mut readiness_signal = ReadinessSignal::TcpAccept;
    let program = match resolve_child_program() {
        Ok(program) => Some(program),
        Err(reason) => {
            errors.push(reason);
            None
        }
    };
    if let Some(program) = program {
        for index in 0..settings.samples {
            let dir = root.join(format!("wake-{index}"));
            match wake_sample(&program, settings, &dir) {
                Ok(sample) => {
                    samples.push(sample.elapsed_ms);
                    readiness_signal = sample.signal;
                    description = Some(sample.child);
                }
                Err(reason) => errors.push(reason),
            }
        }
    }
    WakeAxis {
        readiness_signal,
        readiness_rule: READINESS_RULE,
        accept_poll_interval_us: ACCEPT_POLL_INTERVAL_US,
        samples: samples.len(),
        spawn_to_ready_ms: Cell::from_option(
            Percentiles::from_samples(&samples),
            "no child reached a completed TCP accept, so no wake latency was measured",
        ),
        child: Cell::from_option(description, "no ready child was spawned in this run"),
        errors,
        evidence_kind,
    }
}

/// One completed spawn-to-ready observation.
struct WakeSample {
    elapsed_ms: f64,
    signal: ReadinessSignal,
    child: String,
}

fn wake_sample(program: &Path, settings: &ChildSettings, dir: &Path) -> Result<WakeSample, String> {
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("wake child vault dir failed: {error}"))?;
    let probe = WakeProbe::bind()?;
    let addr = probe.addr()?;
    let (program, args) = child_command(
        settings.child.as_ref(),
        program,
        addr,
        dir,
        settings.hold_ms,
    );
    let child_line = describe_child(&program, &args);
    let started = Instant::now();
    let mut child = spawn_child(&program, &args)?;
    let ready = probe.wait_ready(started, Duration::from_millis(settings.timeout_ms));
    let sample = match ready {
        Ok(ready) => {
            drop(ready.stream);
            WakeSample {
                elapsed_ms: ready.elapsed_ms,
                signal: ready.signal,
                child: child_line,
            }
        }
        Err(reason) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(reason);
        }
    };
    let _ = child.wait();
    Ok(sample)
}

// ─── ten ready children ──────────────────────────────────────────────────

/// Axis 4: resident memory with exactly `required` ready children, each
/// holding its own open vault. The measurement is the children; the
/// ARCH-0023b budget travels beside it as a comparison slot only.
pub(crate) fn measure_resident_memory(
    root: &Path,
    settings: &ChildSettings,
    required: usize,
    evidence_kind: EvidenceKind,
) -> ResidentMemoryAxis {
    let mut errors = Vec::new();
    let program = match resolve_child_program() {
        Ok(program) => program,
        Err(reason) => {
            errors.push(reason.clone());
            return resident_memory_not_ready(required, errors, reason, evidence_kind);
        }
    };
    match hold_ready_children(&program, settings, root, required) {
        Ok(rss) => resident_memory_measured(required, rss, errors, evidence_kind),
        Err(reason) => {
            errors.push(reason.clone());
            resident_memory_not_ready(required, errors, reason, evidence_kind)
        }
    }
}

/// Spawns `required` children against ONE listener, waits for `required`
/// completed accepts, then samples each live child's RSS while they are all
/// simultaneously ready.
fn hold_ready_children(
    program: &Path,
    settings: &ChildSettings,
    root: &Path,
    required: usize,
) -> Result<Vec<u64>, String> {
    let probe = WakeProbe::bind()?;
    let addr = probe.addr()?;
    let timeout = Duration::from_millis(settings.timeout_ms);
    let mut children = Vec::with_capacity(required);
    let mut streams = Vec::with_capacity(required);
    let started = Instant::now();
    for index in 0..required {
        let dir = root.join(format!("ready-{index}"));
        if let Err(error) = std::fs::create_dir_all(&dir) {
            kill_all(&mut children);
            return Err(format!("ready child vault dir failed: {error}"));
        }
        let (child_program, args) = child_command(
            settings.child.as_ref(),
            program,
            addr,
            &dir,
            settings.hold_ms,
        );
        match spawn_child(&child_program, &args) {
            Ok(child) => children.push(child),
            Err(reason) => {
                kill_all(&mut children);
                return Err(reason);
            }
        }
    }
    for _ in 0..required {
        match probe.wait_ready(started, timeout) {
            Ok(ready) => streams.push(ready.stream),
            Err(reason) => {
                kill_all(&mut children);
                return Err(format!(
                    "only {} of {required} children reached a completed TCP accept: {reason}",
                    streams.len()
                ));
            }
        }
    }
    let mut rss = Vec::with_capacity(required);
    let mut unreadable = false;
    for child in &children {
        match process_rss_bytes(child.id()) {
            Some(bytes) => rss.push(bytes),
            None => {
                unreadable = true;
                break;
            }
        }
    }
    drop(streams);
    if unreadable {
        kill_all(&mut children);
        return Err(
            "per-process RSS is not readable on this platform, so the ten-ready-children \
             measurement is unavailable"
                .to_owned(),
        );
    }
    for child in &mut children {
        let _ = child.wait();
    }
    Ok(rss)
}

fn kill_all(children: &mut Vec<Child>) {
    for child in &mut *children {
        let _ = child.kill();
        let _ = child.wait();
    }
    children.clear();
}

fn resident_memory_measured(
    required: usize,
    rss: Vec<u64>,
    errors: Vec<String>,
    evidence_kind: EvidenceKind,
) -> ResidentMemoryAxis {
    let observed = rss.len();
    let total: u64 = rss.iter().sum();
    let mean = if observed == 0 {
        None
    } else {
        Some(total / observed as u64)
    };
    let budget_bytes = ARCH_0023B_PER_VAULT_BUDGET_MB * 1024 * 1024;
    let comparison = mean.map(|mean| {
        format!(
            "mean ready child RSS {mean} B vs the ARCH-0023b {ARCH_0023B_PER_VAULT_BUDGET_MB} MB \
             ({budget_bytes} B) per-vault budget slot"
        )
    });
    ResidentMemoryAxis {
        required_ready_children: required,
        ready_children_observed: observed,
        child_holds_open_vault: true,
        per_child_rss_bytes: Cell::measured(rss),
        total_child_rss_bytes: Cell::measured(total),
        mean_child_rss_bytes: Cell::from_option(mean, "no ready child RSS sample was collected"),
        parent_rss_bytes: Cell::from_option(
            process_rss_bytes(std::process::id()),
            "the harness process RSS is not readable on this platform",
        ),
        arch_0023b_per_vault_budget_mb: ARCH_0023B_PER_VAULT_BUDGET_MB,
        budget_comparison: Cell::from_option(
            comparison,
            "no measured child RSS to compare against the budget slot",
        ),
        errors,
        evidence_kind,
    }
}

fn resident_memory_not_ready(
    required: usize,
    errors: Vec<String>,
    reason: String,
    evidence_kind: EvidenceKind,
) -> ResidentMemoryAxis {
    ResidentMemoryAxis {
        required_ready_children: required,
        ready_children_observed: 0,
        child_holds_open_vault: true,
        per_child_rss_bytes: Cell::not_ready(reason.clone()),
        total_child_rss_bytes: Cell::not_ready(reason.clone()),
        mean_child_rss_bytes: Cell::not_ready(reason.clone()),
        parent_rss_bytes: Cell::from_option(
            process_rss_bytes(std::process::id()),
            "the harness process RSS is not readable on this platform",
        ),
        arch_0023b_per_vault_budget_mb: ARCH_0023B_PER_VAULT_BUDGET_MB,
        budget_comparison: Cell::not_ready(reason),
        errors,
        evidence_kind,
    }
}

/// Best-effort resident set size for one live pid. `None` where the platform
/// exposes no per-process counter — reported as such, never guessed.
pub(crate) fn process_rss_bytes(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib: u64 = line
        .trim_start_matches("VmRSS:")
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kib * 1024)
}

// ─── gated writes ────────────────────────────────────────────────────────

/// Actor and subject fixtures for the gated-write axis.
fn gated_write_actors() -> Result<(EntityId, EntityId), String> {
    let actor = EntityId::from_bytes([0xA7; 16])
        .map_err(|error| format!("gated-write actor id failed: {error}"))?;
    let subject = EntityId::from_bytes([0x5B; 16])
        .map_err(|error| format!("gated-write subject id failed: {error}"))?;
    Ok((actor, subject))
}

fn gated_write_envelope(actor: EntityId) -> Result<WriteEnvelope, String> {
    let provenance = WriteProvenance::new(Value::Map(vec![
        (Value::from("harness"), Value::from("oneiron-bench perf")),
        (Value::from("ticket"), Value::from("ONE-1579")),
    ]))
    .map_err(|error| format!("gated-write provenance failed: {error}"))?;
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        provenance,
        ClaimApprovalStatus::Auto,
    ))
}

/// One commit carrying exactly one claim candidate, so a commit and a gate
/// decision stand in one-to-one correspondence.
fn commit_gated_claim(
    vault: &Vault,
    envelope: &WriteEnvelope,
    subject: EntityId,
    index: usize,
) -> Result<(), oneiron::Error> {
    let claim_id = EntityId::now();
    let now = 1_000_000 + index as u64;
    let candidate = ClaimCandidate::new(
        GATED_WRITE_PREDICATE,
        ClaimSubject::Entity(subject),
        Value::from(format!("perf-{index}")),
        1.0,
    )
    .with_scope(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            candidate,
            envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .commit()
}

/// Axis 5: gated-write commits per second, error counts, and the gate ledger
/// read back to prove one decision was recorded per commit.
pub(crate) fn measure_gated_writes(
    vault: &Vault,
    warmup: usize,
    measured: usize,
    evidence_kind: EvidenceKind,
) -> Result<GatedWriteAxis, String> {
    let (actor, subject) = gated_write_actors()?;
    let envelope = gated_write_envelope(actor)?;
    for (id, label, entity_type) in [
        (actor, "actor", ENTITY_TYPE_PERSON),
        (subject, "subject", BENCH_ENTITY_TYPE),
    ] {
        vault
            .put_entity(
                &id,
                entity_type,
                TimeRange { start: 1, end: 1 },
                1,
                b"perf-gated-write",
            )
            .map_err(|error| format!("gated-write {label} seed failed: {error}"))?;
    }
    for index in 0..warmup {
        let _ = commit_gated_claim(vault, &envelope, subject, index);
    }

    let ledger_limit = warmup.saturating_add(measured).saturating_add(64);
    let baseline = vault
        .gate_decisions(ledger_limit)
        .map_err(|error| format!("gate ledger baseline read failed: {error}"))?
        .len();

    let mut latency_ms = Vec::with_capacity(measured);
    let mut error_kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut commits_ok = 0_usize;
    let started = Instant::now();
    for index in 0..measured {
        let step = Instant::now();
        let outcome = commit_gated_claim(vault, &envelope, subject, warmup + index);
        latency_ms.push(step.elapsed().as_secs_f64() * 1e3);
        match outcome {
            Ok(()) => commits_ok += 1,
            Err(error) => {
                let kind = error.kind();
                *error_kinds.entry(format!("{kind:?}")).or_insert(0) += 1;
            }
        }
    }
    let wall_clock_ms = started.elapsed().as_secs_f64() * 1e3;

    let decisions = vault
        .gate_decisions(ledger_limit)
        .map_err(|error| format!("gate ledger read failed: {error}"))?;
    let recorded = decisions.len().saturating_sub(baseline);
    let mut gate_outcomes: BTreeMap<String, usize> = BTreeMap::new();
    for decision in decisions.iter().take(recorded) {
        *gate_outcomes.entry(decision.outcome.clone()).or_insert(0) += 1;
    }

    Ok(GatedWriteAxis {
        write_path: GATED_WRITE_PATH,
        warmup_commits: warmup,
        measured_commits: measured,
        commits_ok,
        commit_errors: measured - commits_ok,
        error_kinds,
        wall_clock_ms,
        commits_per_second: if wall_clock_ms > 0.0 && measured > 0 {
            Cell::measured(measured as f64 / (wall_clock_ms / 1e3))
        } else {
            Cell::not_ready("no measured gated-write commit window was opened")
        },
        commit_latency_ms: Cell::from_option(
            Percentiles::from_samples(&latency_ms),
            "no gated-write commit was timed",
        ),
        gate_decisions_recorded: recorded,
        one_decision_per_commit: recorded == measured,
        gate_outcomes,
        meets_full_run_floor: warmup >= super::report::FULL_RUN_MIN_GATED_WRITE_WARMUP
            && measured >= super::report::FULL_RUN_MIN_GATED_WRITE_MEASURED,
        floor: "full-run gated writes require >=1000 warmup and >=10000 measured commits",
        evidence_kind,
    })
}

// ─── bench-owned cache events ────────────────────────────────────────────

/// Where a cache event came from. Only `real_traffic` is admissible in a full
/// run; the other two exist so a smoke can say what it is out loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CacheEventSource {
    RealTraffic,
    SyntheticSmoke,
    Simulated,
}

impl CacheEventSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RealTraffic => "real_traffic",
            Self::SyntheticSmoke => "synthetic_smoke",
            Self::Simulated => "simulated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CacheOutcome {
    Hit,
    Miss,
}

/// One bench-owned cache event row. These are produced OUTSIDE the engine:
/// `vault.rs` and `ppr.rs` retrieval internals are never instrumented.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEvent {
    rung: String,
    outcome: CacheOutcome,
    source: CacheEventSource,
    #[serde(default)]
    observed_at_unix_ms: Option<u64>,
    #[serde(default)]
    session: Option<String>,
}

/// Why a cache-event stream was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheIngestError {
    #[error("cache event row {row} is malformed: {reason}")]
    Malformed { row: usize, reason: String },
    #[error(
        "cache event row {row} carries source `{reason}`: a full run accepts real-traffic cache \
         events only, never a synthetic or simulated source"
    )]
    SyntheticSourceInFullRun { row: usize, reason: String },
    #[error(
        "cache event row {row} names rung `{rung}`, which the plan does not list; a rung the plan \
         omits must stay omitted rather than be invented from an event"
    )]
    UnlistedRung { row: usize, rung: String },
}

/// One reported cache rung.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct CacheRungRow {
    pub(crate) rung: String,
    pub(crate) events: usize,
    pub(crate) hits: usize,
    pub(crate) misses: usize,
    /// `not_ready` when the rung saw no admissible event. NEVER `0.0`.
    pub(crate) hit_rate: Cell<f64>,
    pub(crate) sessions: usize,
    /// Newest admissible observation for this rung, when the events carried
    /// one. Absent rather than zeroed when no row was timestamped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) latest_observed_at_unix_ms: Option<u64>,
}

/// Axis 7: real-traffic cache hit rates per listed rung.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct CacheAxis {
    pub(crate) source_kind: &'static str,
    pub(crate) rungs_listed: Vec<String>,
    pub(crate) rows: Vec<CacheRungRow>,
    pub(crate) events_admitted: usize,
    pub(crate) rejects_synthetic_source_for_full_run: bool,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) note: &'static str,
}

const CACHE_NOTE: &str = "cache events are BENCH-OWNED rows: they are read from a JSONL stream the \
     harness owns, and no retrieval internal in vault.rs or ppr.rs is instrumented or mutated to \
     produce them; a listed rung with no admissible event stays not_ready and never reads as a \
     zero hit rate";

impl CacheAxis {
    /// Ingests a bench-owned JSONL cache-event stream.
    ///
    /// A full run accepts `real_traffic` events ONLY. A rung the plan does not
    /// list is refused rather than invented, and a listed rung with no
    /// admissible event is reported `not_ready`.
    pub(crate) fn ingest(
        mode: RunMode,
        rungs: &[String],
        jsonl: &str,
    ) -> Result<Self, CacheIngestError> {
        let mut tallies: BTreeMap<&str, RungTally> = rungs
            .iter()
            .map(|rung| (rung.as_str(), RungTally::default()))
            .collect();
        let mut admitted = 0_usize;
        for (offset, line) in jsonl.lines().enumerate() {
            let row = offset + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let event: CacheEvent =
                serde_json::from_str(trimmed).map_err(|error| CacheIngestError::Malformed {
                    row,
                    reason: error.to_string(),
                })?;
            if mode.is_full() && event.source != CacheEventSource::RealTraffic {
                return Err(CacheIngestError::SyntheticSourceInFullRun {
                    row,
                    reason: event.source.as_str().to_owned(),
                });
            }
            if !tallies.contains_key(event.rung.as_str()) {
                return Err(CacheIngestError::UnlistedRung {
                    row,
                    rung: event.rung,
                });
            }
            if let Some(tally) = tallies.get_mut(event.rung.as_str()) {
                tally.record(&event);
                admitted += 1;
            }
        }

        let rows = rungs
            .iter()
            .map(|rung| {
                let tally = tallies.get(rung.as_str()).copied().unwrap_or_default();
                tally.row(rung)
            })
            .collect();
        Ok(Self {
            source_kind: if mode.is_full() {
                "real_traffic_only"
            } else {
                "synthetic_smoke_fixture"
            },
            rungs_listed: rungs.to_vec(),
            rows,
            events_admitted: admitted,
            rejects_synthetic_source_for_full_run: true,
            evidence_kind: if mode.is_full() {
                EvidenceKind::IngestedRealTrafficEvents
            } else {
                EvidenceKind::SyntheticSmoke
            },
            note: CACHE_NOTE,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RungTally {
    hits: usize,
    misses: usize,
    sessions: usize,
    latest_observed_at_unix_ms: Option<u64>,
}

impl RungTally {
    fn record(&mut self, event: &CacheEvent) {
        match event.outcome {
            CacheOutcome::Hit => self.hits += 1,
            CacheOutcome::Miss => self.misses += 1,
        }
        if event.session.is_some() {
            self.sessions += 1;
        }
        if let Some(observed) = event.observed_at_unix_ms {
            self.latest_observed_at_unix_ms = Some(
                self.latest_observed_at_unix_ms
                    .map_or(observed, |latest| latest.max(observed)),
            );
        }
    }

    fn row(self, rung: &str) -> CacheRungRow {
        let events = self.hits + self.misses;
        CacheRungRow {
            rung: rung.to_owned(),
            events,
            hits: self.hits,
            misses: self.misses,
            hit_rate: if events == 0 {
                Cell::not_ready(format!(
                    "rung `{rung}` is listed in the plan but saw no admissible cache event in this \
                     run; a required rung with no real event is not_ready, never a zero hit rate"
                ))
            } else {
                Cell::measured(self.hits as f64 / events as f64)
            },
            sessions: self.sessions,
            latest_observed_at_unix_ms: self.latest_observed_at_unix_ms,
        }
    }
}

// ─── ready-child mode ────────────────────────────────────────────────────

/// Harness-internal child mode. Spawned by the wake and ready-children probes;
/// it opens a vault (so the child is a genuinely active vault, not an idle
/// process), announces readiness by CONNECTING to the parent's probe, and then
/// blocks until the parent closes the socket or the hold budget expires.
pub(crate) fn run_wake_child(args: &[String]) -> ExitCode {
    match wake_child(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("perf wake-child: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn wake_child(args: &[String]) -> Result<(), String> {
    let mut ready_addr = None;
    let mut vault_dir = None;
    let mut hold_ms = 30_000_u64;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("wake-child flag `{flag}` needs a value"))?;
        match flag {
            "--ready-addr" => ready_addr = Some(value.clone()),
            "--vault" => vault_dir = Some(value.clone()),
            "--hold-ms" => {
                hold_ms = value
                    .parse()
                    .map_err(|_| format!("--hold-ms expects milliseconds, got `{value}`"))?;
            }
            other => return Err(format!("unknown wake-child flag `{other}`")),
        }
        index += 2;
    }
    let ready_addr = ready_addr.ok_or_else(|| "--ready-addr is required".to_owned())?;
    let ready_addr: SocketAddr = ready_addr
        .parse()
        .map_err(|_| format!("--ready-addr is not a socket address: `{ready_addr}`"))?;

    // Opening the vault BEFORE announcing readiness is the point: the child
    // only counts as ready once it is a live process holding an open vault.
    let _held_vault = match vault_dir {
        Some(dir) => Some(
            Vault::open(dir, child_vault_config())
                .map_err(|error| format!("child vault open failed: {error}"))?,
        ),
        None => None,
    };

    let mut stream = TcpStream::connect(ready_addr)
        .map_err(|error| format!("child could not reach the readiness probe: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(hold_ms.max(1))))
        .map_err(|error| format!("child could not arm its hold timeout: {error}"))?;
    let mut scratch = [0_u8; 1];
    let _ = stream.read(&mut scratch);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn rungs(names: &[&str]) -> Vec<String> {
        names.iter().copied().map(String::from).collect()
    }

    /// A full run must refuse a synthetic or simulated cache source outright,
    /// accept the same rows for a smoke, and never turn a listed-but-silent
    /// rung into a zero hit rate.
    #[test]
    fn cache_events_reject_synthetic_source_for_full_run() {
        let listed = rungs(&["embedding", "posting_list", "context_pack"]);
        let synthetic = concat!(
            r#"{"rung":"embedding","outcome":"hit","source":"synthetic_smoke"}"#,
            "\n",
            r#"{"rung":"embedding","outcome":"miss","source":"synthetic_smoke"}"#,
            "\n"
        );

        let refused = CacheAxis::ingest(RunMode::Full, &listed, synthetic)
            .expect_err("a full run must refuse a synthetic cache source");
        match refused {
            CacheIngestError::SyntheticSourceInFullRun { row, reason } => {
                assert_eq!(row, 1);
                assert_eq!(reason, "synthetic_smoke");
            }
            other => panic!("expected a synthetic-source refusal, got {other}"),
        }

        let simulated = r#"{"rung":"embedding","outcome":"hit","source":"simulated"}"#;
        assert!(
            matches!(
                CacheAxis::ingest(RunMode::Full, &listed, simulated),
                Err(CacheIngestError::SyntheticSourceInFullRun { .. })
            ),
            "a simulated source is refused for a full run too"
        );

        // The same rows are admissible for a synthetic smoke, which says what
        // it is out loud.
        let smoke = CacheAxis::ingest(RunMode::SyntheticSmoke, &listed, synthetic)
            .expect("a smoke admits its own fixture");
        assert_eq!(smoke.events_admitted, 2);
        assert!(smoke.rejects_synthetic_source_for_full_run);
        assert_eq!(smoke.evidence_kind, EvidenceKind::SyntheticSmoke);
        let embedding = &smoke.rows[0];
        assert_eq!(embedding.events, 2);
        assert!(
            (embedding.hit_rate.value().copied().unwrap_or(-1.0) - 0.5).abs() < f64::EPSILON,
            "one hit of two events is a 0.5 hit rate"
        );

        // A listed rung with no event is not_ready, never zero.
        for silent in &smoke.rows[1..] {
            assert!(
                matches!(silent.hit_rate, Cell::NotReady { .. }),
                "rung `{}` saw no event and must be not_ready, not 0",
                silent.rung
            );
            assert_eq!(silent.events, 0);
        }

        // Real traffic passes a full run and reports a real rate.
        let real = concat!(
            r#"{"rung":"posting_list","outcome":"hit","source":"real_traffic"}"#,
            "\n",
            r#"{"rung":"posting_list","outcome":"hit","source":"real_traffic"}"#,
            "\n",
            r#"{"rung":"posting_list","outcome":"miss","source":"real_traffic"}"#
        );
        let full =
            CacheAxis::ingest(RunMode::Full, &listed, real).expect("real traffic is admitted");
        assert_eq!(full.evidence_kind, EvidenceKind::IngestedRealTrafficEvents);
        let posting = &full.rows[1];
        assert_eq!(posting.rung, "posting_list");
        assert!((posting.hit_rate.value().copied().unwrap_or(-1.0) - (2.0 / 3.0)).abs() < 1e-12);

        // An unlisted rung is refused rather than invented.
        let stray = r#"{"rung":"not_in_plan","outcome":"hit","source":"real_traffic"}"#;
        assert!(matches!(
            CacheAxis::ingest(RunMode::Full, &listed, stray),
            Err(CacheIngestError::UnlistedRung { .. })
        ));
    }

    /// Readiness must be the completed TCP accept and nothing else. The stand-in
    /// child emits a stream of convincing "ready" log lines well before it
    /// connects; a probe that watched log text would return early, and a probe
    /// that waited on the accept cannot.
    #[test]
    fn wake_probe_waits_for_tcp_accept_not_log_text() {
        let probe = WakeProbe::bind().expect("probe binds");
        let addr = probe.addr().expect("probe has an address");
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let log_writer = Arc::clone(&log);
        let quiet_for = Duration::from_millis(120);

        let started = Instant::now();
        let child = std::thread::spawn(move || {
            // Everything a log-text wait would have tripped on, emitted first.
            for line in ["listening", "READY", "server ready", "startup complete"] {
                log_writer
                    .lock()
                    .expect("log lock")
                    .push(String::from(line));
                std::thread::sleep(quiet_for / 4);
            }
            TcpStream::connect(addr).expect("stand-in child connects")
        });

        let ready = probe
            .wait_ready(started, Duration::from_secs(20))
            .expect("the probe accepts the child");
        let connection = child.join().expect("stand-in child thread");

        assert_eq!(ready.signal, ReadinessSignal::TcpAccept);
        assert!(
            ready.elapsed_ms >= quiet_for.as_secs_f64() * 1e3 * 0.8,
            "readiness must not fire before the connect; got {}ms while the child spent {}ms only \
             writing log text",
            ready.elapsed_ms,
            quiet_for.as_secs_f64() * 1e3
        );
        let emitted = log.lock().expect("log lock").clone();
        assert!(
            emitted.iter().any(|line| line.contains("READY")),
            "the fixture must actually have emitted ready-looking log text"
        );
        assert_eq!(emitted.len(), 4, "all four log lines landed before ready");
        drop(connection);
        drop(ready.stream);
    }

    /// One commit carries exactly one claim candidate, so the gate ledger must
    /// grow by exactly one decision per commit — including for a commit the
    /// gate refuses, whose denial receipt is itself a decision.
    #[test]
    fn gated_write_fixture_records_one_decision_per_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), perf_vault_config(16, 2)).expect("vault opens");
        let commits = 5_usize;

        let axis = measure_gated_writes(&vault, 2, commits, EvidenceKind::SyntheticSmoke)
            .expect("gated-write axis measures");

        assert_eq!(axis.measured_commits, commits);
        assert_eq!(
            axis.gate_decisions_recorded, commits,
            "the gate ledger must record exactly one decision per measured commit (gate outcomes: \
             {:?}, commit errors: {:?})",
            axis.gate_outcomes, axis.error_kinds
        );
        assert!(axis.one_decision_per_commit);
        assert_eq!(
            axis.commits_ok + axis.commit_errors,
            commits,
            "every commit is accounted for as an ok or an error"
        );
        assert_eq!(
            axis.gate_outcomes.values().sum::<usize>(),
            commits,
            "every recorded decision is attributed to an outcome"
        );
        assert!(axis.commit_latency_ms.is_measured());
        assert!(axis.commits_per_second.is_measured());
        assert!(
            !axis.meets_full_run_floor,
            "a five-commit fixture is deliberately below the full-run floor"
        );
        assert_eq!(axis.write_path, GATED_WRITE_PATH);
    }

    #[test]
    fn the_corpus_is_reproducible_from_its_seed() {
        let left = generate_corpus(1579, 8, 4, 6).expect("corpus");
        let right = generate_corpus(1579, 8, 4, 6).expect("corpus");
        let other = generate_corpus(1580, 8, 4, 6).expect("corpus");
        assert_eq!(left.hash, right.hash);
        assert_ne!(left.hash, other.hash);
        assert_eq!(left.queries.len(), 4);
        assert_eq!(left.vectors.len(), 8);
        assert_eq!(left.query_vectors.len(), 4);
        for query in &left.queries {
            assert!(query.text.starts_with("qzmk"), "{}", query.text);
        }
        let markers: std::collections::BTreeSet<&str> =
            left.docs.iter().map(|doc| doc.marker.as_str()).collect();
        assert_eq!(markers.len(), left.docs.len(), "markers are unique");
    }

    #[test]
    fn warm_and_cold_passes_read_the_same_corpus_into_separate_sets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let corpus = generate_corpus(3, 24, 6, 4).expect("corpus");
        let config = perf_vault_config(24, 2);
        {
            let vault = Vault::open(dir.path(), config.clone()).expect("vault opens");
            index_corpus(&vault, &corpus).expect("corpus indexes");
        }
        let vault = Vault::open(dir.path(), config).expect("vault reopens");
        let cold = measure_cold(&vault, &corpus, 10);
        let warm = measure_warm(&vault, &corpus, 10, 1);
        assert_eq!(cold.label, "cold");
        assert_eq!(warm.label, "warm");
        assert_eq!(cold.samples, corpus.queries.len());
        assert_eq!(warm.samples, corpus.queries.len());
        assert!(cold.latency_ms.is_measured());
        assert!(warm.latency_ms.is_measured());
    }
}
