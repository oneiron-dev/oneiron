//! FIX 1189 overlap bench: a paged `search` scan over one ~24 MiB result
//! body at an 8 MiB scan bound, following each reply's `next` until `done`.
//! Prints wall ms for the whole scan (min/p50/mean over 11 runs), the
//! continuation count, an SoL floor (one memcpy pass over the same bytes),
//! and a match digest, so a before/after pair on the SAME machine (release
//! profile) shows identical matches with fewer continuations after the fix.
//!
//! Public API only, mirroring `sync_memory.rs`.
//!
//! Run: cargo bench --bench result_search_overlap

use std::time::{Duration, Instant};

use oneiron::code_run::{
    CODE_RUN_RNG_SEED_LEN, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunResultBinding, ResultFacet,
};
use oneiron::entity_id::EntityId;
use oneiron::limit_ask::EngineLimit;
use oneiron::{Vault, VaultConfig};
use serde_json::{Value, json};

/// Bytes of the bench body: three scan bounds.
const BODY_BYTES: usize = 24 << 20;

/// Scan bound the bench vault sets: small enough to force continuations.
const SCAN_BOUND: u64 = 8 << 20;

/// Full scans timed, after one warm-up scan.
const RUNS: usize = 11;

/// Bytes of one body line; the body is an exact multiple of it.
const LINE_BYTES: usize = 128;

/// One line in this many carries the needle: 24 matches over the body.
const NEEDLE_EVERY: usize = 8192;

/// The sparse literal the scan looks for.
const NEEDLE: &str = "NEEDLE";

/// A result path the read door resolves: `executor/repl/store/*.result`.
const OUTPUT_PATH: &str = "executor/repl/store/bench0123456789abcdef0123456789abcdef.result";

/// The name the run binds the body under.
const BINDING_NAME: &str = "r1";

/// Search inputs ask for far more than the body holds, so every stop is
/// scan-bound, never match-limit.
const SEARCH_LIMIT: u32 = 1_000_000;

/// FNV-1a 64 offset basis: the empty match digest.
const DIGEST_EMPTY: u64 = 14_695_981_039_346_656_037;

/// FNV-1a 64 prime.
const DIGEST_PRIME: u64 = 1_099_511_628_211;

/// One full paged scan: what it found and what it cost.
struct ScanReport {
    digest: u64,
    matches: usize,
    calls: usize,
    scanned: Vec<(u64, u64)>,
}

/// The bench body: `BODY_BYTES` of text lines, every `NEEDLE_EVERY`-th line
/// carrying the needle once.
fn build_body() -> Vec<u8> {
    let mut raw = Vec::with_capacity(BODY_BYTES);
    let lines = BODY_BYTES / LINE_BYTES;
    for i in 0..lines {
        let mut line = if i % NEEDLE_EVERY == NEEDLE_EVERY - 1 {
            format!("line {i:08} holds {NEEDLE} once ")
        } else {
            format!("line {i:08} filler ")
        };
        while line.len() < LINE_BYTES - 1 {
            line.push('.');
        }
        line.push('\n');
        raw.extend_from_slice(line.as_bytes());
    }
    raw
}

/// A vault holding one run with one bound body, scanned at `SCAN_BOUND`.
fn seed_vault(dir: &tempfile::TempDir, raw: &[u8]) -> (Vault, EntityId) {
    let mut config = VaultConfig::default();
    config
        .limits
        .set(EngineLimit::CodeResultScanBytes, SCAN_BOUND);
    let vault = Vault::open(dir.path(), config).expect("open bench vault");
    let run_id = EntityId::now();
    let output = CodeRunRawOutput::from_bytes(OUTPUT_PATH, raw).expect("bench body manifest");
    vault
        .put_code_run_raw_output(Some(run_id), &output, raw)
        .expect("store bench body");
    let mut record = CodeRunReplayRecord::new(
        run_id,
        CodeRunDeterminism::new(1_719_000_002_000, [0xBC; CODE_RUN_RNG_SEED_LEN]),
    );
    record.outputs.push(output.clone());
    record.bindings.push(CodeRunResultBinding::new(
        BINDING_NAME,
        output.handle.clone(),
    ));
    vault
        .put_code_run_replay_record(&record)
        .expect("store bench replay record");
    (vault, run_id)
}

/// FNV-1a over one word of a match.
fn mix(mut digest: u64, word: u64) -> u64 {
    for byte in word.to_le_bytes() {
        digest ^= u64::from(byte);
        digest = digest.wrapping_mul(DIGEST_PRIME);
    }
    digest
}

/// One match's offset, length and line folded into `digest`.
fn fold_match(digest: u64, entry: &Value) -> u64 {
    let offset = entry
        .get("offset")
        .expect("an offset")
        .as_u64()
        .expect("a u64 offset");
    let len = entry
        .get("len")
        .expect("a len")
        .as_u64()
        .expect("a u64 len");
    let line = entry
        .get("line")
        .expect("a line")
        .as_u64()
        .expect("a u64 line");
    mix(mix(mix(digest, offset), len), line)
}

/// One `scanned` span of a reply.
fn span_of(output: &Value) -> (u64, u64) {
    let span = output.get("scanned").expect("a scanned span");
    (
        span[0].as_u64().expect("a span start"),
        span[1].as_u64().expect("a span end"),
    )
}

/// Follows `next` until `done`, digesting every match so a before/after
/// pair can show identical matches.
fn paged_scan(vault: &Vault, run_id: EntityId) -> ScanReport {
    let mut input = json!({"pattern": NEEDLE, "limit": SEARCH_LIMIT});
    let mut digest = DIGEST_EMPTY;
    let mut matches = 0;
    let mut calls = 0;
    let mut scanned = Vec::new();
    loop {
        let reply = vault
            .read_code_run_result(
                run_id,
                BINDING_NAME,
                Some(ResultFacet::Search),
                input,
                |_| Ok(false),
            )
            .expect("search the bench body");
        calls += 1;
        let output = reply.get("output").expect("a search answer, not a refusal");
        for entry in output
            .get("matches")
            .expect("matches")
            .as_array()
            .expect("a match list")
        {
            digest = fold_match(digest, entry);
            matches += 1;
        }
        scanned.push(span_of(output));
        if output
            .get("done")
            .expect("a done flag")
            .as_bool()
            .expect("a bool done")
        {
            break;
        }
        let next = output.get("next").expect("a cursor while not done").clone();
        input = json!({"pattern": NEEDLE, "limit": SEARCH_LIMIT, "cursor": next});
    }
    ScanReport {
        digest,
        matches,
        calls,
        scanned,
    }
}

/// The SoL floor for one full scan: one memcpy pass over the body bytes.
fn sol_floor(raw: &[u8]) -> Duration {
    let mut sink = vec![0_u8; raw.len()];
    let start = Instant::now();
    sink.copy_from_slice(raw);
    std::hint::black_box(&sink);
    start.elapsed()
}

/// Sorted run times as min/p50/mean milliseconds.
fn summarize(mut times: Vec<Duration>) -> (f64, f64, f64) {
    times.sort();
    let min = times.first().expect("at least one run").as_secs_f64() * 1000.0;
    let p50 = times[times.len() / 2].as_secs_f64() * 1000.0;
    let sum: Duration = times.iter().sum();
    let mean = sum.as_secs_f64() * 1000.0 / times.len() as f64;
    (min, p50, mean)
}

fn main() {
    println!("=== FIX 1189 search-overlap bench ===\n");
    let raw = build_body();
    assert_eq!(raw.len(), BODY_BYTES, "the body is three scan bounds");
    println!(
        "body: {} bytes in {} lines",
        raw.len(),
        raw.len() / LINE_BYTES
    );
    let dir = tempfile::tempdir().expect("bench tempdir");
    let (vault, run_id) = seed_vault(&dir, &raw);

    let first = paged_scan(&vault, run_id);
    println!(
        "warm-up (off the clock): {} matches in {} calls",
        first.matches, first.calls
    );

    let mut times = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        let report = paged_scan(&vault, run_id);
        times.push(start.elapsed());
        assert_eq!(report.digest, first.digest, "matches are deterministic");
        assert_eq!(report.matches, first.matches, "match count is stable");
        assert_eq!(report.calls, first.calls, "continuations are stable");
    }
    let (min, p50, mean) = summarize(times);
    let sol = sol_floor(&raw).as_secs_f64() * 1000.0;

    println!(
        "\nfull paged scans: {RUNS} runs over {} MiB at {SCAN_BOUND} B bound",
        BODY_BYTES >> 20
    );
    println!("wall ms: min {min:.2}, p50 {p50:.2}, mean {mean:.2}");
    println!("SoL floor (one memcpy pass): {sol:.2} ms");
    println!("SoL/measured: {:.1}% (p50)", 100.0 * sol / p50);
    println!(
        "matches: {} (digest {:016x}), calls: {}",
        first.matches, first.digest, first.calls
    );
    println!("scanned spans: {:?}", first.scanned);
}
