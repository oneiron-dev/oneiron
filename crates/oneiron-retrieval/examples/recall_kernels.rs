//! Bench-only micro-bench (never part of production paths): public recall kernels in
//! `oneiron-retrieval` over deterministic SYNTHETIC numeric inputs.
//!
//! Kernels (all real public symbols, linked from `oneiron-retrieval` plus its
//! already-declared `oneiron-contracts` dependency only):
//! - `distance::cosine_similarity`: one query against N candidates.
//! - `distance::PreparedCosine::new` + `distance`: the same workload through the
//!   prepared query (construction happens OUTSIDE the timed region; only the
//!   per-candidate `distance` calls are timed).
//! - `fusion::sort_scored_entities_desc`: one full sort of N synthetic scored
//!   entities (the fresh clone per repeat happens OUTSIDE the timed region; only
//!   the sort itself is timed).
//! - `fusion::fuse_ranked_lists`: one z-score-sum fusion of L ranked lists of
//!   `FUSION_LIST_LENGTH` synthetic entries.
//!
//! Entity ids use the checked public `EntityId::from_bytes` constructor
//! (`crates/oneiron-contracts/src/entity_id.rs`): plain `pub`, ungated, rejecting
//! only the reserved sentinel patterns (all-zero, all-`0xFF`, `[type, 0xFF x15]`).
//! Synthetic ids carry a fixed `0x5A` marker half so they can never match a sentinel.
//!
//! Inputs are deterministic integer arithmetic with power-of-two scaling (counter
//! multiples modulo 1024/64, divided by 512/8): no RNG state, no machine-dependent
//! seeds, no transcendentals, bit-identical on every machine. `corpus=synthetic`,
//! `turns=0 messages=0 claims=0`: these are kernel vectors, NOT the 457-turn corpus,
//! and no private fixture text is baked in anywhere.
//!
//! Timing uses `std::time::Instant` per repeat. Outputs are collected into
//! preallocated buffers inside the timed loop and fingerprinted (explicit FNV-1a 64
//! over the actual output bytes) AFTER the timer stops, so hashing never dominates
//! the measurement. `black_box` shields kernel inputs/outputs from elimination.
//!
//! Output is timings plus one fingerprint only: no correctness assertions, no test
//! suite, no speed-win claim. The printed fingerprint covers every kernel output of
//! every repeat in order; a code change keeps its win only if time drops AND the
//! fingerprint is unchanged. Micro-kernel percent-of-1ms-SoL is a per-op yardstick
//! only: it is NOT end-to-end recall speed and cannot stand in for recall accuracy,
//! BM25/HNSW/Vault/gate/hydrate behaviour, or full-pipeline proof.

use std::hint::black_box;
use std::time::Instant;

use oneiron_contracts::entity_id::EntityId;
use oneiron_retrieval::distance::{PreparedCosine, cosine_similarity};
use oneiron_retrieval::fusion::{FUSION_LIST_LENGTH, fuse_ranked_lists, sort_scored_entities_desc};
use oneiron_retrieval::pipeline::ScoredEntity;

/// Default number of timed repeats.
const DEFAULT_REPEATS: usize = 3;
/// Default vector dimension for the cosine workloads.
const DEFAULT_DIMS: usize = 128;
/// Default candidate count per cosine batch (also the sort input length).
const DEFAULT_CANDIDATES: usize = 512;
/// Default ranked-list count for the fusion workload.
const DEFAULT_LISTS: usize = 4;

/// Fixed marker second half of every synthetic entity id: never all-zero, never
/// all-`0xFF`, never `[type, 0xFF x15]`, so `from_bytes` cannot reject it.
const ID_MARKER: [u8; 8] = [0x5A; 8];

struct Config {
    repeats: usize,
    dims: usize,
    candidates: usize,
    lists: usize,
}

fn print_usage() {
    eprintln!(
        "usage: recall_kernels [--repeats N] [--dims D] [--candidates C] [--lists L]\n\
         defaults: repeats={} dims={} candidates={} lists={} (list length = FUSION_LIST_LENGTH)",
        DEFAULT_REPEATS, DEFAULT_DIMS, DEFAULT_CANDIDATES, DEFAULT_LISTS
    );
}

fn take_usize(args: &[String], index: &mut usize, flag: &str) -> Result<usize, String> {
    let raw = args
        .get(*index)
        .ok_or_else(|| format!("{flag} needs a value"))?;
    *index += 1;
    let value: usize = raw
        .parse()
        .map_err(|_| format!("{flag} needs a positive integer, got {raw:?}"))?;
    if value == 0 {
        return Err(format!("{flag} must be at least 1"));
    }
    Ok(value)
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut cfg = Config {
        repeats: DEFAULT_REPEATS,
        dims: DEFAULT_DIMS,
        candidates: DEFAULT_CANDIDATES,
        lists: DEFAULT_LISTS,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repeats" => {
                i += 1;
                cfg.repeats = take_usize(args, &mut i, "--repeats")?;
            }
            "--dims" => {
                i += 1;
                cfg.dims = take_usize(args, &mut i, "--dims")?;
            }
            "--candidates" => {
                i += 1;
                cfg.candidates = take_usize(args, &mut i, "--candidates")?;
            }
            "--lists" => {
                i += 1;
                cfg.lists = take_usize(args, &mut i, "--lists")?;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(cfg)
}

/// Deterministic synthetic vector component from integer arithmetic only: a counter
/// multiple plus a lane multiple, modulo 1024, scaled by the power of two 512 into
/// `[-1.0, 1.0)`. Exact in `f32` (division by 512 and the `-1.0` shift lose nothing
/// for these magnitudes); bit-identical on every machine.
fn component(counter: u64, lane: usize) -> f32 {
    let raw = counter
        .wrapping_mul(73)
        .wrapping_add((lane as u64).wrapping_mul(151))
        % 1024;
    raw as f32 / 512.0 - 1.0
}

/// Deterministic score with deliberate ties: 64 distinct values in `[-4.0, 4.0)`,
/// exact in `f32`.
fn score(counter: u64) -> f32 {
    (counter % 64) as f32 / 8.0 - 4.0
}

/// Explicit FNV-1a 64 over actual output bytes (stable across runs/versions),
/// counting the bytes absorbed so each line can print actual fingerprinted bytes.
struct Fnv1a64 {
    state: u64,
    len: usize,
}

impl Fnv1a64 {
    fn new() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
            len: 0,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state ^= b as u64;
            self.state = self.state.wrapping_mul(0x0100_0000_01b3);
        }
        self.len += bytes.len();
    }

    fn digest(self) -> u64 {
        self.state
    }
}

fn id_of(counter: u64) -> Result<EntityId, String> {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&counter.to_be_bytes());
    bytes[8..].copy_from_slice(&ID_MARKER);
    EntityId::from_bytes(bytes).map_err(|err| format!("synthetic id {counter} rejected: {err:?}"))
}

fn report(
    kernel: &str,
    repeat: usize,
    cfg: &Config,
    ops: usize,
    items: usize,
    fp_bytes: usize,
    extra: &str,
    batch_ms: f64,
) {
    let ms_per_op = batch_ms / ops as f64;
    let pct_of_1ms = 100.0 / ms_per_op;
    println!(
        "kernel={kernel} repeat={repeat}/{} ops={ops} items={items} fp_bytes={fp_bytes}{extra} \
         batch_ms={batch_ms:.3} ms_per_op={ms_per_op:.6} pct_of_1ms={pct_of_1ms:.2}",
        cfg.repeats,
    );
}

fn run(cfg: &Config) -> Result<(), String> {
    let query: Vec<f32> = (0..cfg.dims).map(|lane| component(0, lane)).collect();
    let candidates: Vec<Vec<f32>> = (0..cfg.candidates)
        .map(|n| {
            (0..cfg.dims)
                .map(|lane| component(n as u64 + 1, lane))
                .collect()
        })
        .collect();

    let mut counter: u64 = 0;
    let mut sort_base = Vec::with_capacity(cfg.candidates);
    for _ in 0..cfg.candidates {
        let id = id_of(counter)?;
        sort_base.push(ScoredEntity {
            id,
            score: score(counter),
        });
        counter += 1;
    }
    let mut fuse_base: Vec<Vec<ScoredEntity>> = Vec::with_capacity(cfg.lists);
    for _ in 0..cfg.lists {
        let mut list = Vec::with_capacity(FUSION_LIST_LENGTH);
        for _ in 0..FUSION_LIST_LENGTH {
            let id = id_of(counter)?;
            list.push(ScoredEntity {
                id,
                score: score(counter),
            });
            counter += 1;
        }
        sort_scored_entities_desc(&mut list);
        fuse_base.push(list);
    }

    let mut hash = Fnv1a64::new();
    for repeat in 1..=cfg.repeats {
        // cosine_similarity: one query against every candidate.
        let mut sims = Vec::with_capacity(cfg.candidates);
        let start = Instant::now();
        for cand in &candidates {
            let out = cosine_similarity(black_box(query.as_slice()), black_box(cand.as_slice()));
            sims.push(black_box(out));
        }
        let batch_ms = start.elapsed().as_secs_f64() * 1000.0;
        let before = hash.len;
        for out in &sims {
            hash.update(&out.to_bits().to_le_bytes());
        }
        report(
            "cosine_similarity",
            repeat,
            cfg,
            cfg.candidates,
            sims.len(),
            hash.len - before,
            &format!(" dims={} vec_bytes={}", cfg.dims, cfg.dims * 4),
            batch_ms,
        );

        // PreparedCosine: construction is setup (outside the timer); only the
        // per-candidate distance calls are timed.
        let prepared = PreparedCosine::new(query.as_slice());
        let mut dists = Vec::with_capacity(cfg.candidates);
        let start = Instant::now();
        for cand in &candidates {
            let out = prepared.distance(black_box(cand.as_slice()));
            dists.push(black_box(out));
        }
        let batch_ms = start.elapsed().as_secs_f64() * 1000.0;
        let before = hash.len;
        for out in &dists {
            hash.update(&out.to_bits().to_le_bytes());
        }
        report(
            "prepared_cosine",
            repeat,
            cfg,
            cfg.candidates,
            dists.len(),
            hash.len - before,
            &format!(" dims={} vec_bytes={}", cfg.dims, cfg.dims * 4),
            batch_ms,
        );

        // sort_scored_entities_desc: fresh clone is setup (outside the timer);
        // only the sort itself is timed.
        let mut work = sort_base.clone();
        let start = Instant::now();
        sort_scored_entities_desc(black_box(work.as_mut_slice()));
        black_box(work.as_slice());
        let batch_ms = start.elapsed().as_secs_f64() * 1000.0;
        let before = hash.len;
        for item in &work {
            hash.update(item.id.as_bytes());
            hash.update(&item.score.to_bits().to_le_bytes());
        }
        report(
            "fusion_sort",
            repeat,
            cfg,
            1,
            work.len(),
            hash.len - before,
            "",
            batch_ms,
        );

        // fuse_ranked_lists: pure over shared input, timed directly.
        let start = Instant::now();
        let fused = fuse_ranked_lists(black_box(fuse_base.as_slice()));
        black_box(fused.as_slice());
        let batch_ms = start.elapsed().as_secs_f64() * 1000.0;
        let before = hash.len;
        for item in &fused {
            hash.update(item.id.as_bytes());
            hash.update(&item.score.to_bits().to_le_bytes());
        }
        report(
            "fuse_ranked_lists",
            repeat,
            cfg,
            1,
            fused.len(),
            hash.len - before,
            &format!(
                " lists={} list_len={} outputs={}",
                cfg.lists,
                FUSION_LIST_LENGTH,
                fused.len()
            ),
            batch_ms,
        );
    }

    println!(
        "config corpus=synthetic turns=0 messages=0 claims=0 repeats={} dims={} candidates={} \
         lists={} list_len={}",
        cfg.repeats, cfg.dims, cfg.candidates, cfg.lists, FUSION_LIST_LENGTH
    );
    println!("fingerprint_fnv1a64={:016x}", hash.digest());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match parse_args(&args) {
        Ok(cfg) => cfg,
        Err(message) => {
            eprintln!("error: {message}");
            print_usage();
            std::process::exit(2);
        }
    };
    if let Err(message) = run(&cfg) {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}
