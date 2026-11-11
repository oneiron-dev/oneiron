//! Bench-only micro-bench (never part of production paths): the public default O200k
//! context-pack token counter in `oneiron-base` over deterministic GENERATED generic
//! record strings.
//!
//! Kernel: `tokenizer::count_context_pack_tokens` (the real public default counter,
//! `DEFAULT_CONTEXT_PACK_TOKENIZER = PackTokenizer::O200kBase`). Linked from
//! `oneiron-base` only. The first call pays the one-time vendored-singleton load
//! (tiktoken-rs ships vocabularies via `include_str!`, so counting is offline at
//! runtime and at benchmark time); repeat 1 may include that load.
//!
//! Records are generated from a fixed generic word list plus counter-derived field
//! names/numbers: no prompts, no personas, no eval text, no private fixture. They
//! are kernel record-strings, NOT the 457-turn corpus: `corpus=synthetic`,
//! `turns=0 messages=0 claims=0`.
//!
//! Timing uses `std::time::Instant` per repeat. Counts are collected into a
//! preallocated buffer inside the timed loop and fingerprinted (explicit FNV-1a 64
//! over each actual count plus its input byte length) AFTER the timer stops, so
//! hashing never dominates the measurement. `black_box` shields inputs/outputs.
//!
//! Output is timings plus one fingerprint only: no correctness assertions, no test
//! suite, no speed-win claim, no tokenizer-policy change. The fingerprint covers
//! every count of every repeat in order; a code change keeps its win only if time
//! drops AND the fingerprint is unchanged. Micro-kernel percent-of-1ms-SoL is a
//! per-op yardstick only: it is NOT end-to-end recall speed and cannot stand in for
//! recall accuracy or full-pipeline proof.

use std::hint::black_box;
use std::time::Instant;

use oneiron_base::tokenizer::count_context_pack_tokens;

/// Default number of timed repeats.
const DEFAULT_REPEATS: usize = 3;
/// Default record count per batch.
const DEFAULT_RECORDS: usize = 256;
/// Default generic words per record (plus one field name and one number each).
const DEFAULT_WORDS_PER_RECORD: usize = 64;

/// Fixed generic vocabulary for generated records. Deliberately bland: these words
/// carry no prompt, persona, eval, or fixture meaning.
const WORDS: [&str; 24] = [
    "alpha", "bravo", "cargo", "delta", "engine", "field", "grid", "harbor", "index", "junction",
    "kernel", "ledger", "module", "node", "oxide", "panel", "quota", "relay", "sector", "turbine",
    "unit", "vector", "work", "yield",
];

struct Config {
    repeats: usize,
    records: usize,
    words_per_record: usize,
}

fn print_usage() {
    eprintln!(
        "usage: tokenizer_count [--repeats N] [--records R] [--words-per-record W]\n\
         defaults: repeats={} records={} words-per-record={}",
        DEFAULT_REPEATS, DEFAULT_RECORDS, DEFAULT_WORDS_PER_RECORD
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
        records: DEFAULT_RECORDS,
        words_per_record: DEFAULT_WORDS_PER_RECORD,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repeats" => {
                i += 1;
                cfg.repeats = take_usize(args, &mut i, "--repeats")?;
            }
            "--records" => {
                i += 1;
                cfg.records = take_usize(args, &mut i, "--records")?;
            }
            "--words-per-record" => {
                i += 1;
                cfg.words_per_record = take_usize(args, &mut i, "--words-per-record")?;
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

/// One deterministic generic record: a counter-derived field name plus cycling
/// vocabulary words with counter-derived numbers. Built once, outside the timer.
fn make_record(index: usize, words: usize) -> String {
    let mut out = String::new();
    out.push_str("field");
    out.push_str(&index.to_string());
    out.push('=');
    for w in 0..words {
        out.push_str(WORDS[(index + w) % WORDS.len()]);
        out.push(' ');
        out.push_str(&((index * 31 + w) % 1000).to_string());
        out.push(' ');
    }
    out
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
    // Counting cannot fail (the counter returns `usize`), so the whole run is
    // infallible after argument parsing: no Result plumbing needed here.
    let records: Vec<String> = (0..cfg.records)
        .map(|r| make_record(r, cfg.words_per_record))
        .collect();
    let input_bytes: usize = records.iter().map(|r| r.len()).sum();

    let mut hash = Fnv1a64::new();
    for repeat in 1..=cfg.repeats {
        let mut counts = Vec::with_capacity(cfg.records);
        let start = Instant::now();
        for record in &records {
            let n = count_context_pack_tokens(black_box(record.as_str()));
            counts.push(black_box(n));
        }
        let batch_ms = start.elapsed().as_secs_f64() * 1000.0;
        let before = hash.len;
        let mut total_tokens: usize = 0;
        for (record, n) in records.iter().zip(counts.iter()) {
            hash.update(&n.to_le_bytes());
            hash.update(&(record.len() as u64).to_le_bytes());
            total_tokens += *n;
        }
        let ms_per_op = batch_ms / cfg.records as f64;
        let pct_of_1ms = 100.0 / ms_per_op;
        println!(
            "kernel=context_pack_count repeat={repeat}/{} ops={} items={} fp_bytes={} \
             input_bytes={input_bytes} total_tokens={total_tokens} batch_ms={batch_ms:.3} \
             ms_per_op={ms_per_op:.6} pct_of_1ms={pct_of_1ms:.2}",
            cfg.repeats,
            cfg.records,
            counts.len(),
            hash.len - before,
        );
    }

    println!(
        "config corpus=synthetic turns=0 messages=0 claims=0 repeats={} records={} \
         words_per_record={} input_bytes={input_bytes}",
        cfg.repeats, cfg.records, cfg.words_per_record,
    );
    println!("fingerprint_fnv1a64={:016x}", hash.digest());
}
