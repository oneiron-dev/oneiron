//! Bench-only micro-bench (never part of production paths): the public persisted
//! vector-row f16 codec in `oneiron-store` over deterministic SYNTHETIC numeric vectors.
//!
//! Kernels (real public symbols, linked from `oneiron-store` only):
//! - `vector_row::encode_vector_row_v1`: `&[f32]` to the canonical EMB-3 v1 row
//!   (one format-tag byte plus little-endian f16 components).
//! - `vector_row::decode_vector_row`: row bytes back to `Vec<f32>`.
//!
//! Inputs are deterministic integer arithmetic with power-of-two scaling (counter
//! multiples modulo 2048, divided by 16): values in `[-64.0, 64.0)` at exact 1/16
//! steps, always finite and always f16-representable, so the codec's refusal of
//! non-finite/f16-unrepresentable components can never trigger. No RNG state, no
//! machine-dependent seeds, no transcendentals. `corpus=synthetic`, `turns=0`
//! `messages=0` `claims=0`: kernel vectors, NOT the 457-turn corpus.
//!
//! Timing uses `std::time::Instant` per repeat. Rows are collected into
//! preallocated buffers inside the timed loop and fingerprinted (explicit FNV-1a 64
//! over the ACTUAL encoded bytes and the ACTUAL decoded `f32` bits) AFTER the timer
//! stops, so hashing never dominates the measurement. `black_box` shields
//! inputs/outputs from elimination.
//!
//! Output is timings plus one fingerprint only: no correctness assertions, no test
//! suite, no speed-win claim, no storage/format/API change. The fingerprint covers
//! every encoded row and every decoded vector of every repeat in order; a code
//! change keeps its win only if time drops AND the fingerprint is unchanged.
//! Micro-kernel percent-of-1ms-SoL is a per-op yardstick only: it is NOT end-to-end
//! recall speed and cannot stand in for recall accuracy or full-pipeline proof.

use std::hint::black_box;
use std::time::Instant;

use oneiron_store::vector_row::{decode_vector_row, encode_vector_row_v1};

/// Default number of timed repeats.
const DEFAULT_REPEATS: usize = 3;
/// Default vector dimension per row.
const DEFAULT_DIMS: usize = 128;
/// Default row count per batch.
const DEFAULT_ROWS: usize = 512;

struct Config {
    repeats: usize,
    dims: usize,
    rows: usize,
}

fn print_usage() {
    eprintln!(
        "usage: vector_row_codec [--repeats N] [--dims D] [--rows R]\n\
         defaults: repeats={} dims={} rows={}",
        DEFAULT_REPEATS, DEFAULT_DIMS, DEFAULT_ROWS
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
        rows: DEFAULT_ROWS,
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
            "--rows" => {
                i += 1;
                cfg.rows = take_usize(args, &mut i, "--rows")?;
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

/// Deterministic synthetic vector component from integer arithmetic only: a row
/// multiple plus a lane multiple, modulo 2048, scaled by the power of two 16 into
/// `[-64.0, 64.0)` at exact 1/16 steps. Exact in `f32` AND in `f16`, so the codec's
/// finite-f16 refusal can never trigger; bit-identical on every machine.
fn level(row: usize, lane: usize) -> f32 {
    let raw = (row as u64)
        .wrapping_mul(37)
        .wrapping_add((lane as u64).wrapping_mul(91))
        % 2048;
    raw as f32 / 16.0 - 64.0
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

fn run(cfg: &Config) -> Result<(), String> {
    let vectors: Vec<Vec<f32>> = (0..cfg.rows)
        .map(|row| (0..cfg.dims).map(|lane| level(row, lane)).collect())
        .collect();

    let mut hash = Fnv1a64::new();
    for repeat in 1..=cfg.repeats {
        // Encode every synthetic vector; the codec returns a fresh byte row.
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(cfg.rows);
        let start = Instant::now();
        for vec in &vectors {
            let row = encode_vector_row_v1(black_box(vec.as_slice())).map_err(|err| {
                format!(
                    "synthetic row rejected by the codec, dims={}: {err:?}",
                    cfg.dims
                )
            })?;
            encoded.push(black_box(row));
        }
        let batch_ms = start.elapsed().as_secs_f64() * 1000.0;
        let before = hash.len;
        let mut bytes: usize = 0;
        for row in &encoded {
            hash.update(row.as_slice());
            bytes += row.len();
        }
        let ms_per_op = batch_ms / cfg.rows as f64;
        let pct_of_1ms = 100.0 / ms_per_op;
        println!(
            "kernel=vector_row_encode repeat={repeat}/{} ops={} items={} fp_bytes={} dims={} \
             bytes={bytes} batch_ms={batch_ms:.3} ms_per_op={ms_per_op:.6} \
             pct_of_1ms={pct_of_1ms:.2}",
            cfg.repeats,
            cfg.rows,
            encoded.len(),
            hash.len - before,
            cfg.dims,
        );

        // Decode every encoded row back to f32; dimensions come from the CLI.
        let mut decoded: Vec<Vec<f32>> = Vec::with_capacity(cfg.rows);
        let start = Instant::now();
        for row in &encoded {
            let vec = decode_vector_row(black_box(row.as_slice()), black_box(cfg.dims))
                .map_err(|err| format!("codec round trip failed, dims={}: {err:?}", cfg.dims))?;
            decoded.push(black_box(vec));
        }
        let batch_ms = start.elapsed().as_secs_f64() * 1000.0;
        let before = hash.len;
        let mut floats: usize = 0;
        for vec in &decoded {
            for v in vec {
                hash.update(&v.to_bits().to_le_bytes());
                floats += 1;
            }
        }
        let ms_per_op = batch_ms / cfg.rows as f64;
        let pct_of_1ms = 100.0 / ms_per_op;
        println!(
            "kernel=vector_row_decode repeat={repeat}/{} ops={} items={} fp_bytes={} dims={} \
             floats={floats} batch_ms={batch_ms:.3} ms_per_op={ms_per_op:.6} \
             pct_of_1ms={pct_of_1ms:.2}",
            cfg.repeats,
            cfg.rows,
            decoded.len(),
            hash.len - before,
            cfg.dims,
        );
    }

    println!(
        "config corpus=synthetic turns=0 messages=0 claims=0 repeats={} dims={} rows={}",
        cfg.repeats, cfg.dims, cfg.rows,
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
