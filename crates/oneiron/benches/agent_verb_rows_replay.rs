//! FIX 837 speed bench: cold full-record reads versus warm cached repeated reads.
//!
//! Builds replay records with N recorded `AgentVerb` outcomes at realistic
//! output sizes, then times K simulated step setups
//! (`agent_verb_rows()` + `resident_tool_answer_rows(record, None)`) in two
//! modes:
//!
//! - `cold`: every setup reads a freshly cloned record, whose row cache
//!   starts empty, so each setup pays the full outcome decode.
//! - `warm`: all setups re-read one record, so only the (untimed) warmup
//!   decodes and every timed setup hits the FIX 837 cache.
//!
//! The speed-of-light floor is one streaming `memcpy` pass over the same
//! outcome JSON bytes, measured in this binary; each line reports
//! `sol_pct = 100 * sol_ms / measured_ms`.
//!
//! Public API only. Run: `cargo bench --bench agent_verb_rows_replay`
//! (release profile, same machine for before/after comparisons).

use std::hint::black_box;
use std::time::Instant;

use oneiron::EntityId;
use oneiron::code_run::{
    AgentVerbAnswer, CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord, SelfAgentVerbCall,
    SelfCall, SelfDispatchOutcome, resident_tool_answer_rows,
};
use oneiron::task_verb::sdk::AgentVerb;

/// Recorded answers per record: small, medium, large runs.
const NS: [usize; 3] = [10, 100, 500];
/// Per-answer output JSON sizes: a short answer and a long one.
const OUT_BS: [usize; 2] = [1024, 50 * 1024];
/// Served rows listed beside each answer.
const ROWS_PER_ANSWER: usize = 3;
/// Timed setups per (N, output bytes, mode) cell.
const SETUPS: usize = 10;
/// Frozen clock shared by every bench row (timestamps do not affect reads).
const FROZEN_MS: u64 = 1_719_000_002_000;
/// Total bytes the SoL loop copies, so tiny cells still time stably.
const SOL_TARGET_BYTES: usize = 50 * 1024 * 1024;

/// A deterministic non-reserved id: the `0x51` fill can never match the
/// all-zero, all-`0xFF`, or `[_, 0xFF * 15]` sentinel patterns.
fn eid(tag: u8, n: u64) -> EntityId {
    let mut bytes = [0x51u8; 16];
    bytes[0] = tag;
    bytes[1..9].copy_from_slice(&n.to_le_bytes());
    EntityId::from_bytes(bytes).expect("bench entity id")
}

/// An answer output whose JSON encoding is exactly `out_b` bytes.
fn output_value(seq: usize, out_b: usize) -> serde_json::Value {
    let base = serde_json::json!({ "seq": seq, "text": "" })
        .to_string()
        .len();
    let pad = out_b.saturating_sub(base);
    serde_json::json!({ "seq": seq, "text": "x".repeat(pad) })
}

/// A record with `n` `AgentVerb` answers plus the concatenated outcome JSON
/// bytes the SoL loop streams over.
fn build_record(n: usize, out_b: usize) -> (CodeRunReplayRecord, Vec<u8>) {
    let determinism = CodeRunDeterminism::new(FROZEN_MS, [0xAC; 32]);
    let mut record = CodeRunReplayRecord::new(eid(0xA0, 0), determinism);
    let mut sol_src = Vec::new();
    for seq in 0..n {
        let output = output_value(seq, out_b);
        sol_src.extend_from_slice(output.to_string().as_bytes());
        let rows: Vec<EntityId> = (0..ROWS_PER_ANSWER)
            .map(|r| eid(0xB0 + r as u8, seq as u64))
            .collect();
        let call = SelfCall::AgentVerb(SelfAgentVerbCall {
            verb: AgentVerb::VaultRecall,
            input: serde_json::json!({ "query": "bench" }),
        });
        let outcome = SelfDispatchOutcome::AgentVerb(AgentVerbAnswer::new(output, Some(rows)));
        let row = CodeRunBridgeCall::record(seq as u64, &call, &outcome, FROZEN_MS, FROZEN_MS)
            .expect("bench bridge row");
        record.bridge_calls.push(row);
    }
    (record, sol_src)
}

/// One simulated step setup: the two FIX 837 reads. Returns the rows served
/// so the caller can prove the work happened.
fn one_setup(record: &CodeRunReplayRecord) -> (usize, usize) {
    let verb_rows = black_box(record.agent_verb_rows().expect("verb rows decode"));
    let resident_rows =
        black_box(resident_tool_answer_rows(record, None).expect("resident rows decode"));
    (verb_rows.len(), resident_rows.len())
}

/// Wall ms of one streaming pass over `sol_src`: the SoL floor.
fn sol_ms_per_pass(sol_src: &[u8]) -> f64 {
    let reps = (SOL_TARGET_BYTES / sol_src.len().max(1)).max(1);
    let mut dst = vec![0u8; sol_src.len()];
    let start = Instant::now();
    for _ in 0..reps {
        dst.copy_from_slice(black_box(sol_src));
        black_box(&dst);
    }
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    black_box(&dst);
    ms / reps as f64
}

fn stats_ms(cell: &mut [f64]) -> (f64, f64, f64) {
    cell.sort_by(f64::total_cmp);
    let min = cell[0];
    let p50 = cell[cell.len() / 2];
    let mean = cell.iter().sum::<f64>() / cell.len() as f64;
    (min, p50, mean)
}

#[allow(clippy::too_many_arguments)]
fn report(
    n: usize,
    out_b: usize,
    total_b: usize,
    mode: &str,
    cell_ms: &mut Vec<f64>,
    sol_ms: f64,
    verb_rows: usize,
) {
    let (min, p50, mean) = stats_ms(cell_ms);
    let sol_pct = 100.0 * sol_ms / mean.max(f64::MIN_POSITIVE);
    println!(
        "RESULT n={n} out_b={out_b} total_b={total_b} mode={mode} setups={SETUPS} ms_min={min:.3} ms_p50={p50:.3} ms_mean={mean:.3} sol_ms={sol_ms:.4} sol_pct={sol_pct:.2} verb_rows={verb_rows}"
    );
}

fn main() {
    println!("=== FIX 837 agent_verb_rows replay bench ===");
    println!("mode=cold reads a fresh clone per setup; mode=warm re-reads one record.");
    println!("sol_ms = one memcpy pass over the outcome bytes; sol_pct = 100*sol_ms/ms_mean.");
    for n in NS {
        for out_b in OUT_BS {
            let (record, sol_src) = build_record(n, out_b);
            let total_b = sol_src.len();
            // Guard: the reads must serve every answer's rows, not `None`.
            let (verb_rows, _) = one_setup(&record);
            assert_eq!(verb_rows, n * ROWS_PER_ANSWER, "n={n} out_b={out_b}");
            let sol_ms = sol_ms_per_pass(&sol_src);

            // Cold: each setup decodes a freshly cloned (cache-empty) record.
            // Clones are built outside the timer so only the reads are timed.
            let clones: Vec<CodeRunReplayRecord> = (0..SETUPS).map(|_| record.clone()).collect();
            let mut cold_ms = Vec::with_capacity(SETUPS);
            for clone in &clones {
                let start = Instant::now();
                let (rows, _) = one_setup(clone);
                cold_ms.push(start.elapsed().as_secs_f64() * 1000.0);
                assert_eq!(rows, verb_rows);
            }
            report(n, out_b, total_b, "cold", &mut cold_ms, sol_ms, verb_rows);

            // Warm: one record; the first read warms the cache (untimed) and
            // the timed setups re-read through it.
            let (warm_rows, _) = one_setup(&record);
            assert_eq!(warm_rows, verb_rows);
            let mut warm_ms = Vec::with_capacity(SETUPS);
            for _ in 0..SETUPS {
                let start = Instant::now();
                let (rows, _) = one_setup(&record);
                warm_ms.push(start.elapsed().as_secs_f64() * 1000.0);
                assert_eq!(rows, verb_rows);
            }
            report(n, out_b, total_b, "warm", &mut warm_ms, sol_ms, verb_rows);
        }
    }
    println!("done");
}
