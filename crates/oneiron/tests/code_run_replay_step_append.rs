//! A guarded replay append reads only what it compares and keeps from the row
//! it replaces (FIX 16). Every executor step commits the run's whole replay
//! record through `put_code_run_replay_record_if_generation`. On main that put
//! encoded the record once and dropped the bytes, decoded the whole stored
//! row to compare its generation, and checked each result binding against
//! every output at each encode.
//!
//! The test seeds one run with 2,000 bridge calls, outputs and bindings, then
//! appends 50 steps of one call, one output, one binding and one checkpoint
//! each, and prints the time of those 50 appends: main and the fix are
//! compared by that line, run on one host. It also checks that each append
//! stored exactly the record it was given, and that a stale or missing
//! generation is still refused.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test code_run_replay_step_append`

use std::time::{Duration, Instant};

use oneiron::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayGeneration,
    CodeRunReplayRecord, CodeRunResultBinding, CodeRunStepCheckpoint, SelfCall,
    SelfDispatchOutcome, SelfMemorySearchCall, SelfMemorySearchResult,
    encode_code_run_replay_record,
};
use oneiron::{EntityId, Error, Vault, VaultConfig};

/// Bridge calls, outputs and bindings the run holds before the timed steps.
const SEEDED: u64 = 2_000;
/// Calls and outputs of each seeded step, which ends at one checkpoint.
const PER_SEEDED_STEP: u64 = 10;
/// Steps the test appends, each timed.
const STEPS: u64 = 50;

fn bridge_call(seq: u64) -> CodeRunBridgeCall {
    let query = format!("replay append fixture query {seq:05} {}", "q".repeat(64));
    let at = 1_000 + seq;
    CodeRunBridgeCall::record(
        seq,
        &SelfCall::MemorySearch(SelfMemorySearchCall::new(query.clone(), 10)),
        &SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
            query,
            results: Vec::new(),
            hooks: Vec::new(),
        }),
        at,
        at + 1,
    )
    .expect("bridge call")
}

/// One output with its own bytes, path and result name.
fn bound_output(index: u64) -> (CodeRunRawOutput, CodeRunResultBinding) {
    let path = format!("results/step-output-{index:05}.txt");
    let body = format!("output {index:05} {}", "o".repeat(300));
    let output = CodeRunRawOutput::from_bytes(path.clone(), body.as_bytes()).expect("raw output");
    let binding = CodeRunResultBinding::new(format!("r{index}"), output.handle.clone(), path);
    (output, binding)
}

fn checkpoint(seq: u64, bridge_end: u64) -> CodeRunStepCheckpoint {
    let mut state_hash = [0_u8; 32];
    state_hash[..8].copy_from_slice(&seq.to_le_bytes());
    CodeRunStepCheckpoint::new(seq, format!("step-{seq}"), state_hash, 5_000 + seq)
        .expect("checkpoint")
        .ending_at(bridge_end)
}

/// Adds one call, one bound output and, when `checkpoint_seq` is given, the
/// checkpoint of the step those end.
fn append(record: &mut CodeRunReplayRecord, index: u64, checkpoint_seq: Option<u64>) {
    record.bridge_calls.push(bridge_call(index));
    let (output, binding) = bound_output(index);
    record.outputs.push(output);
    record.bindings.push(binding);
    if let Some(seq) = checkpoint_seq {
        let calls = u64::try_from(record.bridge_calls.len()).expect("call count");
        record.step_checkpoints.push(checkpoint(seq, calls));
    }
}

fn is_concurrent_write(result: oneiron::Result<CodeRunReplayGeneration>) -> bool {
    matches!(result, Err(Error::ConcurrentWrite(_)))
}

#[test]
fn replay_step_append_timed() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    for index in 0..SEEDED {
        let step_end = (index + 1) % PER_SEEDED_STEP == 0;
        append(
            &mut record,
            index,
            step_end.then_some(index / PER_SEEDED_STEP),
        );
    }
    let mut generation = vault
        .put_code_run_replay_record_if_generation(&record, None)
        .expect("seeded record");

    let seeded_steps = SEEDED / PER_SEEDED_STEP;
    let mut previous = generation;
    let mut elapsed = Duration::ZERO;
    for step in 0..STEPS {
        append(&mut record, SEEDED + step, Some(seeded_steps + step));
        let started = Instant::now();
        let next = vault
            .put_code_run_replay_record_if_generation(&record, Some(generation))
            .expect("guarded append");
        elapsed += started.elapsed();
        previous = generation;
        generation = next;
    }
    let row_bytes = encode_code_run_replay_record(&record)
        .expect("encoded record")
        .len();
    let total_ms = elapsed.as_secs_f64() * 1_000.0;
    println!(
        "FIX16-APPEND seeded={SEEDED} steps={STEPS} row_bytes={row_bytes} total_ms={total_ms:.1} per_step_ms={:.2}",
        total_ms / STEPS as f64
    );

    // Each append stored exactly the record it was given.
    let stored = vault
        .get_code_run_replay_record(&run_id)
        .expect("stored record reads")
        .expect("stored record");
    assert_eq!(
        encode_code_run_replay_record(&stored).expect("stored bytes"),
        encode_code_run_replay_record(&record).expect("record bytes"),
    );
    assert_eq!(stored.generation().expect("stored generation"), generation);
    assert_eq!(generation.bridge_call_count, SEEDED + STEPS);
    assert_eq!(generation.output_count, SEEDED + STEPS);
    assert_eq!(generation.step_checkpoint_count, seeded_steps + STEPS);

    // A writer holding an older generation, or none, is refused; the
    // current one still appends.
    assert!(is_concurrent_write(
        vault.put_code_run_replay_record_if_generation(&record, Some(previous))
    ));
    assert!(is_concurrent_write(
        vault.put_code_run_replay_record_if_generation(&record, None)
    ));
    let again = vault
        .put_code_run_replay_record_if_generation(&record, Some(generation))
        .expect("current generation appends");
    assert_eq!(again, generation);
}
