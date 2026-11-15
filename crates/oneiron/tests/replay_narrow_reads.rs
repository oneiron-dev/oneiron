//! The narrow replay reads (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT PR4): a run's checkpoint count,
//! outputs and bridge calls read without the other families, equal to the assembled record's,
//! and flat in the unread families' sizes. No retired-marker test: nothing public or behind a
//! door retires one run's replay row alone (see CHANGES.md).
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test replay_narrow_reads`
#![cfg(oneiron_test_support)]

use oneiron::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunResultBinding, CodeRunStepCheckpoint, SelfCall, SelfDispatchOutcome,
    SelfMemorySearchCall, SelfMemorySearchResult,
};
use oneiron::test_doors::replay_rows;
use oneiron::{EntityId, Vault, VaultConfig};

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

#[test]
fn narrow_reads_equal_the_assembled_record() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    for index in 0..4_u64 {
        let checkpoint_seq = if index < 3 { Some(index) } else { None };
        append(&mut record, index, checkpoint_seq);
    }
    record.bridge_calls.push(bridge_call(4));
    vault
        .put_code_run_replay_record_if_generation(&record, None)
        .expect("seeded record");
    let stored = vault
        .get_code_run_replay_record(&run_id)
        .expect("stored record reads")
        .expect("stored record");
    assert_eq!(stored.bridge_calls.len(), 5);
    assert_eq!(stored.step_checkpoints.len(), 3);
    assert_eq!(stored.outputs.len(), 4);
    assert_eq!(
        replay_rows::outputs(&vault, run_id).expect("outputs read"),
        Some(stored.outputs.clone()),
    );
    assert_eq!(
        replay_rows::bridge_calls(&vault, run_id).expect("bridge calls read"),
        Some(stored.bridge_calls.clone()),
    );
    assert_eq!(
        replay_rows::checkpoint_count(&vault, run_id).expect("checkpoint count reads"),
        Some(stored.step_checkpoints.len() as u64),
    );
}

#[test]
fn an_absent_run_reads_none() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    assert_eq!(
        replay_rows::outputs(&vault, run_id).expect("outputs read"),
        None,
    );
    assert_eq!(
        replay_rows::bridge_calls(&vault, run_id).expect("bridge calls read"),
        None,
    );
    assert_eq!(
        replay_rows::checkpoint_count(&vault, run_id).expect("checkpoint count reads"),
        None,
    );
}

#[test]
fn an_outputs_read_is_flat_in_the_call_count() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let seed = |calls: u64| {
        let run_id = EntityId::now();
        let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
        for index in 0..calls {
            record.bridge_calls.push(bridge_call(index));
        }
        for seq in 0..3_u64 {
            record.step_checkpoints.push(checkpoint(seq, seq + 1));
        }
        for index in 0..3_u64 {
            let (output, binding) = bound_output(index);
            record.outputs.push(output);
            record.bindings.push(binding);
        }
        vault
            .put_code_run_replay_record_if_generation(&record, None)
            .expect("seeded record");
        run_id
    };
    let small = seed(20);
    let big = seed(2_000);

    let before = replay_rows::read_bytes();
    let small_outputs = replay_rows::outputs(&vault, small)
        .expect("small outputs read")
        .expect("small outputs");
    let outputs_small = replay_rows::read_bytes() - before;
    assert_eq!(small_outputs.len(), 3);

    let before = replay_rows::read_bytes();
    let big_outputs = replay_rows::outputs(&vault, big)
        .expect("big outputs read")
        .expect("big outputs");
    let outputs_big = replay_rows::read_bytes() - before;
    assert_eq!(big_outputs, small_outputs);

    let before = replay_rows::read_bytes();
    let small_count = replay_rows::checkpoint_count(&vault, small)
        .expect("small count reads")
        .expect("small count");
    let counts_small = replay_rows::read_bytes() - before;
    assert_eq!(small_count, 3);

    let before = replay_rows::read_bytes();
    let big_count = replay_rows::checkpoint_count(&vault, big)
        .expect("big count reads")
        .expect("big count");
    let counts_big = replay_rows::read_bytes() - before;
    assert_eq!(big_count, 3);

    let before = replay_rows::read_bytes();
    vault
        .get_code_run_replay_record(&small)
        .expect("small whole read")
        .expect("small record");
    let whole_small = replay_rows::read_bytes() - before;

    let before = replay_rows::read_bytes();
    vault
        .get_code_run_replay_record(&big)
        .expect("big whole read")
        .expect("big record");
    let whole_big = replay_rows::read_bytes() - before;

    eprintln!(
        "narrow read bytes: outputs {} {} counts {} {} whole {} {}",
        outputs_small, outputs_big, counts_small, counts_big, whole_small, whole_big
    );
    // The narrow reads are flat in the call count: only the head's own count
    // field grows (a wider MessagePack int for 2,000 than for 20), never the
    // items, so the outputs items' bytes are exactly equal and each narrow
    // delta moves by at most a few head bytes while the whole read grows.
    assert_eq!(outputs_small - counts_small, outputs_big - counts_big);
    assert!(
        outputs_big - outputs_small <= 8,
        "outputs read grew with the call count: {outputs_small} to {outputs_big}"
    );
    assert!(
        counts_big - counts_small <= 8,
        "count read grew with the call count: {counts_small} to {counts_big}"
    );
    assert!(
        whole_big > whole_small + 100_000,
        "whole read did not grow with the call count: {whole_small} to {whole_big}"
    );
}
