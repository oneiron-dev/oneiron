//! The replay-rows seam joins head and items (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT PR1 and PR2).
//! Every raw access to the code-run replay tables goes through the one door, so the
//! door's canonical bytes are the record's encoding as stored, and a guarded append
//! writes bytes flat in the run length.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test replay_rows_seam`
#![cfg(oneiron_test_support)]

use oneiron::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunResultBinding, CodeRunStepCheckpoint, SelfCall, SelfDispatchOutcome,
    SelfMemorySearchCall, SelfMemorySearchResult, decode_code_run_replay_record,
    encode_code_run_replay_record,
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
fn canonical_bytes_are_the_encoded_record() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    let mut index = 0_u64;
    for step in 0..20_u64 {
        for _ in 0..3 {
            record.bridge_calls.push(bridge_call(index));
            let (output, binding) = bound_output(index);
            record.outputs.push(output);
            record.bindings.push(binding);
            index += 1;
        }
        let calls = u64::try_from(record.bridge_calls.len()).expect("call count");
        record.step_checkpoints.push(checkpoint(step, calls));
    }
    vault
        .put_code_run_replay_record(&record)
        .expect("put record");
    let stored = vault
        .get_code_run_replay_record(&run_id)
        .expect("stored record reads")
        .expect("stored record");
    let door_bytes = replay_rows::canonical_bytes(&vault, run_id)
        .expect("door reads")
        .expect("door finds the row");
    assert_eq!(
        door_bytes,
        encode_code_run_replay_record(&stored).expect("stored bytes"),
    );
    assert_eq!(
        decode_code_run_replay_record(&door_bytes).expect("door bytes decode"),
        stored,
    );
    let unknown = EntityId::now();
    assert_eq!(
        replay_rows::canonical_bytes(&vault, unknown).expect("unknown reads"),
        None,
    );
}

#[test]
fn a_guarded_append_writes_bytes_flat_in_the_run_length() {
    let mut deltas = Vec::new();
    for seeded in [20_u64, 2_000_u64] {
        let directory = tempfile::tempdir().expect("temporary vault");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
        let run_id = EntityId::now();
        let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
        for index in 0..seeded {
            append(&mut record, index, Some(index));
        }
        let generation = vault
            .put_code_run_replay_record_if_generation(&record, None)
            .expect("seeded record");
        append(&mut record, seeded, Some(seeded));
        let before = replay_rows::written_bytes();
        vault
            .put_code_run_replay_record_if_generation(&record, Some(generation))
            .expect("guarded append");
        let after = replay_rows::written_bytes();
        let delta = after.saturating_sub(before);
        deltas.push(delta);
    }
    let ratio = deltas[1] as f64 / deltas[0] as f64;
    println!(
        "replay append bytes: seeded20={} seeded2000={} ratio={ratio:.2}",
        deltas[0], deltas[1],
    );
    assert!(
        deltas[1] <= deltas[0] * 2,
        "append bytes grow with the run: {} vs {}",
        deltas[1],
        deltas[0],
    );
}
