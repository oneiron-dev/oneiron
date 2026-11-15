//! The split replay rows assemble (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT PR1 and PR2).
//! Head plus items join to the whole encoding; appends, rebinds, whole puts and header
//! crossings keep it, and the historical lift sweep walks every item through its head.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test replay_split_rows`
#![cfg(oneiron_test_support)]

use oneiron::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunResultBinding, CodeRunStepCheckpoint, SelfCall, SelfDispatchOutcome,
    SelfMemorySearchCall, SelfMemorySearchResult, encode_code_run_replay_record,
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
fn appends_assemble_the_record_put() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    for index in 0..40_u64 {
        append(&mut record, index, Some(index));
    }
    let mut generation = vault
        .put_code_run_replay_record_if_generation(&record, None)
        .expect("seeded record");
    for step in 0..10_u64 {
        let index = 40 + step;
        append(&mut record, index, Some(index));
        generation = vault
            .put_code_run_replay_record_if_generation(&record, Some(generation))
            .expect("guarded append");
        let stored = vault
            .get_code_run_replay_record(&run_id)
            .expect("stored record reads")
            .expect("stored record");
        assert_eq!(stored, record);
        let door_bytes = replay_rows::canonical_bytes(&vault, run_id)
            .expect("door reads")
            .expect("door finds the row");
        assert_eq!(
            door_bytes,
            encode_code_run_replay_record(&record).expect("in-memory bytes"),
        );
    }
}

#[test]
fn a_rebind_replaces_its_slot() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    for index in 0..10_u64 {
        append(&mut record, index, Some(index));
    }
    let generation = vault
        .put_code_run_replay_record_if_generation(&record, None)
        .expect("seeded record");
    let before = replay_rows::item_count(&vault, run_id).expect("item count reads");
    let other = record.outputs[5].clone();
    record.bindings[3] = CodeRunResultBinding::new(
        record.bindings[3].name.clone(),
        other.handle.clone(),
        other.path.clone(),
    );
    vault
        .put_code_run_replay_record_if_generation(&record, Some(generation))
        .expect("guarded rebind");
    let stored = vault
        .get_code_run_replay_record(&run_id)
        .expect("stored record reads")
        .expect("stored record");
    assert_eq!(stored.bindings, record.bindings);
    let after = replay_rows::item_count(&vault, run_id).expect("item count reads");
    assert_eq!(after, before);
}

#[test]
fn a_whole_put_after_a_shorter_record_drops_stale_items() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let determinism = CodeRunDeterminism::new(0, [7; 32]);
    let mut long = CodeRunReplayRecord::new(run_id, determinism);
    for index in 0..30_u64 {
        append(&mut long, index, Some(index));
    }
    vault
        .put_code_run_replay_record_if_generation(&long, None)
        .expect("long record");
    let mut short = CodeRunReplayRecord::new(run_id, determinism);
    for index in 0..10_u64 {
        append(&mut short, index, Some(index));
    }
    vault
        .put_code_run_replay_record_if_generation(&short, None)
        .expect("short record");
    let stored = vault
        .get_code_run_replay_record(&run_id)
        .expect("stored record reads")
        .expect("stored record");
    assert_eq!(stored, short);
    let count = replay_rows::item_count(&vault, run_id).expect("item count reads");
    let expected = (short.bridge_calls.len()
        + short.step_checkpoints.len()
        + short.outputs.len()
        + short.bindings.len()) as u64;
    assert_eq!(count, expected);
}

#[test]
fn two_families_cross_the_array16_header() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    for index in 0..15_u64 {
        record.bridge_calls.push(bridge_call(index));
        let (output, binding) = bound_output(index);
        record.outputs.push(output);
        if index < 5 {
            record.bindings.push(binding);
        }
    }
    for seq in 0..5_u64 {
        record.step_checkpoints.push(checkpoint(seq, (seq + 1) * 3));
    }
    let mut generation = vault
        .put_code_run_replay_record_if_generation(&record, None)
        .expect("seeded record");
    for index in 15..17_u64 {
        record.bridge_calls.push(bridge_call(index));
        let (output, _) = bound_output(index);
        record.outputs.push(output);
        generation = vault
            .put_code_run_replay_record_if_generation(&record, Some(generation))
            .expect("guarded append");
        let door_bytes = replay_rows::canonical_bytes(&vault, run_id)
            .expect("door reads")
            .expect("door finds the row");
        assert_eq!(
            door_bytes,
            encode_code_run_replay_record(&record).expect("in-memory bytes"),
        );
    }
}

#[test]
fn the_lift_sweep_walks_every_item_through_its_head() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    for index in 0..4_u64 {
        append(&mut record, index, Some(index));
    }
    vault
        .put_code_run_replay_record_if_generation(&record, None)
        .expect("seeded record");
    let items = replay_rows::item_count(&vault, run_id).expect("item count reads");
    assert_eq!(items, 16);
    let routed = replay_rows::lift_routed_items(&vault, run_id).expect("lift route reads");
    assert_eq!(routed, items);
}
