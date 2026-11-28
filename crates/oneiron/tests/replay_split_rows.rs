//! The split replay rows assemble (FIX CODE-RUN-REPLAY-SPLIT-LAYOUT PR1 and PR2).
//! Head plus items join to the whole encoding; appends, rebinds, whole puts and header
//! crossings keep it, a guarded write that replaces a stored checkpoint persists it, the
//! side-row wall reads the head's fields as it read the whole record's, and the historical
//! lift sweep walks every item through its head.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test replay_split_rows`
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::code_run::{
    CodeRunAbiLayoutCheck, CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput,
    CodeRunReplayRecord, CodeRunResultBinding, CodeRunStepCheckpoint, SelfCall,
    SelfDispatchOutcome, SelfMemorySearchCall, SelfMemorySearchResult,
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
    let long_generation = vault
        .put_code_run_replay_record_if_generation(&long, None)
        .expect("long record");
    let mut short = CodeRunReplayRecord::new(run_id, determinism);
    for index in 0..10_u64 {
        append(&mut short, index, Some(index));
    }
    // Under the long record's generation: the shorter counts select the whole put.
    vault
        .put_code_run_replay_record_if_generation(&short, Some(long_generation))
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
fn a_guarded_write_that_replaces_a_stored_checkpoint_persists_it() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    for index in 0..6_u64 {
        append(&mut record, index, Some(index));
    }
    let generation = vault
        .put_code_run_replay_record_if_generation(&record, None)
        .expect("seeded record");
    // No count moves, so the guarded write takes the append path: a middle
    // checkpoint and the last one (whose hash the generation carries) change.
    record.step_checkpoints[2].state_hash = [9; 32];
    let last = record.step_checkpoints.len() - 1;
    record.step_checkpoints[last].state_hash = [8; 32];
    let next = vault
        .put_code_run_replay_record_if_generation(&record, Some(generation))
        .expect("guarded overwrite");
    let stored = vault
        .get_code_run_replay_record(&run_id)
        .expect("stored record reads")
        .expect("stored record");
    assert_eq!(stored, record);
    assert_eq!(stored.generation().expect("stored generation"), next);
    vault
        .put_code_run_replay_record_if_generation(&stored, Some(next))
        .expect("the read record saves under its own generation");
}

/// The public BIP39 test vector, a recovery phrase's twelve words.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

#[test]
fn a_recovery_phrase_in_an_abi_check_is_refused_at_the_head() {
    let directory = tempfile::tempdir().expect("temporary vault");
    // The owner's scan switch at its default (on), with a custody door.
    let vault = Vault::open(directory.path(), VaultConfig::default()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    let clean_run = EntityId::now();
    let mut clean = CodeRunReplayRecord::new(clean_run, CodeRunDeterminism::new(0, [7; 32]));
    append(&mut clean, 0, Some(0));
    vault
        .put_code_run_replay_record_if_generation(&clean, None)
        .expect("a clean record lands with the scan on");
    let run_id = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(0, [7; 32]));
    append(&mut record, 0, Some(0));
    let words: Vec<&str> = PHRASE.split(' ').collect();
    record
        .abi_layout_checks
        .push(CodeRunAbiLayoutCheck::for_fields("fixture", 1, &words));
    // The head's shell carries the ABI checks: the wall reads the field words
    // joined, as in the whole record, and a masked check no longer matches its
    // layout hash, so the write refuses rather than store the phrase or an
    // unreadable record.
    let refused = vault.put_code_run_replay_record_if_generation(&record, None);
    assert!(refused.is_err(), "the phrase write landed: {refused:?}");
    assert!(
        vault
            .get_code_run_replay_record(&run_id)
            .expect("the refused run reads")
            .is_none()
    );
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
