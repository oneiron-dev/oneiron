//! A code-mode step's replay capture (FIX row [AGENT-RUN-START-LATENCY-4S]).
//! The executor's system prompt ends with the build's whole declarations
//! text (host verbs, the code-mode catalog, the runtime types), about 1.1 MB.
//! A step captures its request before its model call, in the vault's write
//! transaction, so the capture's cost delays every run's first call and every
//! write that arrives meanwhile. The capture keeps that compiled-in text out
//! of the stored request and names it by digest; the capsule's reader puts
//! it back, and reads none for declarations this build does not carry.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_mode_step_capture`.
#![cfg(oneiron_test_support)]

use std::time::{Duration, Instant};

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::code_mode_capture::{
    capture_step, captured_request, code_mode_request, executor_system_prompt, only_capsule,
    stored_request_bytes,
};
use oneiron::{AttemptId, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// A capture's bound. It took 1654-1666 ms per run on a dev build on
/// main 78cc2772937 (fleet job 1113-111412-b6ee, nelly).
const CAPTURE_BOUND: Duration = Duration::from_millis(400);

/// What a code-mode request stores at most, once its declarations are kept
/// out: its config, the prompt's head and the task.
const STORED_REQUEST_BOUND: usize = 64 * 1024;

fn vault_with_agent() -> (tempfile::TempDir, Vault, WriteActor) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let person = EntityId::from_bytes([0x5C; 16]).expect("entity id");
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("seed the step's actor");
    (dir, vault, WriteActor::new(person, EdgeActorClass::Agent))
}

#[test]
fn code_mode_step_capture_takes_under_400ms_per_run() {
    let (_dir, vault, actor) = vault_with_agent();
    let system = executor_system_prompt();
    for run in 0..3 {
        let request = code_mode_request(system.clone(), &format!("task {run}"));
        let started = Instant::now();
        let captured = capture_step(&vault, AttemptId::now(), actor, &request);
        let took = started.elapsed();
        eprintln!(
            "## COST capture_run{run} ms={:.1} system_bytes={}",
            took.as_secs_f64() * 1000.0,
            system.len()
        );
        assert!(captured, "run {run}: no capsule was staged");
        assert!(
            took < CAPTURE_BOUND,
            "run {run}: a code-mode step's capture took {took:?} (bound {CAPTURE_BOUND:?})"
        );
    }
}

#[test]
fn captured_code_mode_request_reads_back_as_sent() {
    let (_dir, vault, actor) = vault_with_agent();
    let request = code_mode_request(executor_system_prompt(), "list the open projects");
    let attempt = AttemptId::now();
    assert!(capture_step(&vault, attempt, actor, &request));
    let capsule = only_capsule(&vault, attempt).expect("the run's capsule");
    let read = captured_request(&vault, &capsule).expect("read the capsule's request");
    assert!(
        read.as_ref() == Some(&request),
        "the capsule's request does not read back as sent"
    );
    let sent = request.canonical_bytes().expect("canonical bytes");
    assert_eq!(
        capsule.request_hash,
        *blake3::hash(&sent).as_bytes(),
        "the capsule's request hash is not the hash of the request as sent"
    );
    assert!(
        capsule.as_sent(),
        "a request the wall placed nothing in does not read as the request as sent"
    );
}

#[test]
fn captured_code_mode_request_stores_its_declarations_by_reference() {
    let (_dir, vault, actor) = vault_with_agent();
    let request = code_mode_request(executor_system_prompt(), "list the open projects");
    let attempt = AttemptId::now();
    assert!(capture_step(&vault, attempt, actor, &request));
    let capsule = only_capsule(&vault, attempt).expect("the run's capsule");
    let stored = stored_request_bytes(&vault, &capsule)
        .expect("read the stored request")
        .expect("the capsule keeps its request");
    let sent = request.canonical_bytes().expect("canonical bytes");
    eprintln!(
        "## BYTES request_sent={} request_stored={}",
        sent.len(),
        stored.len()
    );
    assert!(
        stored.len() <= STORED_REQUEST_BOUND,
        "the capsule stores {} request bytes of the {} sent (bound {STORED_REQUEST_BOUND})",
        stored.len(),
        sent.len()
    );
}

#[test]
fn a_request_naming_declarations_this_build_lacks_reads_none() {
    let (_dir, vault, actor) = vault_with_agent();
    let other = format!(
        "You are Oneiron's engine-native executor.\n[executor declarations blake3:{}]",
        "0".repeat(64)
    );
    let request = code_mode_request(other, "list the open projects");
    let attempt = AttemptId::now();
    assert!(capture_step(&vault, attempt, actor, &request));
    let capsule = only_capsule(&vault, attempt).expect("the run's capsule");
    let read = captured_request(&vault, &capsule).expect("read the capsule's request");
    assert!(
        read.is_none(),
        "a request naming another build's declarations read back rebuilt"
    );
}
