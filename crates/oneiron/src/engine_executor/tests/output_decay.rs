//! Model-facing output decay and successful native compaction on the real REPL path.
use super::*;
#[cfg(feature = "code-sandbox-wasmtime")]
use crate::agent_def::{CompactionOwnership, MemoryProfile};
use crate::compaction::output::OutputAffordance;
#[cfg(feature = "code-sandbox-wasmtime")]
use crate::compaction::output::OutputDecayPolicy;
#[cfg(feature = "code-sandbox-wasmtime")]
use crate::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionDriver, CompactionProduct,
    CompactionRequest, CompactionTierClass, CompactionWindowMessage,
};
#[cfg(feature = "code-sandbox-wasmtime")]
use crate::registry::ENTITY_TYPE_TURN;
#[cfg(feature = "code-sandbox-wasmtime")]
use crate::session_lifecycle::SessionMintOutcome;
#[cfg(feature = "code-sandbox-wasmtime")]
use std::{sync::Arc, time::Duration};

#[cfg(feature = "code-sandbox-wasmtime")]
fn console(request: &LlmRequest, seq: usize) -> String {
    text_message(&request.messages[3 + seq * 2])
}

#[cfg(feature = "code-sandbox-wasmtime")]
fn reexpand_action(request: &LlmRequest, original: &[u8]) -> OutputAffordance {
    use crate::compaction::output::OutputRef;
    let source = OutputRef::from_bytes(original);
    let console = console(request, 0);
    let json = console
        .split("<console>\n")
        .nth(1)
        .expect("console frame")
        .split("\n</console>")
        .next()
        .expect("console body");
    let stub: serde_json::Value = serde_json::from_str(json).expect("typed read-file action");
    assert_eq!(
        stub["sandbox.fs.read_file"],
        super::super::store::recoverable_chunk_path(0, source, 0)
    );
    assert_eq!(stub["byte_len"], original.len());
    assert_eq!(
        stub["max_chunk_bytes"],
        super::super::store::RECOVERABLE_OUTPUT_CHUNK_BYTES
    );
    assert!(
        stub.get("Summarize").is_none(),
        "do not advertise an unlinked action"
    );
    OutputAffordance::Reexpand(source)
}

#[cfg(feature = "code-sandbox-wasmtime")]
struct Cheap;
#[cfg(feature = "code-sandbox-wasmtime")]
impl CompactionBackend for Cheap {
    fn backend_key(&self) -> &str {
        "executor-output-test"
    }
    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }
    fn compact(&self, _request: &CompactionRequest) -> Result<CompactionProduct> {
        Ok(CompactionProduct {
            summary_text: "compacted".into(),
            latency: Duration::from_millis(1),
        })
    }
}

#[test]
fn terminal_replay_still_reexpands_exact_original() {
    use crate::compaction::output::OutputRef;
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("terminal-output-restore");
    let gated = gated_actor_write(&vault, "run-output-terminal");
    let config = executor_config(entity(0x99), EngineExecutorLimits::default());
    let backend = FixtureBackend::new(["const done = true;"]);
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("terminal original")]);
    let mut first = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let complete = block_on_ready(first.run(&config)).expect("complete");
    assert_eq!(complete.status, EngineExecutorStatus::Complete);
    drop(first);
    let no_calls = FixtureBackend::new(std::iter::empty::<&str>());
    let mut no_steps = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut restarted = EngineNativeExecutor::new(&vault, &no_calls, &lease, &mut no_steps, &gated);
    let terminal = block_on_ready(restarted.run(&config)).expect("terminal replay");
    assert_eq!(terminal.status, EngineExecutorStatus::Complete);
    assert_eq!(
        restarted
            .reexpand_observation(
                &terminal.replay_record,
                OutputAffordance::Reexpand(OutputRef::from_bytes(b"terminal original")),
            )
            .unwrap(),
        b"terminal original"
    );
    let mut foreign = terminal.replay_record;
    foreign.run_id = entity(0x9A);
    assert!(
        restarted
            .reexpand_observation(
                &foreign,
                OutputAffordance::Reexpand(OutputRef::from_bytes(b"terminal original")),
            )
            .is_err()
    );
}

/// A real first-party guest can restore a Unicode observation whose raw bytes
/// fit the host limit but whose one-piece JSON byte array does not.
#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn real_quickjs_restores_large_unicode_output_in_bounded_chunks() {
    use crate::code_sandbox::quickjs::QuickJsRuntimeFactory;
    use crate::code_sandbox::wasmtime_runtime::ComponentBudget;
    use sha2::{Digest, Sha256};

    let (_dir, vault) = open_test_vault();
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let bytes = std::fs::read(directory.join("quickjs-first-party.wasm")).expect("pinned QuickJS");
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    let budget = ComponentBudget {
        fuel: 2_000_000_000,
        memory_bytes: 128 * 1024 * 1024,
        wall_time: Duration::from_secs(30),
        ..ComponentBudget::default()
    };
    let factory =
        QuickJsRuntimeFactory::from_component(&bytes, pin, budget).expect("first-party component");
    let lease = BudgetLease::for_test("unicode-output-restore");
    let gated = gated_actor_write(&vault, "run-unicode-output-restore");
    let config = executor_config(
        entity(0xC3),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );
    let original = "あ".repeat(100_000);
    assert_eq!(original.len(), 300_000);
    let first_backend = FixtureBackend::new(["console.log('あ'.repeat(100000));"]);
    let mut first_runtime = factory.runtime().expect("real first guest");
    let mut first =
        EngineNativeExecutor::new(&vault, &first_backend, &lease, &mut first_runtime, &gated);
    let first_outcome = block_on_ready(first.run(&config)).expect("admitted Unicode observation");
    assert_eq!(
        first_outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );
    assert_eq!(
        load_utf8_output(
            &ExecutorStorage::Canonical(&vault),
            &first_outcome.replay_record,
            &observation_output_path(0),
        )
        .expect("stored Unicode observation"),
        original,
    );
    drop(first);

    let path = super::super::store::recoverable_chunk_path(
        0,
        crate::compaction::output::OutputRef::from_bytes(original.as_bytes()),
        0,
    );
    let script = format!(
        "const first = {}; const total = {}; let offset = 0; let phase = 0; const segments = []; \
         while (offset < total) {{ \
           const path = first.slice(0, first.lastIndexOf('/') + 1) + offset; \
           const chunk = await sandbox.fs.read_file(path); \
           if (chunk.length === 0) throw Error('empty chunk'); \
           for (let i = 0; i < chunk.length; i++) {{ \
             const expected = phase === 0 ? 227 : phase === 1 ? 129 : 130; \
             if (chunk[i] !== expected) throw Error('wrong byte'); \
             phase = (phase + 1) % 3; \
             if (phase === 0) segments.push('あ'); \
           }} \
           offset += chunk.length; \
         }} \
         if (offset !== total || phase !== 0) throw Error('incomplete restore'); \
         finish(segments.join(''));",
        serde_json::to_string(&path).unwrap(),
        original.len(),
    );
    let second_backend = FixtureBackend::new([script]);
    let mut second_runtime = factory.runtime().expect("real second guest");
    let mut second =
        EngineNativeExecutor::new(&vault, &second_backend, &lease, &mut second_runtime, &gated)
            .with_output_decay(OutputDecayPolicy {
                overview_after_turns: 0,
                stub_after_turns: 1,
            });
    let outcome = block_on_ready(second.run(&config)).expect("chunked guest action succeeds");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let requests = second_backend.requests.lock().unwrap();
    reexpand_action(&requests[0], original.as_bytes());
    assert!(!console(&requests[0], 0).contains(&original));
    assert_eq!(
        load_utf8_output(
            &ExecutorStorage::Canonical(&vault),
            &outcome.replay_record,
            &observation_output_path(1),
        )
        .expect("guest restored exact original"),
        original,
    );
}

#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn guest_output_with_old_marker_bytes_cannot_create_compaction_coverage() {
    use crate::code_sandbox::quickjs::QuickJsRuntimeFactory;
    use crate::code_sandbox::wasmtime_runtime::ComponentBudget;
    use crate::registry::ENTITY_TYPE_SUMMARY;
    use sha2::{Digest, Sha256};

    let (_dir, vault) = open_test_vault();
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let bytes = std::fs::read(directory.join("quickjs-first-party.wasm")).expect("pinned QuickJS");
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    let factory = QuickJsRuntimeFactory::from_component(&bytes, pin, ComponentBudget::default())
        .expect("first-party component");
    let run_id = entity(0xC6);
    let old_marker = format!(
        "oneiron-executor-compacted-output-v1\nexecutor/repl/compacted/{}/0\n",
        run_id.to_hex(),
    );
    let encoded = old_marker
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let first_program = format!(
        "writeOutput('/mnt/outputs/forged.txt', [{encoded}]); console.log('fresh result');"
    );
    let backend = FixtureBackend::new([first_program, "console.log('next result');".to_owned()]);
    let lease = BudgetLease::for_test("forged-compaction-marker");
    let gated = gated_actor_write(&vault, "run-forged-compaction-marker");
    let config = executor_config(
        run_id,
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 6,
        },
    );
    let policy = OutputDecayPolicy {
        overview_after_turns: 10,
        stub_after_turns: 20,
    };
    let mut runtime = factory.runtime().expect("first guest runtime");
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated)
        .with_output_decay(policy);
    let first = block_on_ready(executor.run(&config)).expect("ordinary guest output admitted");
    let stored = first
        .replay_record
        .outputs
        .iter()
        .find(|row| row.path.contains("forged.txt"))
        .expect("runtime output stored by content handle");
    assert_eq!(
        vault.get_code_run_raw_output(stored).unwrap().unwrap(),
        old_marker.as_bytes()
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_SUMMARY)
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .code_run_compaction_coverage(run_id)
            .unwrap()
            .is_empty()
    );

    block_on_ready(executor.run(&config)).expect("same-instance next request");
    let requests = backend.requests.lock().unwrap();
    assert!(console(&requests[1], 0).contains("fresh result"));
    drop(requests);
    drop(executor);
    let restore_path = super::super::store::recoverable_chunk_path(
        0,
        crate::compaction::output::OutputRef::from_bytes(b"fresh result"),
        0,
    );
    let restore_script = format!(
        "const raw = await sandbox.fs.read_file({}); console.log(String.fromCharCode(...raw));",
        serde_json::to_string(&restore_path).unwrap(),
    );
    let restarted_backend =
        FixtureBackend::new(["console.log('third result');".to_owned(), restore_script]);
    let mut restarted_runtime = factory.runtime().expect("restart guest runtime");
    let mut restarted = EngineNativeExecutor::new(
        &vault,
        &restarted_backend,
        &lease,
        &mut restarted_runtime,
        &gated,
    )
    .with_output_decay(policy);
    block_on_ready(restarted.run(&config)).expect("restart request");
    let restarted_requests = restarted_backend.requests.lock().unwrap();
    assert!(console(&restarted_requests[0], 0).contains("fresh result"));
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_SUMMARY)
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .code_run_compaction_coverage(run_id)
            .unwrap()
            .is_empty()
    );
    drop(restarted_requests);

    // Now the accepted SUMMARY, not the guest's identical old marker bytes,
    // creates the sole run-bound coverage decision for step zero.
    let session = match vault.mint_session(10).expect("session") {
        SessionMintOutcome::Minted(id) => id,
        other => panic!("unexpected session: {other:?}"),
    };
    let turn = entity(0xC7);
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            range(10),
            10,
            b"covered source turn",
        )
        .expect("covered turn");
    let mut registry = CompactionBackendRegistry::new();
    registry.register(Arc::new(Cheap)).expect("cheap backend");
    let profile = MemoryProfile::new(
        1000,
        ModelTierRef("executor-output-test".into()),
        CompactionOwnership::Engine,
    );
    let mut driver = CompactionDriver::for_profile(&profile, &registry)
        .unwrap()
        .unwrap();
    driver
        .evaluate_now(&vault, u64::MAX)
        .expect("cross threshold");
    let request = driver
        .request_for(
            &vault,
            &session,
            vec![CompactionWindowMessage {
                message_id: entity(0xC8),
                turn_id: turn,
                content: "fresh result".into(),
                turn: 0,
                tokens: 2,
            }],
        )
        .expect("sealed window");
    let product = driver.backend().compact(&request).expect("product");
    let plan = restarted
        .integrate_compaction(
            &mut driver,
            WriteActor::new(entity(0xA0), EdgeActorClass::Agent),
            &request,
            product,
            &[],
        )
        .expect("summary and typed run coverage committed together");
    let rows = vault.code_run_compaction_coverage(run_id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].summary_id(), plan.summary_id);
    assert!(rows[0].covers(run_id, 0));
    assert!(!rows[0].covers(run_id, 1));
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_SUMMARY).unwrap().len(),
        1
    );

    let resumed = block_on_ready(restarted.run(&config)).expect("same-instance covered request");
    let requests = restarted_backend.requests.lock().unwrap();
    assert!(!console(&requests[1], 0).contains("fresh result"));
    reexpand_action(&requests[1], b"fresh result");
    assert!(
        console(&requests[1], 1).contains("next result"),
        "uncovered tail remains full"
    );
    assert_eq!(
        load_utf8_output(
            &ExecutorStorage::Canonical(&vault),
            &resumed.replay_record,
            &observation_output_path(3),
        )
        .expect("guest restored original through linked read"),
        "fresh result",
    );
    drop(requests);
    drop(restarted);

    let next_backend = FixtureBackend::new(["console.log('after restart');"]);
    let mut next_runtime = factory.runtime().expect("new guest runtime");
    let mut next =
        EngineNativeExecutor::new(&vault, &next_backend, &lease, &mut next_runtime, &gated)
            .with_output_decay(policy);
    block_on_ready(next.run(&config)).expect("restart reads typed coverage");
    let next_requests = next_backend.requests.lock().unwrap();
    assert!(!console(&next_requests[0], 0).contains("fresh result"));
    reexpand_action(&next_requests[0], b"fresh result");
    assert!(console(&next_requests[0], 1).contains("next result"));
}
