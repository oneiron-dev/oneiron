//! Model-facing output decay and successful native compaction on the real REPL path.
use super::*;
use crate::agent_def::{CompactionOwnership, MemoryProfile};
use crate::compaction::output::{OutputAffordance, OutputDecayPolicy};
use crate::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionDriver, CompactionProduct,
    CompactionRequest, CompactionTierClass, CompactionWindowMessage,
};
use crate::registry::ENTITY_TYPE_TURN;
use crate::session_lifecycle::SessionMintOutcome;
use std::{sync::Arc, time::Duration};

fn console(request: &LlmRequest, seq: usize) -> String {
    text_message(&request.messages[3 + seq * 2])
}

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

#[test]
fn durable_executor_requests_decay_and_reexpand_original_observation() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new((0..6).map(|_| "const x = 1;"));
    let lease = BudgetLease::for_test("output-decay");
    let raw = format!("{} exact tail", "abcdef".repeat(40));
    let mut runtime = FixtureRuntime::new((0..6).map(|seq| {
        JsCodeModeStepOutcome::pending(if seq == 0 {
            raw.clone()
        } else {
            format!("row {seq}")
        })
    }));
    let gated = gated_actor_write(&vault, "run-output-decay");
    let config = executor_config(
        entity(0x94),
        EngineExecutorLimits {
            soft_steps: 6,
            hard_steps: 8,
        },
    );
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated)
        .with_output_decay(OutputDecayPolicy {
            overview_after_turns: 2,
            stub_after_turns: 4,
        });
    let outcome = block_on_ready(executor.run(&config)).expect("six steps");
    let requests = backend.requests.lock().expect("requests");
    assert!(console(&requests[1], 0).contains(&raw), "fresh full view");
    let overview = console(&requests[2], 0);
    assert!(overview.contains(&raw[..128]));
    assert!(!overview.contains("exact tail"));
    let stub = console(&requests[4], 0);
    assert!(!stub.contains(&raw));
    let action = reexpand_action(&requests[4], raw.as_bytes());
    assert_eq!(
        executor
            .reexpand_observation(&outcome.replay_record, action)
            .unwrap(),
        raw.as_bytes()
    );
}

struct Cheap;
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
fn successful_native_compaction_changes_the_next_real_executor_request() {
    let (_dir, vault) = open_test_vault();
    let session = match vault.mint_session(10).expect("mint session") {
        SessionMintOutcome::Minted(id) => id,
        other => panic!("unexpected session: {other:?}"),
    };
    let turn = entity(0x96);
    vault
        .put_entity(&turn, ENTITY_TYPE_TURN, range(10), 10, b"source turn")
        .expect("turn");
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
    let backend = FixtureBackend::new(["const a = 1;", "const b = 2;", "const c = 3;"]);
    let lease = BudgetLease::for_test("output-compact");
    let mut runtime = FixtureRuntime::new([
        JsCodeModeStepOutcome::pending("covered original"),
        JsCodeModeStepOutcome::pending("retained tail"),
        JsCodeModeStepOutcome::pending("later"),
    ]);
    let gated = gated_actor_write(&vault, "run-output-compact");
    let mut config = executor_config(
        entity(0x97),
        EngineExecutorLimits {
            soft_steps: 2,
            hard_steps: 4,
        },
    );
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated)
        .with_output_decay(OutputDecayPolicy {
            overview_after_turns: 2,
            stub_after_turns: 5,
        });
    let first = block_on_ready(executor.run(&config)).expect("first two steps");
    assert_eq!(
        first.status,
        EngineExecutorStatus::Yielded { next_step_seq: 2 }
    );
    driver
        .evaluate_now(&vault, u64::MAX)
        .expect("cross threshold");
    let request = driver
        .request_for(
            &vault,
            &session,
            vec![CompactionWindowMessage {
                message_id: entity(0x98),
                turn_id: turn,
                content: "covered original".into(),
                turn: 0,
                tokens: 2,
            }],
        )
        .expect("request");
    let product = driver.backend().compact(&request).expect("product");
    executor
        .integrate_compaction(
            &mut driver,
            WriteActor::new(entity(0xA0), EdgeActorClass::Agent),
            &request,
            product,
            &[],
        )
        .expect("compaction commit");
    config.limits.soft_steps = 1;
    let resumed = block_on_ready(executor.run(&config)).expect("next real model request");
    assert_eq!(
        resumed.status,
        EngineExecutorStatus::Yielded { next_step_seq: 3 }
    );
    let requests = backend.requests.lock().expect("requests");
    assert_eq!(requests.len(), 3);
    let next = &requests[2];
    assert!(!console(next, 0).contains("covered original"));
    assert!(
        console(next, 1).contains("retained tail"),
        "{}",
        console(next, 1)
    );
    let action = reexpand_action(next, b"covered original");
    assert_eq!(
        executor
            .reexpand_observation(&resumed.replay_record, action)
            .unwrap(),
        b"covered original"
    );
    drop(requests);
    drop(executor);

    // A new executor rehydrates the committed reference through its routed
    // marker, rather than replaying a freshly expanded historical console.
    let restarted_backend = FixtureBackend::new(["const d = 4;"]);
    let mut restarted_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("again")]);
    let mut restarted = EngineNativeExecutor::new(
        &vault,
        &restarted_backend,
        &lease,
        &mut restarted_runtime,
        &gated,
    )
    .with_output_decay(OutputDecayPolicy {
        overview_after_turns: 2,
        stub_after_turns: 5,
    });
    let after_restart = block_on_ready(restarted.run(&config)).expect("restart");
    let restarted_requests = restarted_backend.requests.lock().expect("restart requests");
    assert!(!console(&restarted_requests[0], 0).contains("covered original"));
    assert!(console(&restarted_requests[0], 1).contains("retained tail"));
    assert_eq!(
        restarted
            .reexpand_observation(
                &after_restart.replay_record,
                reexpand_action(&restarted_requests[0], b"covered original"),
            )
            .unwrap(),
        b"covered original"
    );
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

#[test]
fn one_step_yield_compacts_latest_committed_output_and_keeps_next_tail() {
    let (_dir, vault) = open_test_vault();
    let session = match vault.mint_session(10).expect("mint") {
        SessionMintOutcome::Minted(id) => id,
        other => panic!("unexpected session: {other:?}"),
    };
    let turn = entity(0xB6);
    vault
        .put_entity(&turn, ENTITY_TYPE_TURN, range(10), 10, b"covered turn")
        .unwrap();
    let mut registry = CompactionBackendRegistry::new();
    registry.register(Arc::new(Cheap)).unwrap();
    let profile = MemoryProfile::new(
        1000,
        ModelTierRef("executor-output-test".into()),
        CompactionOwnership::Engine,
    );
    let mut driver = CompactionDriver::for_profile(&profile, &registry)
        .unwrap()
        .unwrap();
    let backend = FixtureBackend::new(["const first = 1;", "const second = 2;"]);
    let lease = BudgetLease::for_test("latest-compact");
    let mut runtime = FixtureRuntime::new([
        JsCodeModeStepOutcome::pending("latest covered output"),
        JsCodeModeStepOutcome::pending("uncovered next tail"),
    ]);
    let gated = gated_actor_write(&vault, "run-latest-compact");
    let config = executor_config(
        entity(0xB7),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 4,
        },
    );
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let first = block_on_ready(executor.run(&config)).unwrap();
    assert_eq!(
        first.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );
    assert!(
        executor.output_context.is_empty(),
        "no next request assembled yet"
    );
    driver.evaluate_now(&vault, u64::MAX).unwrap();
    let request = driver
        .request_for(
            &vault,
            &session,
            vec![CompactionWindowMessage {
                message_id: entity(0xB8),
                turn_id: turn,
                content: "latest covered output".into(),
                turn: 0,
                tokens: 1,
            }],
        )
        .unwrap();
    let product = driver.backend().compact(&request).unwrap();
    executor
        .integrate_compaction(
            &mut driver,
            WriteActor::new(entity(0xA0), EdgeActorClass::Agent),
            &request,
            product,
            &[],
        )
        .unwrap();
    let second = block_on_ready(executor.run(&config)).unwrap();
    let requests = backend.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(!console(&requests[1], 0).contains("latest covered output"));
    assert_eq!(
        executor
            .reexpand_observation(
                &second.replay_record,
                reexpand_action(&requests[1], b"latest covered output"),
            )
            .unwrap(),
        b"latest covered output"
    );
    drop(requests);
    drop(executor);
    let restart_backend = FixtureBackend::new(["const third = 3;"]);
    let mut restart_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("later")]);
    let mut restarted = EngineNativeExecutor::new(
        &vault,
        &restart_backend,
        &lease,
        &mut restart_runtime,
        &gated,
    );
    block_on_ready(restarted.run(&config)).unwrap();
    let requests = restart_backend.requests.lock().unwrap();
    assert!(!console(&requests[0], 0).contains("latest covered output"));
    assert!(console(&requests[0], 1).contains("uncovered next tail"));
}

#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn real_quickjs_guest_uses_stub_read_file_and_receives_exact_original() {
    use crate::code_sandbox::quickjs::QuickJsRuntimeFactory;
    use crate::code_sandbox::wasmtime_runtime::ComponentBudget;
    use sha2::{Digest, Sha256};

    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["console.log('first');"]);
    let lease = BudgetLease::for_test("guest-output-restore");
    let original = "recoverable exact original";
    let mut first_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending(original)]);
    let gated = gated_actor_write(&vault, "run-guest-output-restore");
    let config = executor_config(
        entity(0xC0),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );
    let mut first = EngineNativeExecutor::new(&vault, &backend, &lease, &mut first_runtime, &gated);
    block_on_ready(first.run(&config)).expect("durable first observation");
    drop(first);

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
    let mut runtime = factory.runtime().expect("real guest runtime");
    let path = super::super::store::recoverable_chunk_path(
        0,
        crate::compaction::output::OutputRef::from_bytes(original.as_bytes()),
        0,
    );
    let script = format!(
        "const raw = await sandbox.fs.read_file({}); finish(String.fromCharCode(...raw));",
        serde_json::to_string(&path).unwrap()
    );
    let second_backend = FixtureBackend::new([script]);
    let mut second =
        EngineNativeExecutor::new(&vault, &second_backend, &lease, &mut runtime, &gated)
            .with_output_decay(OutputDecayPolicy {
                overview_after_turns: 0,
                stub_after_turns: 1,
            });
    let outcome = block_on_ready(second.run(&config)).expect("guest action succeeds");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let requests = second_backend.requests.lock().unwrap();
    reexpand_action(&requests[0], original.as_bytes());
    let restored = load_utf8_output(
        &ExecutorStorage::Canonical(&vault),
        &outcome.replay_record,
        &observation_output_path(1),
    )
    .expect("stored guest observation");
    assert_eq!(restored, original);
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
