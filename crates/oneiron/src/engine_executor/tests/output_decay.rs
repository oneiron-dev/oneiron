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

fn reexpand_action(request: &LlmRequest) -> OutputAffordance {
    let console = console(request, 0);
    let json = console
        .split("<console>\n")
        .nth(1)
        .expect("console frame")
        .split("\n</console>")
        .next()
        .expect("console body");
    let affordances: [OutputAffordance; 2] = serde_json::from_str(json).expect("typed actions");
    affordances[0].clone()
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
    let action = reexpand_action(&requests[4]);
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
    let action = reexpand_action(next);
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
                reexpand_action(&restarted_requests[0]),
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
