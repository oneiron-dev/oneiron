//! Model-facing output decay and successful native compaction on the real REPL path.
use super::*;
use crate::compaction::output::OutputAffordance;

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
