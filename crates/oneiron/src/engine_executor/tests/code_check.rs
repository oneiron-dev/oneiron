//! The checked-in `src/task_verb/code-mode.d.ts`, which a shadow check's
//! oracle fixtures read, is the verb table's rendering of `self.memory`; and a
//! shadow check never changes how a step ends.
use super::*;
use oneiron_code_check::{
    BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, Diagnostic, ShadowCheck,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Substrate invariant (ARCH-0028, one table): the checked-in code-mode
/// declarations are exactly what the verb table renders. A row added, dropped
/// or retyped in `scripts/sdk/agent-verbs.json` fails here until the file is
/// regenerated with `ONEIRON_UPDATE_TEST_FIXTURES=1`.
#[test]
fn code_mode_declarations_file_is_the_verb_table() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/task_verb/code-mode.d.ts");
    let rendered = crate::task_verb::sdk::code_mode_declarations();
    if std::env::var_os("ONEIRON_UPDATE_TEST_FIXTURES").is_some() {
        std::fs::write(path, rendered).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        rendered,
        "regenerate with ONEIRON_UPDATE_TEST_FIXTURES=1"
    );
}

/// A checker that finds one diagnostic in every program, or panics.
struct FixtureCheck {
    panics: bool,
}

impl CodeCheck for FixtureCheck {
    fn backend(&self) -> BackendId {
        BackendId {
            name: "fixture",
            pin: "fixture".to_owned(),
        }
    }

    fn check(&self, _input: &CheckInput<'_>) -> Result<CheckReport, CheckFailure> {
        assert!(!self.panics, "the fixture checker crashed");
        Ok(CheckReport {
            backend: self.backend(),
            diagnostics: vec![Diagnostic {
                file: Some("program.js".to_owned()),
                line: 1,
                column: 1,
                category: "error".to_owned(),
                code: 2551,
                message: "fixture".to_owned(),
            }],
            peak_memory_bytes: None,
        })
    }
}

/// The step of `executor_preserves_durable_wait_when_runtime_errors_after_wait`
/// parks its run on the wait its program recorded before failing. With a
/// shadow check attached, even one that panics, the step still parks the run,
/// and the check counts it as waiting, not failed.
#[test]
fn a_shadow_check_leaves_a_parked_step_parked() {
    for panics in [false, true] {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new(["await ask('continue?');"]);
        let lease = BudgetLease::for_test("executor-lease");
        let mut runtime =
            ErrorAfterCallsRuntime::new(vec![SelfCall::Ask(SelfAskCall::new("continue?"))]);
        let gated_write = gated_actor_write(&vault, "run-wait-then-error");
        let config = executor_config(
            entity(0x8D),
            EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 1,
            },
        );
        let shadow = ShadowCheck::new(Arc::new(FixtureCheck { panics }));
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write)
                .with_code_check(&shadow);
        let outcome = block_on_ready(executor.run(&config)).expect("durable wait persists");
        assert!(
            matches!(outcome.status, EngineExecutorStatus::Waiting(_)),
            "panics: {panics}"
        );
        assert_eq!(outcome.steps_run, 1);
        let totals = shadow.metrics().snapshot();
        if panics {
            assert_eq!(totals.unchecked, BTreeMap::from([("code_check_crashed", 1)]));
        } else {
            assert_eq!(
                totals.then_with_diagnostics,
                BTreeMap::from([("waiting", 1)])
            );
        }
    }
}
