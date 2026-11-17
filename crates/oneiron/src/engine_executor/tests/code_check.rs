//! The checked-in `src/task_verb/code-mode.d.ts` is the verb table's
//! rendering of `self.memory`, and the declarations a step's program is
//! type-checked against; a type check never changes how a step ends. A
//! parked step stays parked with a check attached, even one whose checker
//! crashes: the check's result arrives as the step's type feedback only,
//! pending while the check runs on its own thread and landed under the
//! step's `check_ref` after.
use super::*;
use crate::code_run::{
    DiagnosticCollection, KeptProgramSteps, ProgramStepFeedback, TypeDiagnostics,
};
use crate::engine_executor::TypeFeedback;
use oneiron_code_check::{
    BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, Diagnostic, FeedbackCheck,
    StepThen,
};
use std::sync::Arc;

/// Substrate invariant (ARCH-0028, one table): the checked-in code-mode
/// declarations are exactly what the verb table renders. A row added, dropped
/// or retyped in `scripts/sdk/verbs/` fails here until the file is
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

    fn check(&self, _input: &CheckInput<'_>) -> std::result::Result<CheckReport, CheckFailure> {
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
            incomplete: None,
        })
    }
}

/// The parked step's type feedback as one read finds it: the check runs on
/// its own thread, so a read sees it pending or landed, never anything else.
/// Landed, the fixture's report is one diagnostic; a crashed check is the
/// typed failure, feedback only, never a refusal and never an unpark.
fn assert_parked_step_feedback(
    feedback: &ProgramStepFeedback,
    run: &crate::EntityId,
    panics: bool,
) {
    assert_eq!(feedback.step.run, run.to_hex(), "panics: {panics}");
    assert_eq!(feedback.step.program_seq, 0, "panics: {panics}");
    assert_eq!(feedback.step.invocation, 0, "panics: {panics}");
    assert_eq!(
        feedback.check_ref,
        format!("type_diagnostics:{}:0:0", run.to_hex()),
        "panics: {panics}"
    );
    assert!(feedback.preparation_note.is_none(), "panics: {panics}");
    match &feedback.type_diagnostics {
        TypeDiagnostics::Pending { check } => {
            assert_eq!(check.language, "javascript", "panics: {panics}");
            assert_eq!(check.file, "program.js", "panics: {panics}");
            assert_eq!(check.backend, "fixture", "panics: {panics}");
            assert_eq!(check.pin, "fixture", "panics: {panics}");
            assert_eq!(check.action_digest, None, "panics: {panics}");
            assert_eq!(check.elapsed_us, None, "panics: {panics}");
            assert_eq!(check.peak_memory_bytes, None, "panics: {panics}");
        }
        TypeDiagnostics::Complete {
            check,
            measures,
            diagnostics,
        } => {
            assert!(!panics, "a crashed check never completes");
            assert_eq!(check.language, "javascript", "panics: {panics}");
            assert_eq!(check.file, "program.js", "panics: {panics}");
            assert_eq!(check.backend, "fixture", "panics: {panics}");
            assert_eq!(check.pin, "fixture", "panics: {panics}");
            assert!(check.action_digest.is_some(), "panics: {panics}");
            assert!(check.elapsed_us.is_some(), "panics: {panics}");
            assert_eq!(check.peak_memory_bytes, None, "panics: {panics}");
            assert_eq!(measures.count, 1, "panics: {panics}");
            let DiagnosticCollection::Inline { diagnostics } = diagnostics else {
                panic!("one diagnostic stays inline");
            };
            assert_eq!(diagnostics.len(), 1, "panics: {panics}");
            let diagnostic = &diagnostics[0];
            assert_eq!(
                diagnostic.file.as_deref(),
                Some("program.js"),
                "panics: {panics}"
            );
            assert_eq!(diagnostic.line, 1, "panics: {panics}");
            assert_eq!(diagnostic.column, 1, "panics: {panics}");
            assert_eq!(diagnostic.category, "error", "panics: {panics}");
            assert_eq!(diagnostic.code, 2551, "panics: {panics}");
            assert_eq!(diagnostic.message, "fixture", "panics: {panics}");
            assert_eq!(diagnostic.message_bytes, 7, "panics: {panics}");
            assert_eq!(
                measures.bytes,
                serde_json::to_vec(diagnostics)
                    .expect("diagnostics encode")
                    .len() as u64,
                "panics: {panics}"
            );
        }
        TypeDiagnostics::Failed {
            check,
            failure,
            measures,
            diagnostics,
        } => {
            assert!(panics, "the fixture check fails only by crashing");
            assert_eq!(failure, CheckFailure::Crashed.code(), "panics: {panics}");
            assert_eq!(check.language, "javascript", "panics: {panics}");
            assert_eq!(check.file, "program.js", "panics: {panics}");
            assert_eq!(check.backend, "unknown", "panics: {panics}");
            assert_eq!(check.pin, "", "panics: {panics}");
            assert_eq!(check.action_digest, None, "panics: {panics}");
            assert!(check.elapsed_us.is_some(), "panics: {panics}");
            assert_eq!(check.peak_memory_bytes, None, "panics: {panics}");
            assert_eq!(measures.count, 0, "panics: {panics}");
            assert_eq!(measures.bytes, 2, "panics: {panics}");
            let DiagnosticCollection::Inline { diagnostics } = diagnostics else {
                panic!("no diagnostic leaves nothing to store");
            };
            assert!(diagnostics.is_empty(), "panics: {panics}");
        }
        TypeDiagnostics::Unavailable { reason, detail } => {
            panic!("the checker was ready: {reason} {detail:?}");
        }
    }
}

/// The check's counts as this return finds them: the check is counted once
/// its step's end is known, on the check's own thread, so this read sees it
/// counted or not yet. Either way the step counts as waiting, never failed.
fn assert_waiting_counts(check: &FeedbackCheck, panics: bool) {
    let totals = check.metrics().snapshot();
    if panics {
        assert_eq!(totals.checked, 0, "panics: {panics}");
        assert_eq!(totals.with_diagnostics, 0, "panics: {panics}");
        assert!(totals.codes.is_empty(), "panics: {panics}");
        assert_eq!(totals.diagnostic_occurrences, 0, "panics: {panics}");
        assert_eq!(totals.diagnostic_bytes, 0, "panics: {panics}");
        assert!(totals.then_with_diagnostics.is_empty(), "panics: {panics}");
        assert!(totals.then_clean.is_empty(), "panics: {panics}");
        assert!(totals.latency.is_empty(), "panics: {panics}");
        assert!(
            totals
                .unchecked
                .keys()
                .all(|code| *code == CheckFailure::Crashed.code()),
            "panics: {panics}"
        );
        assert!(
            totals.unchecked.values().sum::<u64>() <= 1,
            "panics: {panics}"
        );
    } else {
        assert!(totals.checked <= 1, "panics: {panics}");
        assert_eq!(totals.with_diagnostics, totals.checked, "panics: {panics}");
        assert_eq!(
            totals.diagnostic_occurrences, totals.checked,
            "panics: {panics}"
        );
        assert_eq!(
            totals.diagnostic_bytes,
            7 * totals.checked,
            "panics: {panics}"
        );
        assert!(totals.unchecked.is_empty(), "panics: {panics}");
        assert!(totals.then_clean.is_empty(), "panics: {panics}");
        assert!(
            totals
                .then_with_diagnostics
                .keys()
                .all(|then| *then == StepThen::Waiting.as_str()),
            "panics: {panics}"
        );
        assert_eq!(
            totals.then_with_diagnostics.values().sum::<u64>(),
            totals.checked,
            "panics: {panics}"
        );
        assert!(
            totals.codes.keys().all(|code| *code == 2551),
            "panics: {panics}"
        );
        assert_eq!(
            totals.codes.values().sum::<u64>(),
            totals.checked,
            "panics: {panics}"
        );
        assert!(
            totals.latency.keys().all(|backend| *backend == "fixture"),
            "panics: {panics}"
        );
        assert_eq!(
            totals.latency.len() as u64,
            totals.checked,
            "panics: {panics}"
        );
    }
}

/// The step of `executor_preserves_durable_wait_when_runtime_errors_after_wait`
/// parks its run on the wait its program recorded before failing. With a type
/// check attached, even one whose checker crashes, the step still parks the
/// run: attaching the check never unparks the durable wait, and the check's
/// result arrives as the step's type feedback only, pending while the check
/// runs on its own thread and landed under the step's `check_ref` after.
#[test]
fn a_type_check_leaves_a_parked_step_parked() {
    for panics in [false, true] {
        let (_dir, vault) = open_test_vault();
        let vault = Arc::new(vault);
        let backend = FixtureBackend::new(["await ask('continue?');"]);
        let lease = BudgetLease::for_test("executor-lease");
        let mut runtime =
            ErrorAfterCallsRuntime::new(vec![SelfCall::Ask(SelfAskCall::new("continue?"))]);
        let gated_write = gated_actor_write(&vault, "run-wait-then-error");
        let config = executor_config(entity(0x8D), EngineExecutorLimits { soft_steps: 1 });
        let checker: Arc<dyn CodeCheck> = Arc::new(FixtureCheck { panics });
        let check = Arc::new(FeedbackCheck::new(checker));
        let feedback = TypeFeedback::loading("fixture", Arc::clone(&vault));
        feedback.loaded(Ok(Arc::clone(&check)));
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write)
                .with_code_check(&feedback);
        let outcome = block_on_ready(executor.run(&config)).expect("durable wait persists");
        assert!(
            matches!(outcome.status, EngineExecutorStatus::Waiting(_)),
            "panics: {panics}"
        );
        assert_eq!(outcome.steps_run, 1, "panics: {panics}");
        assert_eq!(outcome.program_steps.len(), 1, "panics: {panics}");
        assert_parked_step_feedback(&outcome.program_steps[0], &config.run_id, panics);
        let key = (config.run_id, 0, 0);
        let row = vault
            .type_diagnostics_row(key)
            .expect("step feedback row reads")
            .expect("the parked step kept its feedback");
        assert_parked_step_feedback(&row.feedback(key), &config.run_id, panics);
        let KeptProgramSteps::Kept(steps) = vault.kept_program_steps(config.run_id) else {
            panic!("the parked step kept its feedback");
        };
        assert_eq!(steps.len(), 1, "panics: {panics}");
        assert_parked_step_feedback(&steps[0], &config.run_id, panics);
        assert_waiting_counts(&check, panics);
    }
}
