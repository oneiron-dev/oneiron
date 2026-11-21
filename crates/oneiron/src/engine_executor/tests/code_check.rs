//! The checked-in `src/task_verb/code-mode.d.ts` is the verb table's
//! rendering of `self.memory`, and the declarations a step's program is
//! type-checked against; a type check never changes how a step ends. A
//! parked step stays parked with a check attached, even one whose checker
//! crashes: the check's result arrives as the step's type feedback only,
//! pending while the check runs on its own thread and landed under the
//! step's `check_ref` after.
use super::*;
use crate::code_run::{
    DiagnosticCollection, KeptProgramSteps, ProgramStepFeedback, TYPE_CHECK_NOT_LOADED,
    TYPE_CHECK_OFF, TypeDiagnostics,
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

/// The step feedback row at `key` as it stands.
fn kept_step_feedback(vault: &Vault, key: crate::code_run::StepKey) -> ProgramStepFeedback {
    vault
        .type_diagnostics_row(key)
        .expect("step feedback row reads")
        .expect("the step kept its feedback")
        .feedback(key)
}

/// A program that fails before its first host call commits no step, so the
/// re-entry's program runs at the same step and keeps its feedback under
/// the same row. The failed program's check, landed before the re-entry,
/// never holds off the feedback of the program that ran the step: the row
/// shows the re-entry's check, pending while it runs, and then its result.
#[test]
fn a_failed_programs_landed_check_yields_to_the_next_program_at_its_step() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let lease = BudgetLease::for_test("executor-lease");
    let gated_write = gated_actor_write(&vault, "run-uncommitted-then-rerun");
    let config = executor_config(entity(0x8E), EngineExecutorLimits { soft_steps: 1 });
    let key = (config.run_id, 0, 0);

    // The first program fails before its first host call; its check has
    // landed already (no checker serves it).
    let off = TypeFeedback::off();
    let failed_backend = FixtureBackend::new(["throw new Error('first');"]);
    let mut failed_runtime = ErrorAfterCallsRuntime::new(Vec::new());
    let mut failed = EngineNativeExecutor::new(
        &vault,
        &failed_backend,
        &lease,
        &mut failed_runtime,
        &gated_write,
    )
    .with_code_check(&off);
    block_on_ready(failed.run(&config)).expect_err("the program fails before any host call");
    assert!(matches!(
        kept_step_feedback(&vault, key).type_diagnostics,
        TypeDiagnostics::Unavailable { ref reason, .. } if reason == TYPE_CHECK_OFF
    ));

    // The re-entry's program runs the same step while its check waits for
    // its checker's load.
    let loading = TypeFeedback::loading("fixture", Arc::clone(&vault));
    let rerun_backend = FixtureBackend::new(["const second = true;"]);
    let mut rerun_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("ran")]);
    let mut rerun = EngineNativeExecutor::new(
        &vault,
        &rerun_backend,
        &lease,
        &mut rerun_runtime,
        &gated_write,
    )
    .with_code_check(&loading);
    let outcome = block_on_ready(rerun.run(&config)).expect("the re-entry runs the step");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(rerun_runtime.seen.len(), 1);
    assert_eq!(
        rerun_runtime.seen[0].seq, 0,
        "the re-entry runs the same step"
    );
    match &kept_step_feedback(&vault, key).type_diagnostics {
        TypeDiagnostics::Pending { check } => assert_eq!(check.backend, "fixture"),
        other => panic!("the step's row holds the failed program's check: {other:?}"),
    }
    let KeptProgramSteps::Kept(steps) = vault.kept_program_steps(config.run_id) else {
        panic!("the run kept its feedback");
    };
    assert_eq!(steps.len(), 1);
    assert!(
        matches!(steps[0].type_diagnostics, TypeDiagnostics::Pending { .. }),
        "the run's step shows the re-entry's check: {:?}",
        steps[0].type_diagnostics
    );

    // The re-entry's check lands and takes its own pending row's place.
    loading.loaded(Err(CheckFailure::Unavailable));
    let mut landed = None;
    for _ in 0..500 {
        let feedback = kept_step_feedback(&vault, key);
        if !matches!(feedback.type_diagnostics, TypeDiagnostics::Pending { .. }) {
            landed = Some(feedback);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let landed = landed.expect("the re-entry's check lands within 5 s");
    assert!(
        matches!(
            &landed.type_diagnostics,
            TypeDiagnostics::Unavailable { reason, detail }
                if reason == TYPE_CHECK_NOT_LOADED
                    && detail.as_deref() == Some(CheckFailure::Unavailable.code())
        ),
        "{:?}",
        landed.type_diagnostics
    );
}

/// The check of `program` at step `key` of a run whose rows are `vault`'s
/// own.
fn canonical_check_job(
    vault: &Vault,
    key: crate::code_run::StepKey,
    program: &str,
) -> crate::engine_executor::code_check::CheckJob {
    crate::engine_executor::code_check::CheckJob {
        key,
        program: program.to_owned(),
        language: oneiron_code_check::ProgramLanguage::JavaScript,
        note: None,
        actor: None,
        source: None,
        declarations: Vec::new(),
        route: crate::code_run::ExecutorStorage::Canonical(vault).feedback_route(),
    }
}

/// The write a check makes when it lands after its step: the check of a
/// program that failed before its first host call, landing after the
/// re-entry's program kept its own feedback at the same step, never takes
/// that feedback's place.
#[test]
fn an_earlier_programs_check_landing_late_keeps_the_later_programs_row() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let key = (entity(0x8F), 0, 0);
    let job = |program: &str| canonical_check_job(&vault, key, program);
    // The failed program's check, then the re-entry's: each lands as it
    // starts, the first with the check mode off, the second with its
    // checker's load failed.
    let off = TypeFeedback::off();
    let earlier = off.start(job("throw new Error('first');"));
    let not_loaded = TypeFeedback::loading("fixture", Arc::clone(&vault));
    not_loaded.loaded(Err(CheckFailure::Unavailable));
    let later = not_loaded.start(job("const second = true;"));

    // The re-entry's step keeps its feedback; the failed program's check
    // writes its landed result after it.
    let row = later.cell().claim_row().expect("the later check's row");
    vault
        .put_type_diagnostics(key, &row)
        .expect("the later program's feedback is kept");
    let late = earlier.cell().claim_row().expect("the earlier check's row");
    vault
        .put_type_diagnostics(key, &late)
        .expect("a refused late landing is no error");

    let feedback = kept_step_feedback(&vault, key);
    assert!(
        matches!(
            &feedback.type_diagnostics,
            TypeDiagnostics::Unavailable { reason, .. } if reason == TYPE_CHECK_NOT_LOADED
        ),
        "the step's row holds the failed program's check: {:?}",
        feedback.type_diagnostics
    );
}

/// Check ids order the checks of one checker incarnation only. A row a
/// dead incarnation wrote names a check id minted ahead of this
/// incarnation's (its clock ran ahead, or ids restarted lower with the
/// process): it never holds off the check of the program that runs the
/// step now.
#[test]
fn a_dead_incarnations_row_yields_to_the_current_check_at_its_step() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let key = (entity(0x91), 0, 0);
    let job = |program: &str| canonical_check_job(&vault, key, program);
    // The current check starts first; the dead incarnation's row names a
    // check minted after it.
    let not_loaded = TypeFeedback::loading("fixture", Arc::clone(&vault));
    not_loaded.loaded(Err(CheckFailure::Unavailable));
    let current = not_loaded.start(job("const second = true;"));
    let off = TypeFeedback::off();
    let ahead = off.start(job("throw new Error('first');"));
    let mut dead = ahead
        .cell()
        .claim_row()
        .expect("the dead incarnation's row");
    dead.incarnation = EntityId::now();
    vault
        .put_type_diagnostics(key, &dead)
        .expect("the dead incarnation's row is kept");

    let row = current.cell().claim_row().expect("the current check's row");
    vault
        .put_type_diagnostics(key, &row)
        .expect("the current check's row is kept");
    let feedback = kept_step_feedback(&vault, key);
    assert!(
        matches!(
            &feedback.type_diagnostics,
            TypeDiagnostics::Unavailable { reason, .. } if reason == TYPE_CHECK_NOT_LOADED
        ),
        "the dead incarnation's row holds the step: {:?}",
        feedback.type_diagnostics
    );
}

/// Each check of a step keeps a collection past one reply at its own body
/// path. A row that takes another check's place releases the body the
/// replaced row named, and a late row that does not take the held row's
/// place releases its own, each in the same write: no body of the step
/// stays held that no row names, for an erase of the run's actor to miss.
#[test]
fn a_step_body_no_feedback_row_names_is_released_in_the_write() {
    use crate::code_run::{
        DiagnosticMeasures, ProgramStepIdentity, StoredStepFeedback, TypeCheckFacts,
    };
    let (_dir, vault) = open_test_vault();
    let run = entity(0x92);
    let key = (run, 0, 0);
    let earliest = EntityId::now();
    let earlier = EntityId::now();
    let later = EntityId::now();
    let check = TypeCheckFacts {
        language: "javascript".to_owned(),
        file: "program.js".to_owned(),
        backend: "fixture".to_owned(),
        pin: "fixture-pin".to_owned(),
        action_digest: None,
        elapsed_us: None,
        peak_memory_bytes: None,
    };
    let step = ProgramStepIdentity::of(run, 0, 0);
    // A landed row of check `id` whose collection the run keeps in that
    // check's own body.
    let landed_with_body = |id: EntityId, text: &str| {
        let mut sink = vault.code_run_output_sink().expect("a body sink");
        crate::engine_executor::store::write_json(&mut sink, &[text])
            .expect("the collection is written");
        let body = vault
            .publish_code_run_output(
                crate::engine_executor::store::type_diagnostics_output_path(0, 0, id),
                sink,
                true,
                Some(run),
            )
            .expect("the run keeps the collection's body");
        let feedback = ProgramStepFeedback::new(
            step.clone(),
            None,
            TypeDiagnostics::Complete {
                check: check.clone(),
                measures: DiagnosticMeasures {
                    count: 1,
                    bytes: body.raw_len,
                },
                diagnostics: DiagnosticCollection::Stored {
                    handle: body.handle.clone(),
                    occurrence: String::new(),
                    byte_len: body.raw_len,
                },
            },
        );
        StoredStepFeedback::of(None, id, &feedback, Some(body))
    };
    let bodies = || {
        vault
            .owned_bodies(&run)
            .expect("the run's bodies read")
            .len()
    };

    // The failed program's check landed with its collection in the body.
    vault
        .put_type_diagnostics(key, &landed_with_body(earlier, "the failed program's"))
        .expect("the landed row is kept");
    assert_eq!(bodies(), 1);

    // The re-entry's check, pending, takes its place, and the body goes.
    let pending = ProgramStepFeedback::new(
        step.clone(),
        None,
        TypeDiagnostics::Pending {
            check: check.clone(),
        },
    );
    vault
        .put_type_diagnostics(key, &StoredStepFeedback::of(None, later, &pending, None))
        .expect("the re-entry's row is kept");
    assert!(matches!(
        kept_step_feedback(&vault, key).type_diagnostics,
        TypeDiagnostics::Pending { .. }
    ));
    assert_eq!(bodies(), 0, "the replaced row's body is released with it");

    // An earlier check landing late keeps its collection in the body, but
    // its row never takes the re-entry's place, so its body goes too.
    vault
        .put_type_diagnostics(key, &landed_with_body(earliest, "an earlier program's"))
        .expect("a refused late landing is no error");
    assert!(matches!(
        kept_step_feedback(&vault, key).type_diagnostics,
        TypeDiagnostics::Pending { .. }
    ));
    assert_eq!(
        bodies(),
        0,
        "the refused row's body is released in its write"
    );
}

/// A checker that finds one diagnostic in every program, its message the
/// program's text padded past one reply, so its step keeps the collection
/// in a body of the run: two checks of one program report the same bytes,
/// checks of two programs other bytes.
struct PastOneReplyCheck;

impl CodeCheck for PastOneReplyCheck {
    fn backend(&self) -> BackendId {
        BackendId {
            name: "fixture",
            pin: "fixture".to_owned(),
        }
    }

    fn check(&self, input: &CheckInput<'_>) -> std::result::Result<CheckReport, CheckFailure> {
        Ok(CheckReport {
            backend: self.backend(),
            diagnostics: vec![Diagnostic {
                file: Some("program.js".to_owned()),
                line: 1,
                column: 1,
                category: "error".to_owned(),
                code: 2551,
                message: format!(
                    "{}{}",
                    input.program,
                    "x".repeat(crate::engine_executor::store::RESULT_REPLY_INLINE_BYTES)
                ),
            }],
            peak_memory_bytes: None,
            incomplete: None,
        })
    }
}

/// The checks of `programs`, started in order at step `key` of `vault`'s
/// run for `actor`, each landed with [`PastOneReplyCheck`]'s report. Their
/// service's own vault is `service_vault`, another, so no check writes a
/// row or keeps a body by itself: each check's collection waits inline for
/// its step to place, as a check that lands before its step ends does. A
/// check's pending row, claimed before it lands, comes back beside it.
fn past_one_reply_checks(
    service_vault: Arc<Vault>,
    vault: &Vault,
    key: crate::code_run::StepKey,
    actor: EntityId,
    programs: &[(&str, bool)],
) -> Vec<(
    crate::engine_executor::code_check::StepCheck,
    Option<crate::code_run::StoredStepFeedback>,
)> {
    let service = TypeFeedback::loading("fixture", service_vault);
    let checks: Vec<_> = programs
        .iter()
        .map(|(program, pending)| {
            let check = service.start(crate::engine_executor::code_check::CheckJob {
                actor: Some(actor),
                ..canonical_check_job(vault, key, program)
            });
            let row = pending.then(|| check.cell().claim_row().expect("the pending row"));
            (check, row)
        })
        .collect();
    let checker: Arc<dyn CodeCheck> = Arc::new(PastOneReplyCheck);
    service.loaded(Ok(Arc::new(FeedbackCheck::new(checker))));
    for (check, _) in &checks {
        let mut waited = 0;
        while matches!(
            check.cell().feedback().type_diagnostics,
            TypeDiagnostics::Pending { .. }
        ) {
            assert!(waited < 500, "the check lands within 5 s");
            waited += 1;
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    checks
}

/// The bodies `run` holds, as the descriptors its erase releases.
fn run_bodies(vault: &Vault, run: EntityId) -> Vec<EntityId> {
    vault
        .owned_bodies(&run)
        .expect("the run's bodies read")
        .into_iter()
        .map(|body| body.occurrence)
        .collect()
}

/// The re-entry's check keeps its pending row at a step whose failed
/// program's check is still running; both land with the same report past
/// one reply and keep it in a body before either row is written. The
/// failed program's row, refused, releases its own body only: the
/// re-entry's landed row names a body the run still holds.
#[test]
fn a_refused_late_checks_body_leaves_the_later_checks_same_bytes_held() {
    let (_dir, vault) = open_test_vault();
    let (_service_dir, service_vault) = open_test_vault();
    let run = entity(0x93);
    let key = (run, 0, 0);
    let program = "const same = 'report';";
    let mut checks = past_one_reply_checks(
        Arc::new(service_vault),
        &vault,
        key,
        entity(0x94),
        &[(program, false), (program, true)],
    );
    let (rerun, rerun_pending) = checks.pop().expect("the re-entry's check");
    let (failed, _) = checks.pop().expect("the failed program's check");
    vault
        .put_type_diagnostics(key, &rerun_pending.expect("the re-entry's pending row"))
        .expect("the re-entry's pending row is kept");

    let storage = crate::code_run::ExecutorStorage::Canonical(&vault);
    failed.cell().finalize(&storage);
    rerun.cell().finalize(&storage);
    let late = failed.cell().claim_row().expect("the failed program's row");
    vault
        .put_type_diagnostics(key, &late)
        .expect("a refused late landing is no error");
    let landed = rerun.cell().claim_row().expect("the re-entry's landed row");
    vault
        .put_type_diagnostics(key, &landed)
        .expect("the re-entry's landed row is kept");

    let row = vault
        .type_diagnostics_row(key)
        .expect("step feedback row reads")
        .expect("the step kept its feedback");
    let body = row.body().expect("the re-entry's row names its body");
    let occurrence = crate::code_run::ResultOccurrence::of(Some(run), &body)
        .expect("the body's occurrence")
        .id();
    assert_eq!(
        run_bodies(&vault, run),
        vec![occurrence],
        "the run holds the body the re-entry's row names, and no other"
    );
}

/// A failed program's check keeps its report past one reply in a body and
/// its row; the re-entry's check at the same step lands another report
/// past one reply. The re-entry's row keeps its own report in a body, takes
/// the failed program's place and releases that row's body; the erase of
/// the run's actor then releases the re-entry's: no body of the step stays
/// held.
#[test]
fn a_later_checks_other_report_is_kept_and_erased_by_its_own_row() {
    let (_dir, vault) = open_test_vault();
    let (_service_dir, service_vault) = open_test_vault();
    let run = entity(0x95);
    let actor = entity(0x96);
    let key = (run, 0, 0);
    let mut checks = past_one_reply_checks(
        Arc::new(service_vault),
        &vault,
        key,
        actor,
        &[
            ("throw new Error('first');", false),
            ("const second = true;", false),
        ],
    );
    let (rerun, _) = checks.pop().expect("the re-entry's check");
    let (failed, _) = checks.pop().expect("the failed program's check");
    let storage = crate::code_run::ExecutorStorage::Canonical(&vault);

    failed.cell().finalize(&storage);
    vault
        .put_type_diagnostics(key, &failed.cell().claim_row().expect("the failed row"))
        .expect("the failed program's row is kept");
    assert_eq!(run_bodies(&vault, run).len(), 1);

    rerun.cell().finalize(&storage);
    vault
        .put_type_diagnostics(key, &rerun.cell().claim_row().expect("the re-entry's row"))
        .expect("the re-entry's row is kept");
    let row = vault
        .type_diagnostics_row(key)
        .expect("step feedback row reads")
        .expect("the step kept its feedback");
    let body = row
        .body()
        .expect("the re-entry's report is kept in a body of its own");
    let occurrence = crate::code_run::ResultOccurrence::of(Some(run), &body)
        .expect("the body's occurrence")
        .id();
    assert_eq!(
        run_bodies(&vault, run),
        vec![occurrence],
        "the replaced row's body goes; the re-entry's stays"
    );

    let mut wtxn = vault.store.env.write_txn().expect("a write");
    crate::code_run::erase_type_diagnostics_actor_in_txn(&vault, &mut wtxn, &actor)
        .expect("the actor's step feedback goes");
    wtxn.commit().expect("the erase commits");
    assert!(
        run_bodies(&vault, run).is_empty(),
        "the erase releases the body the re-entry's row named"
    );
}
