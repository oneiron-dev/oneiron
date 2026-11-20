//! The `library_run` door's nine tests
//! (FIX [BROWSER-LIBRARY-SESSION-DOORS-HELD-BY-NO-TEST]): refusals before a run acts, what it
//! counts after, and what a missed postcondition hands back. The session is real; the browser
//! and the store are fakes. The store proves what the door forwards and returns, not the real
//! vault store's filter, order or ownership rules. The peer proves the door's reads, not a real
//! browser's answers.
use super::session_fixture::SessionFixture;
use super::workflow_store::{PAGE_URL, StoreCall, card, filed_workflow, trace};
use oneiron_browser::{
    AskUpReason, BatchStep, BatchStopCause, BrowserDriver, BrowserError, CheckReceipt, ExpectInput,
    ExpectOutput, FieldSpec, FieldWrite, FieldWriteError, FieldWriter, FieldWritten, FiledWorkflow,
    LibraryRunInput, LibraryRunMode, Observation, RunOutcome, SecretArg, StrictDenial,
    SubgoalStatus,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// The workflow ref the store files for these tests.
const WORKFLOW: &str = "wf1";

/// A check the fixture page misses: no row is named Never.
fn never() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Never".to_owned()),
        ..Default::default()
    }
}

/// A run's input for [`WORKFLOW`] in `mode`, with no arguments.
fn run_input(mode: LibraryRunMode) -> LibraryRunInput {
    LibraryRunInput {
        workflow: WORKFLOW.to_owned(),
        args: BTreeMap::new(),
        base: None,
        mode: Some(mode),
        secret_args: BTreeMap::new(),
    }
}

/// What a missed check's read found: no row, no cut tree, no rebindings.
fn unmet_observed() -> ExpectOutput {
    ExpectOutput {
        met: false,
        row: None,
        partial: None,
        rebindings: Vec::new(),
    }
}

/// An open of the canned program's page.
fn open() -> BatchStep {
    BatchStep::Open {
        url: PAGE_URL.to_owned(),
    }
}

/// The URL of the page an observation read.
fn url_of(observation: &Option<Observation>) -> &str {
    observation.as_ref().expect("the page is read").url.as_str()
}

/// A writer that counts its calls and answers none; a strict run must never ask it.
struct CountingWriter {
    calls: Arc<AtomicUsize>,
}

impl FieldWriter for CountingWriter {
    fn write(&self, _ask: &FieldWrite) -> Result<FieldWritten, FieldWriteError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(FieldWriteError::Unavailable(
            "fixture writer must not run".to_owned(),
        ))
    }
}

/// Asserts the door navigated `navigates` times to the canned page, sent no input, and had every
/// request answered.
fn assert_drove(fixture: &SessionFixture, mark: usize, navigates: usize) {
    let requests = fixture.peer.requests_since(mark);
    let count = requests
        .iter()
        .filter(|request| request.method == "Page.navigate")
        .count();
    assert_eq!(
        count, navigates,
        "the run navigates {navigates} times, not {count}"
    );
    for request in requests
        .iter()
        .filter(|request| request.method == "Page.navigate")
    {
        let params = &request.params;
        assert_eq!(
            params.get("url").and_then(Value::as_str),
            Some(PAGE_URL),
            "every navigate opens the canned page: {params}"
        );
    }
    assert!(
        requests
            .iter()
            .all(|request| !request.method.starts_with("Input.")),
        "a run that types nothing sends no input"
    );
    let unanswered = fixture.peer.unanswered();
    assert!(
        unanswered.is_empty(),
        "every request is answered: {unanswered:?}"
    );
}

/// Files `filed` under [`WORKFLOW`] in the fixture store.
fn file_program(fixture: &SessionFixture, filed: FiledWorkflow) {
    let mut store = fixture.store.lock().expect("store state locks");
    store
        .live
        .insert(WORKFLOW.to_owned(), (card(WORKFLOW), filed));
}

#[test]
fn a_retired_program_is_refused_at_a_run_as_retired_not_as_missing() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    {
        let mut store = fixture.store.lock().expect("store state locks");
        store.retired.push(trace(card(WORKFLOW), 9, None));
    }
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_run(run_input(LibraryRunMode::Assisted));
    let error = result.expect_err("a retired program is refused");
    assert_eq!(
        error,
        BrowserError::WorkflowRetired(WORKFLOW.to_owned()),
        "a retired program answers retired, not missing"
    );
    assert_eq!(error.code(), "workflow_retired", "the retired code");
    assert_eq!(
        error.to_string(),
        "the library's workflow wf1 was retired",
        "the retired words"
    );
    fixture.assert_methods(mark, &[]);
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [
            StoreCall::Program(WORKFLOW.to_owned()),
            StoreCall::IsRetired(WORKFLOW.to_owned()),
        ],
        "a retired lookup reads the live map, then the retires"
    );
    assert!(
        store.recorded_runs.is_empty(),
        "a refused run counts nothing"
    );
}

#[test]
fn a_strict_fill_that_needs_generation_is_denied_without_asking_a_writer() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let mut filed = filed_workflow();
    filed.program.steps = vec![
        open(),
        BatchStep::Fill {
            target: "fixture-field".to_owned(),
            field: FieldSpec {
                generate: true,
                instruction: Some("write a label".to_owned()),
                ..Default::default()
            },
        },
    ];
    file_program(&fixture, filed);
    let writes = Arc::new(AtomicUsize::new(0));
    fixture.session.set_field_writer(Box::new(CountingWriter {
        calls: Arc::clone(&writes),
    }));
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_run(run_input(LibraryRunMode::Strict));
    let output = fixture.expect_ok(result, "a strict fill is denied");
    let denied = BatchStopCause::DeciderAskedUp {
        reason: AskUpReason::Strict {
            denied: StrictDenial::FieldGenerationRequiresModel,
        },
    };
    assert_eq!(output.workflow, WORKFLOW);
    assert_eq!(output.mode, LibraryRunMode::Strict);
    assert_eq!(output.status, SubgoalStatus::NeedsAgent);
    assert!(output.model_free, "a denial at zero tokens is model-free");
    assert_eq!(output.model_free_unproven, None);
    assert!(output.unmet.is_empty(), "no check ran, so none missed");
    assert_eq!(output.batch.completed, 1);
    assert_eq!(output.batch.failed_step, Some(1));
    assert_eq!(output.batch.error, Some("routine_ask_up".to_owned()));
    assert_eq!(output.batch.stop_cause, Some(denied.clone()));
    assert_eq!(output.batch.receipts.len(), 1);
    assert_eq!(
        output.batch.decisions,
        [json!({"strict_denied": {
            "denied": "field_generation_requires_model",
            "question": "Does the written text belong in the field, as its instruction asks?",
            "tokens": 0,
        }})],
        "the denial at zero tokens"
    );
    let failed = output
        .batch
        .failed_receipt
        .as_ref()
        .expect("the denied fill leaves its receipt");
    assert_eq!(failed.step, Some(1));
    assert_eq!(failed.stop_cause, denied);
    assert!(failed.missed.is_empty(), "no check missed");
    assert_eq!(url_of(&failed.observation), PAGE_URL);
    assert_eq!(failed.error, Some("routine_ask_up".to_owned()));
    assert_eq!(url_of(&output.batch.observation), PAGE_URL);
    assert_eq!(
        writes.load(Ordering::SeqCst),
        0,
        "a strict run asks no writer"
    );
    assert_drove(&fixture, mark, 1);
    assert_eq!(
        fixture.session.history_mark(),
        Some(2),
        "the open, then the denied fill"
    );
    let outcome = RunOutcome {
        mode: LibraryRunMode::Strict,
        done: false,
        stop_cause: Some(denied),
    };
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [
            StoreCall::Program(WORKFLOW.to_owned()),
            StoreCall::RecordRun(WORKFLOW.to_owned(), outcome.clone()),
        ],
        "one lookup, one count"
    );
    assert_eq!(
        store.recorded_runs,
        [(WORKFLOW.to_owned(), outcome)],
        "the denial counts once"
    );
}

#[test]
fn a_successful_run_counts_its_final_outcome_once_not_once_per_effect() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    file_program(&fixture, filed_workflow());
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_run(run_input(LibraryRunMode::Assisted));
    let output = fixture.expect_ok(result, "a successful run answers");
    assert_eq!(output.workflow, WORKFLOW);
    assert_eq!(output.status, SubgoalStatus::Done);
    assert_eq!(output.mode, LibraryRunMode::Assisted);
    assert!(output.model_free, "no decision ran, so none took a model");
    assert_eq!(output.model_free_unproven, None);
    assert!(output.unmet.is_empty(), "every check met");
    assert_eq!(output.batch.completed, 1);
    assert_eq!(output.batch.failed_step, None);
    assert_eq!(output.batch.error, None);
    assert_eq!(output.batch.stop_cause, None);
    assert!(output.batch.failed_receipt.is_none(), "no failed receipt");
    assert_eq!(output.batch.receipts.len(), 1);
    assert!(output.batch.decisions.is_empty(), "no decision ran");
    assert_eq!(url_of(&output.batch.observation), PAGE_URL);
    let receipt = output
        .batch
        .receipts
        .first()
        .expect("the open leaves its receipt");
    assert_eq!(receipt.verb, "open", "the open receipted");
    assert_eq!(receipt.seq, 1, "the first entry");
    assert_drove(&fixture, mark, 1);
    assert_eq!(
        fixture.session.history_mark(),
        Some(1),
        "only the open noted"
    );
    let outcome = RunOutcome {
        mode: LibraryRunMode::Assisted,
        done: true,
        stop_cause: None,
    };
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [
            StoreCall::Program(WORKFLOW.to_owned()),
            StoreCall::RecordRun(WORKFLOW.to_owned(), outcome.clone()),
        ],
        "one lookup, one count"
    );
    assert_eq!(
        store.recorded_runs,
        [(WORKFLOW.to_owned(), outcome)],
        "the success counts once"
    );
}

#[test]
fn a_typed_handle_not_held_by_the_run_is_refused_before_lookup_or_effect() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let mark = fixture.peer.mark();
    let input = LibraryRunInput {
        secret_args: BTreeMap::from([("pw".to_owned(), SecretArg::Handle("sc1".to_owned()))]),
        ..run_input(LibraryRunMode::Assisted)
    };
    let result = fixture.session.library_run(input);
    let error = result.expect_err("an unheld handle is refused");
    assert_eq!(
        error,
        BrowserError::Input(
            "the secret argument pw's handle names no secret this run holds".to_owned(),
        ),
        "an unheld handle is refused"
    );
    assert_eq!(error.code(), "browser_input_invalid", "the input code");
    fixture.assert_methods(mark, &[]);
    let store = fixture.store.lock().expect("store state locks");
    assert!(store.calls.is_empty(), "no lookup before the refusal");
    assert!(
        store.recorded_runs.is_empty(),
        "a refused run counts nothing"
    );
}

#[test]
fn a_proven_postcondition_miss_counts_not_done_and_returns_the_check_evidence() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let mut filed = filed_workflow();
    filed.program.postcondition = vec![never()];
    file_program(&fixture, filed);
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_run(run_input(LibraryRunMode::Assisted));
    let output = fixture.expect_ok(result, "a missed postcondition answers");
    assert_eq!(output.status, SubgoalStatus::NeedsAgent);
    assert_eq!(output.mode, LibraryRunMode::Assisted);
    assert!(output.model_free, "no decision ran, so none took a model");
    assert_eq!(output.model_free_unproven, None);
    assert_eq!(output.unmet, [0_usize]);
    assert_eq!(output.batch.completed, 1);
    assert_eq!(output.batch.failed_step, None);
    assert_eq!(output.batch.error, Some("postcondition_unmet".to_owned()));
    assert_eq!(
        output.batch.stop_cause,
        Some(BatchStopCause::PostconditionUnmet)
    );
    assert_eq!(output.batch.receipts.len(), 1);
    assert!(output.batch.decisions.is_empty(), "no decision ran");
    let failed = output
        .batch
        .failed_receipt
        .as_ref()
        .expect("the miss leaves its receipt");
    assert_eq!(failed.step, None);
    assert_eq!(failed.stop_cause, BatchStopCause::PostconditionUnmet);
    assert_eq!(
        failed.missed,
        [CheckReceipt {
            expect: never(),
            observed: unmet_observed()
        }],
        "the check, with what its read found"
    );
    assert_eq!(url_of(&failed.observation), PAGE_URL);
    assert_eq!(failed.error, Some("postcondition_unmet".to_owned()));
    assert_eq!(url_of(&output.batch.observation), PAGE_URL);
    assert_drove(&fixture, mark, 1);
    assert_eq!(
        fixture.session.history_mark(),
        Some(2),
        "the open, then the miss"
    );
    let outcome = RunOutcome {
        mode: LibraryRunMode::Assisted,
        done: false,
        stop_cause: Some(BatchStopCause::PostconditionUnmet),
    };
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [
            StoreCall::Program(WORKFLOW.to_owned()),
            StoreCall::RecordRun(WORKFLOW.to_owned(), outcome.clone()),
        ],
        "one lookup, one count"
    );
    assert_eq!(
        store.recorded_runs,
        [(WORKFLOW.to_owned(), outcome)],
        "the miss counts once, not done"
    );
}

#[test]
fn last_step_no_progress_is_promoted_when_checks_pass_and_its_history_stop_is_withdrawn() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let mut filed = filed_workflow();
    filed.program.steps = vec![open(), open(), open()];
    file_program(&fixture, filed);
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_run(run_input(LibraryRunMode::Assisted));
    let output = fixture.expect_ok(result, "met checks promote the run");
    assert_eq!(output.status, SubgoalStatus::Done);
    assert_eq!(output.mode, LibraryRunMode::Assisted);
    assert!(output.model_free, "no decision ran, so none took a model");
    assert_eq!(output.model_free_unproven, None);
    assert!(output.unmet.is_empty(), "every check met");
    assert_eq!(output.batch.completed, 3);
    assert_eq!(output.batch.failed_step, None);
    assert_eq!(output.batch.error, None);
    assert_eq!(output.batch.stop_cause, None);
    assert!(output.batch.failed_receipt.is_none(), "no failed receipt");
    assert_eq!(output.batch.receipts.len(), 3);
    assert!(output.batch.decisions.is_empty(), "no decision ran");
    assert_eq!(url_of(&output.batch.observation), PAGE_URL);
    assert_drove(&fixture, mark, 3);
    assert_eq!(
        fixture.session.history_mark(),
        Some(3),
        "the stop is withdrawn, the third receipt stands last"
    );
    let last = fixture
        .session
        .receipts()
        .last()
        .expect("three effects landed");
    assert_eq!(last.seq, 3, "the third receipt stands last");
    let outcome = RunOutcome {
        mode: LibraryRunMode::Assisted,
        done: true,
        stop_cause: None,
    };
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [
            StoreCall::Program(WORKFLOW.to_owned()),
            StoreCall::RecordRun(WORKFLOW.to_owned(), outcome.clone()),
        ],
        "one lookup, one count"
    );
    assert_eq!(
        store.recorded_runs,
        [(WORKFLOW.to_owned(), outcome)],
        "the promotion counts once, done"
    );
}

#[test]
fn a_program_the_store_never_filed_is_refused_as_missing() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_run(run_input(LibraryRunMode::Assisted));
    let error = result.expect_err("a missing program is refused");
    assert_eq!(
        error,
        BrowserError::NoWorkflow(WORKFLOW.to_owned()),
        "a program with no record is missing, not retired"
    );
    assert_eq!(error.code(), "browser_no_workflow", "the missing code");
    assert_eq!(
        error.to_string(),
        "the library holds no workflow wf1",
        "the missing words"
    );
    fixture.assert_methods(mark, &[]);
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [
            StoreCall::Program(WORKFLOW.to_owned()),
            StoreCall::IsRetired(WORKFLOW.to_owned()),
        ],
        "a missing lookup reads the live map, then the retires"
    );
    assert!(
        store.recorded_runs.is_empty(),
        "a refused run counts nothing"
    );
}

#[test]
fn an_outcome_store_error_is_returned_after_an_effect_has_landed() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    {
        let mut store = fixture.store.lock().expect("store state locks");
        store
            .live
            .insert(WORKFLOW.to_owned(), (card(WORKFLOW), filed_workflow()));
        store.record_run_error = Some(BrowserError::Library("fixture count refused".to_owned()));
    }
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_run(run_input(LibraryRunMode::Assisted));
    let error = result.expect_err("the count error answers");
    assert_eq!(
        error,
        BrowserError::Library("fixture count refused".to_owned()),
        "the store error is returned"
    );
    assert_drove(&fixture, mark, 1);
    assert_eq!(
        fixture.session.history_mark(),
        Some(1),
        "the open landed before the count failed"
    );
    assert_eq!(
        fixture.session.receipts().count(),
        1,
        "the open's effect stands"
    );
    let outcome = RunOutcome {
        mode: LibraryRunMode::Assisted,
        done: true,
        stop_cause: None,
    };
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [
            StoreCall::Program(WORKFLOW.to_owned()),
            StoreCall::RecordRun(WORKFLOW.to_owned(), outcome),
        ],
        "the refused count was still attempted once"
    );
    assert!(
        store.recorded_runs.is_empty(),
        "a refused count records nothing"
    );
}

#[test]
fn no_progress_on_the_last_step_keeps_its_stop_when_the_checks_miss() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let mut filed = filed_workflow();
    filed.program.steps = vec![open(), open(), open()];
    filed.program.postcondition = vec![never()];
    file_program(&fixture, filed);
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_run(run_input(LibraryRunMode::Assisted));
    let output = fixture.expect_ok(result, "a kept stop answers");
    assert_eq!(output.status, SubgoalStatus::NeedsAgent);
    assert_eq!(output.mode, LibraryRunMode::Assisted);
    assert!(output.model_free, "no decision ran, so none took a model");
    assert_eq!(output.model_free_unproven, None);
    assert_eq!(output.unmet, [0_usize]);
    assert_eq!(output.batch.completed, 3);
    assert_eq!(output.batch.failed_step, Some(2));
    assert_eq!(output.batch.error, Some("browser_no_progress".to_owned()));
    assert_eq!(output.batch.stop_cause, Some(BatchStopCause::NoProgress));
    assert_eq!(output.batch.receipts.len(), 3);
    assert!(output.batch.decisions.is_empty(), "no decision ran");
    let failed = output
        .batch
        .failed_receipt
        .as_ref()
        .expect("the stop keeps its receipt");
    assert_eq!(failed.step, Some(2));
    assert_eq!(failed.stop_cause, BatchStopCause::NoProgress);
    assert_eq!(
        failed.missed,
        [CheckReceipt {
            expect: never(),
            observed: unmet_observed()
        }],
        "the check, with what its read found"
    );
    assert_eq!(url_of(&failed.observation), PAGE_URL);
    assert_eq!(failed.error, Some("browser_no_progress".to_owned()));
    assert_eq!(url_of(&output.batch.observation), PAGE_URL);
    assert_drove(&fixture, mark, 3);
    assert_eq!(
        fixture.session.history_mark(),
        Some(4),
        "three opens, then the kept stop"
    );
    let outcome = RunOutcome {
        mode: LibraryRunMode::Assisted,
        done: false,
        stop_cause: Some(BatchStopCause::NoProgress),
    };
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [
            StoreCall::Program(WORKFLOW.to_owned()),
            StoreCall::RecordRun(WORKFLOW.to_owned(), outcome.clone()),
        ],
        "one lookup, one count"
    );
    assert_eq!(
        store.recorded_runs,
        [(WORKFLOW.to_owned(), outcome)],
        "the kept stop counts once, not done"
    );
}
