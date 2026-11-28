//! [EXTRACTION-JSON-PARSE-RETRY-PROMPT-LOOKUP-OFF]: one Micro wake over one witnessed TURN.
//!
//! 1. A JSON parse failure gets one retry with the same prompt and prompt lookup off. A good
//!    retry completes the try, charging both calls compared with a one-call control.
//! 2. A second JSON parse failure parks the try as Retry with the parse reason, without a third
//!    call.
//! 3. JSON that parses but breaks the extraction contract parks without a retry.
//! 4. The retry's prompt lookup switch goes to an own server, not a third-party API.
//! 5. A reply cut short by the output limit parks without a retry.
//! 6. A run of the try that replays the slice (a thing branch's fan-out after its agent, a try
//!    resumed after a cut pass) takes the retry's saved reply and asks the model no third time.
//! 7. A retry the finalize window refuses before it goes out is not counted on the stage line,
//!    and the refused first reply is still charged.
//! 8. A retry held back before it went out (here by the finalize window) goes out, prompt
//!    lookup off, on the try's next run, in place of a fresh original with lookup on.
//! 9. A retry the backend gives back unsent (no rung serves at this hour) is not counted on the
//!    stage line.
//! 10. A parse failure a hosted rung answered, as its ladder's served receipt names it, is not
//!     asked again: that rung's wire drops the switch, so the retry would be the same request
//!     sent again at once. One an own server answered is asked again.
//!
//! Red on main 1b32efa6512: the first parse failure parks the try Retry after one call
//! (cases 1, 2, 4, 6 fail). Red at 025c8df5887 (review round 1 of #10269, P1 1 and P1 2): the
//! replay sends the original request a third time (case 6), and the stage line counts the
//! refused retry (case 7). Red at 247b54b8331 (review round 2 of #10269, P1 2 and P1 3): the
//! next run sends the original with lookup on (case 8), and the stage line counts the retry
//! given back unsent (case 9). Red on main 8418b839a4ad: the hosted rung's parse failure is
//! asked again (case 10). Doors: `oneiron::test_doors::seat_park_model_step`, built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures_core::Stream;
use oneiron::attempt_queue::{AttemptId, AttemptState};
use oneiron::dreamer_runner::DREAMER_SERVER_PARK_OWNER;
use oneiron::llm::OWN_SERVER_ONLY_PARAM;
use oneiron::test_doors::seat_park_model_step as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, DREAMER_GRACEFUL_WRAP_WINDOW_MS,
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerConsolidationScope, DreamerParkCause, DreamerRunnerStore, DreamerWakeDriver,
    FinishReason, LlmBackend, LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage,
    LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent,
    LlmStreamResult, LlmUsage, ModelLocality, RetryableLlmError, RunWakePass, Vault, VaultConfig,
    WakeAttemptContext, WakeCancellation, WakePassDeadline, WakePassReport, WakeTrigger,
};
use serde_json::Value;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Reply = (&'static str, FinishReason);

const PASS_T: u64 = 1_000;
const PASS_CEILING_MS: u64 = 180_000;
/// Inside the pass's finalize window, before its ceiling: a new step is refused.
const FINALIZE_WINDOW_MS: u64 = PASS_CEILING_MS - 1_000;
/// Past the ceiling and the landing window after it: a finished partition checkpoints.
const LANDING_CLOSED_MS: u64 = PASS_CEILING_MS + DREAMER_GRACEFUL_WRAP_WINDOW_MS;
const WAKE_LINE: &str = "wake";
const BUDGET_TOTAL_UNITS: u64 = 10_000;
const RESERVE_UNITS: u64 = 100;
const READER: &str = "extraction-retry-reader";
const RUN_ID: &str = "extraction-retry-run";
const PROMPT_LOOKUP_PARAM: &str = "oneiron_prompt_lookup";
const STAGE_TARGET: &str = "oneiron::dreamer::stages";
const BAD_JSON: Reply = ("this is not JSON", FinishReason::Stop);
const NO_CANDIDATES: Reply = (r#"{"candidates": []}"#, FinishReason::Stop);
/// The served receipt's key naming where the rung that answered runs
/// (`LlmUsage::SERVED_LOCALITY_KEY`).
const SERVED_LOCALITY_KEY: &str = "locality";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("the wake pass is pending on something other than an attempt-boundary yield");
}

/// A pass deadline on a test clock, and that clock's elapsed milliseconds.
fn test_deadline() -> (WakePassDeadline, Arc<AtomicU64>) {
    let elapsed = Arc::new(AtomicU64::new(0));
    let clock = Arc::clone(&elapsed);
    let deadline = WakePassDeadline::with_clock(
        PASS_CEILING_MS,
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    (deadline, elapsed)
}

/// Moves the pass clock to `ms` once the backend has answered `calls` calls.
#[derive(Clone, Copy)]
struct ClockStep {
    calls: usize,
    ms: u64,
}

/// An immediate backend that repeats its last reply if asked again. From call
/// `outside_hours_from` (0-based) on, it answers that no rung serves at this hour, as a
/// ladder whose only rung closed does: nothing goes out. With `served`, each reply carries a
/// ladder's served receipt naming that locality for the rung that answered.
struct ScriptedBackend {
    replies: Vec<Reply>,
    requests: Mutex<Vec<LlmRequest>>,
    elapsed: Arc<AtomicU64>,
    clock_step: Option<ClockStep>,
    outside_hours_from: Option<usize>,
    served: Option<ModelLocality>,
}

/// A ladder's served receipt for an answer from its first rung, which runs at `locality`.
fn served_receipt(locality: ModelLocality) -> Value {
    serde_json::json!({
        (LlmUsage::SERVED_PROVIDER_KEY): "scripted",
        "rung": 0,
        "failed_rungs": 0,
        (SERVED_LOCALITY_KEY): locality.as_str(),
        "usage": {},
    })
}

impl ScriptedBackend {
    fn calls(&self) -> usize {
        self.requests.lock().expect("the request log").len()
    }

    fn requests(&self) -> Vec<LlmRequest> {
        self.requests.lock().expect("the request log").clone()
    }

    fn respond(&self, request: &LlmRequest) -> LlmResult<LlmResponse> {
        let index = {
            let mut requests = self.requests.lock().expect("the request log");
            let index = requests.len();
            requests.push(request.clone());
            index
        };
        if let Some(step) = self.clock_step
            && step.calls == index + 1
        {
            self.elapsed.store(step.ms, Ordering::SeqCst);
        }
        if self.outside_hours_from.is_some_and(|from| index >= from) {
            return Err(LlmError::Retryable(RetryableLlmError::OutsideHours {
                retry_after: None,
                resets_at: Vec::new(),
            }));
        }
        let (text, finish_reason) = &self.replies[index.min(self.replies.len() - 1)];
        Ok(LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: (*text).to_owned(),
                    signature: None,
                }],
            },
            usage: LlmUsage {
                input: LlmInputUsage {
                    total: 40,
                    cache_read: 0,
                    cache_write: 0,
                },
                output: LlmOutputUsage {
                    total: 10,
                    text: 10,
                    reasoning: 0,
                },
                raw_provider: self.served.map_or(Value::Null, served_receipt),
                call_metadata: None,
            },
            finish_reason: finish_reason.clone(),
            reply_assertions: Default::default(),
            token_scores: None,
        })
    }
}

struct ReplyStream(Option<LlmStreamEvent>);

impl Stream for ReplyStream {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.take().map(Ok))
    }
}

impl LlmBackend for ScriptedBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let response = self.respond(&request);
        Box::pin(async move { response })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let response = self.respond(&request)?;
        Ok(LlmStream::new(ReplyStream(Some(LlmStreamEvent::Done {
            message: response.message,
            usage: response.usage,
            finish_reason: response.finish_reason,
            reply_assertions: response.reply_assertions,
        }))))
    }
}

/// The fields of every stage-line event, as text.
#[derive(Clone, Default)]
struct StageLines(Arc<Mutex<Vec<Vec<(String, String)>>>>);

/// Collects one event's fields.
struct FieldText<'a>(&'a mut Vec<(String, String)>);

impl Visit for FieldText<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.push((field.name().to_owned(), value.to_string()));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_owned(), value.to_owned()));
    }
}

impl Subscriber for StageLines {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != STAGE_TARGET {
            return;
        }
        let mut fields = Vec::new();
        event.record(&mut FieldText(&mut fields));
        self.0.lock().expect("stage lines").push(fields);
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// The host's partition executor over each admitted try. With `replay` (the pass clock), it
/// runs the try twice, as a thing branch's fan-out replays the steps its agent ran and a
/// resumed try replays its cut pass: the first run's landing window has closed once its calls
/// answered, so it checkpoints with nothing landed; the clock then goes back inside the pass
/// for the second run, whose result the pass settles.
struct PassExecutor<'a> {
    inner: doors::PartitionPassExecutor<'a>,
    replay: Option<Arc<AtomicU64>>,
    /// Whether the first of two runs checkpointed.
    cut_checkpointed: Option<bool>,
}

impl DreamerAttemptExecutor for PassExecutor<'_> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let Some(elapsed) = self.replay.clone() else {
            return self.inner.execute(attempt, ctx).await;
        };
        let cut = self.inner.execute(attempt, ctx).await?;
        let checkpointed = matches!(
            cut,
            DreamerAttemptExecution::Park {
                cause: DreamerParkCause::Checkpoint,
                ..
            } | DreamerAttemptExecution::ParkWithSpend {
                cause: DreamerParkCause::Checkpoint,
                ..
            }
        );
        self.cut_checkpointed = Some(checkpointed);
        if !checkpointed {
            return Ok(cut);
        }
        elapsed.store(0, Ordering::SeqCst);
        self.inner.execute(attempt, ctx).await
    }
}

struct ExtractionPass {
    vault: Vault,
    _dir: tempfile::TempDir,
    attempt: AttemptId,
    backend: ScriptedBackend,
    report: WakePassReport,
    stage_lines: Vec<Vec<(String, String)>>,
    cut_checkpointed: Option<bool>,
}

impl ExtractionPass {
    fn assert_completed(&self) -> TestResult {
        assert_eq!(self.report.completed, 1);
        assert_eq!(self.report.parked, 0);
        let store = DreamerRunnerStore::new(&self.vault);
        assert!(store.parked_attempt(self.attempt)?.is_none());
        let status = store.status(self.attempt)?.expect("the try's row");
        assert_eq!(status.attempt.state, AttemptState::Completed);
        Ok(())
    }

    fn assert_parked(&self, cause: DreamerParkCause) -> TestResult<String> {
        assert_eq!(self.report.completed, 0);
        assert_eq!(self.report.parked, 1);
        let park = DreamerRunnerStore::new(&self.vault)
            .parked_attempt(self.attempt)?
            .expect("the try's park");
        assert_eq!(park.cause, cause, "park reason {:?}", park.reason);
        assert_eq!(park.wait, None);
        Ok(park.reason)
    }

    fn assert_retry(&self, reason: &str) -> TestResult {
        let parked = self.assert_parked(DreamerParkCause::Retry)?;
        assert!(
            parked.contains(reason),
            "expected park reason to contain {reason:?}, got {parked:?}"
        );
        Ok(())
    }

    /// `name` on every stage line the pass logged, in order.
    fn stage_field(&self, name: &str) -> Vec<String> {
        self.stage_lines
            .iter()
            .filter_map(|line| {
                line.iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.clone())
            })
            .collect()
    }

    // This fresh budget line served only this try. No units remain reserved after settlement.
    fn charged_units(&self) -> TestResult<u64> {
        let budget = DreamerRunnerStore::new(&self.vault)
            .budget(WAKE_LINE)?
            .expect("the wake line's budget row");
        assert_eq!(budget.reserved_units, 0);
        Ok(budget.total_units - budget.remaining_units)
    }
}

fn run_extraction_pass(replies: &[Reply]) -> TestResult<ExtractionPass> {
    run_scripted_pass(replies, None, false)
}

/// One wake pass over one witnessed TURN's try, its calls answered by `replies` in order. The
/// pass clock moves at `clock_step`; with `replay`, the try runs twice (see [`PassExecutor`]).
fn run_scripted_pass(
    replies: &[Reply],
    clock_step: Option<ClockStep>,
    replay: bool,
) -> TestResult<ExtractionPass> {
    run_backend_pass(replies, clock_step, replay, None)
}

/// [`run_scripted_pass`] whose backend answers no rung serves from call `outside_hours_from` on.
fn run_backend_pass(
    replies: &[Reply],
    clock_step: Option<ClockStep>,
    replay: bool,
    outside_hours_from: Option<usize>,
) -> TestResult<ExtractionPass> {
    run_pass(replies, clock_step, replay, outside_hours_from, None)
}

/// [`run_extraction_pass`] whose every reply names `served` as where the rung that answered
/// runs.
fn run_served_pass(replies: &[Reply], served: ModelLocality) -> TestResult<ExtractionPass> {
    run_pass(replies, None, false, None, Some(served))
}

/// [`run_backend_pass`] whose replies carry a served receipt naming `served`, when given.
fn run_pass(
    replies: &[Reply],
    clock_step: Option<ClockStep>,
    replay: bool,
    outside_hours_from: Option<usize>,
    served: Option<ModelLocality>,
) -> TestResult<ExtractionPass> {
    assert!(!replies.is_empty(), "the backend needs at least one reply");
    let clock = oneiron_store::ports::manual_clock::ManualClock::new(PASS_T);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let dir = tempfile::tempdir()?;
    let vault = doors::open_partition_vault(dir.path(), config, READER)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let enqueued =
        doors::enqueue_witnessed_turn(&vault, "The garden gate is painted blue.", RUN_ID, PASS_T)?;
    assert_eq!(enqueued.len(), 1, "one TURN enqueues one partition try");
    let attempt = enqueued[0];

    let (deadline, elapsed) = test_deadline();
    let backend = ScriptedBackend {
        replies: replies.to_vec(),
        requests: Mutex::new(Vec::new()),
        elapsed: Arc::clone(&elapsed),
        clock_step,
        outside_hours_from,
        served,
    };
    let guard = BudgetGuard::with_reserve_units(
        WAKE_LINE,
        BUDGET_TOTAL_UNITS,
        RESERVE_UNITS,
        BudgetExhaustionPolicy::Suspend,
    );
    let mut executor = PassExecutor {
        inner: doors::PartitionPassExecutor::new(&vault, &backend, &guard, RUN_ID),
        replay: replay.then_some(elapsed),
        cut_checkpointed: None,
    };
    let node_id = release_doors::load_or_mint_client_id(&vault)?;
    let mut driver = DreamerWakeDriver::new(&vault, WAKE_LINE, deadline);
    let lines = StageLines::default();
    let report = tracing::subscriber::with_default(lines.clone(), || {
        block_on_ready(driver.run_wake_pass(
            RunWakePass {
                trigger: WakeTrigger::Compaction,
                scope: DreamerConsolidationScope::Micro,
                local_node_id: node_id,
                lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
                budget_total_units: BUDGET_TOTAL_UNITS,
                reserve_units: RESERVE_UNITS,
                now: PASS_T,
                host_scope: None,
                destination_bound: None,
            },
            &mut executor,
            &WakeCancellation::new(),
        ))
    })?;
    let cut_checkpointed = executor.cut_checkpointed;
    drop(executor);
    let stage_lines = lines.0.lock().expect("stage lines").clone();
    Ok(ExtractionPass {
        vault,
        _dir: dir,
        attempt,
        backend,
        report,
        stage_lines,
        cut_checkpointed,
    })
}

fn run_parse_retry() -> TestResult<ExtractionPass> {
    let pass = run_extraction_pass(&[BAD_JSON, NO_CANDIDATES])?;
    assert_eq!(
        pass.backend.calls(),
        2,
        "one parse failure gets exactly one retry"
    );
    Ok(pass)
}

fn own_server_only(request: &LlmRequest) -> &[Value] {
    request
        .params
        .get(OWN_SERVER_ONLY_PARAM)
        .and_then(Value::as_array)
        .expect("the own-server-only sampling list")
}

#[test]
fn a_reply_that_fails_the_json_parse_is_asked_again_once_with_prompt_lookup_off() -> TestResult {
    let pass = run_parse_retry()?;
    let requests = pass.backend.requests();
    let initial = &requests[0];
    let retry = &requests[1];
    let lookup_name = Value::String(PROMPT_LOOKUP_PARAM.to_owned());

    assert!(!initial.params.contains_key(PROMPT_LOOKUP_PARAM));
    assert!(!own_server_only(initial).contains(&lookup_name));
    assert_eq!(
        retry.params.get(PROMPT_LOOKUP_PARAM),
        Some(&Value::Bool(false))
    );
    assert!(own_server_only(retry).contains(&lookup_name));
    assert_eq!(
        retry.messages, initial.messages,
        "the retry keeps the same prompt"
    );
    assert_ne!(
        initial.canonical_hash()?,
        retry.canonical_hash()?,
        "the retry has its own durable request key"
    );
    pass.assert_completed()?;

    let control = run_extraction_pass(&[NO_CANDIDATES])?;
    assert_eq!(control.backend.calls(), 1);
    control.assert_completed()?;
    let control_units = control.charged_units()?;
    assert!(control_units > 0, "the control call must charge spend");
    assert_eq!(
        pass.charged_units()?,
        2 * control_units,
        "both the parse failure and its successful retry charge spend"
    );
    Ok(())
}

#[test]
fn a_retry_that_fails_the_json_parse_again_parks_the_try_retry_as_before() -> TestResult {
    let pass = run_extraction_pass(&[BAD_JSON])?;
    assert_eq!(pass.backend.calls(), 2, "the retry is never retried");
    pass.assert_retry("extraction response must be JSON")
}

#[test]
fn a_reply_whose_json_parses_but_breaks_the_contract_is_not_retried() -> TestResult {
    let pass = run_extraction_pass(&[("[1, 2]", FinishReason::Stop)])?;
    assert_eq!(pass.backend.calls(), 1, "a contract fault is not retried");
    pass.assert_retry("breaks its contract")
}

#[test]
fn the_retry_sends_prompt_lookup_off_to_an_own_server_only() -> TestResult {
    let pass = run_parse_retry()?;
    let mut retry = pass.backend.requests().pop().expect("the retry request");
    let lookup = PROMPT_LOOKUP_PARAM.to_owned();
    let marker = OWN_SERVER_ONLY_PARAM.to_owned();
    let temperature = "temperature".to_owned();

    retry.envelope.locality = ModelLocality::OwnServer;
    let own_wire = retry.wire_params()?;
    assert_eq!(own_wire.get(&lookup).copied(), Some(&Value::Bool(false)));
    assert!(!own_wire.contains_key(&marker));
    assert!(own_wire.contains_key(&temperature));

    retry.envelope.locality = ModelLocality::ThirdParty;
    let hosted_wire = retry.wire_params()?;
    assert!(!hosted_wire.contains_key(&lookup));
    assert!(!hosted_wire.contains_key(&marker));
    assert!(!hosted_wire.contains_key(&temperature));
    Ok(())
}

#[test]
fn a_cut_reply_is_not_retried() -> TestResult {
    let pass = run_extraction_pass(&[(r#"{"candidates": ["#, FinishReason::Length)])?;
    assert_eq!(pass.backend.calls(), 1, "a cut reply is not retried");
    pass.assert_retry("did not finish whole")
}

#[test]
fn a_replayed_slice_takes_its_saved_retry_reply_and_asks_the_model_no_third_time() -> TestResult {
    let pass = run_scripted_pass(
        &[BAD_JSON, NO_CANDIDATES],
        Some(ClockStep {
            calls: 2,
            ms: LANDING_CLOSED_MS,
        }),
        true,
    )?;
    assert_eq!(
        pass.cut_checkpointed,
        Some(true),
        "the first run checkpoints once its landing window closed"
    );
    let hashes = pass
        .backend
        .requests()
        .iter()
        .map(LlmRequest::canonical_hash)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        pass.backend.calls(),
        2,
        "the replay answers from the retry's saved reply; requests sent: {hashes:x?}"
    );
    pass.assert_completed()
}

#[test]
fn a_retry_the_finalize_window_refuses_is_not_counted_but_charged() -> TestResult {
    let pass = run_scripted_pass(
        &[BAD_JSON],
        Some(ClockStep {
            calls: 1,
            ms: FINALIZE_WINDOW_MS,
        }),
        false,
    )?;
    assert_eq!(
        pass.backend.calls(),
        1,
        "the finalize window refuses the retry before it goes out"
    );
    pass.assert_parked(DreamerParkCause::Checkpoint)?;
    assert_eq!(
        pass.stage_field("parse_retries"),
        ["0"],
        "no retry went out; stage lines: {:?}",
        pass.stage_lines
    );

    let control = run_extraction_pass(&[NO_CANDIDATES])?;
    assert_eq!(control.backend.calls(), 1);
    assert_eq!(
        pass.charged_units()?,
        control.charged_units()?,
        "the refused first reply is charged once"
    );
    Ok(())
}

#[test]
fn a_retry_held_back_goes_out_with_prompt_lookup_off_on_the_next_run() -> TestResult {
    let pass = run_scripted_pass(
        &[BAD_JSON, NO_CANDIDATES],
        Some(ClockStep {
            calls: 1,
            ms: FINALIZE_WINDOW_MS,
        }),
        true,
    )?;
    assert_eq!(
        pass.cut_checkpointed,
        Some(true),
        "the first run checkpoints once the finalize window held its retry back"
    );
    let requests = pass.backend.requests();
    assert_eq!(
        requests.len(),
        2,
        "the next run asks once: the held-back retry"
    );
    assert!(!requests[0].params.contains_key(PROMPT_LOOKUP_PARAM));
    assert_eq!(
        requests[1].params.get(PROMPT_LOOKUP_PARAM),
        Some(&Value::Bool(false)),
        "the next run sends the retry with prompt lookup off, not the original again"
    );
    pass.assert_completed()?;
    assert_eq!(
        pass.stage_field("parse_retries").last().map(String::as_str),
        Some("1"),
        "the run that sent the retry counts it; stage lines: {:?}",
        pass.stage_lines
    );
    Ok(())
}

#[test]
fn a_retry_no_rung_serves_at_this_hour_is_not_counted() -> TestResult {
    let pass = run_backend_pass(&[BAD_JSON], None, false, Some(1))?;
    let requests = pass.backend.requests();
    assert_eq!(
        requests.len(),
        2,
        "the retry reaches the ladder, which gives it back unsent"
    );
    assert_eq!(
        requests[1].params.get(PROMPT_LOOKUP_PARAM),
        Some(&Value::Bool(false))
    );
    assert_eq!(pass.report.completed, 0);
    assert_eq!(
        pass.stage_field("parse_retries"),
        ["0"],
        "no retry went out; stage lines: {:?}",
        pass.stage_lines
    );
    Ok(())
}

#[test]
fn a_parse_failure_a_hosted_rung_answered_is_not_asked_again() -> TestResult {
    let hosted = run_served_pass(&[BAD_JSON, NO_CANDIDATES], ModelLocality::ThirdParty)?;
    assert_eq!(
        hosted.backend.calls(),
        1,
        "a hosted rung's wire drops the switch, so its retry would be the same request"
    );
    hosted.assert_retry("extraction response must be JSON")?;

    let own = run_served_pass(&[BAD_JSON, NO_CANDIDATES], ModelLocality::OwnServer)?;
    assert_eq!(
        own.backend.calls(),
        2,
        "an own server's parse failure is asked again once"
    );
    assert_eq!(
        own.backend.requests()[1].params.get(PROMPT_LOOKUP_PARAM),
        Some(&Value::Bool(false))
    );
    own.assert_completed()
}
