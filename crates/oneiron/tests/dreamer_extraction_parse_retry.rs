//! [EXTRACTION-JSON-PARSE-RETRY-PROMPT-LOOKUP-OFF]: one Micro wake over one witnessed TURN.
//!
//! 1. A JSON parse failure gets one retry with the same prompt and prompt lookup off. A good
//!    retry completes the try, charging both calls compared with a one-call control.
//! 2. A second JSON parse failure parks the try as Retry with the parse reason, without a third
//!    call.
//! 3. JSON that parses but breaks the extraction contract parks without a retry.
//! 4. The retry's prompt lookup switch goes to an own server, not a third-party API.
//! 5. A reply cut short by the output limit parks without a retry.
//!
//! Red on main 1b32efa6512: the first parse failure parks the try Retry after one call
//! (cases 1, 2, 4 fail). Doors: `oneiron::test_doors::seat_park_model_step`, built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures_core::Stream;
use oneiron::attempt_queue::{AttemptId, AttemptState};
use oneiron::dreamer_runner::DREAMER_SERVER_PARK_OWNER;
use oneiron::llm::OWN_SERVER_ONLY_PARAM;
use oneiron::test_doors::seat_park_model_step as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, DreamerConsolidationScope,
    DreamerParkCause, DreamerRunnerStore, DreamerWakeDriver, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest,
    LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, LlmUsage, ModelLocality,
    RunWakePass, Vault, VaultConfig, WakeCancellation, WakePassDeadline, WakePassReport,
    WakeTrigger,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Reply = (&'static str, FinishReason);

const PASS_T: u64 = 1_000;
const PASS_CEILING_MS: u64 = 180_000;
const WAKE_LINE: &str = "wake";
const BUDGET_TOTAL_UNITS: u64 = 10_000;
const RESERVE_UNITS: u64 = 100;
const READER: &str = "extraction-retry-reader";
const RUN_ID: &str = "extraction-retry-run";
const PROMPT_LOOKUP_PARAM: &str = "oneiron_prompt_lookup";
const BAD_JSON: Reply = ("this is not JSON", FinishReason::Stop);
const NO_CANDIDATES: Reply = (r#"{"candidates": []}"#, FinishReason::Stop);

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

fn frozen_deadline() -> WakePassDeadline {
    WakePassDeadline::with_clock(PASS_CEILING_MS, Arc::new(|| 0))
}

/// An immediate backend that repeats its last reply if asked again.
struct ScriptedBackend {
    replies: Vec<Reply>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl ScriptedBackend {
    fn calls(&self) -> usize {
        self.requests.lock().expect("the request log").len()
    }

    fn requests(&self) -> Vec<LlmRequest> {
        self.requests.lock().expect("the request log").clone()
    }

    fn respond(&self, request: &LlmRequest) -> LlmResponse {
        let index = {
            let mut requests = self.requests.lock().expect("the request log");
            let index = requests.len();
            requests.push(request.clone());
            index
        };
        let (text, finish_reason) = &self.replies[index.min(self.replies.len() - 1)];
        LlmResponse {
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
                raw_provider: Value::Null,
                call_metadata: None,
            },
            finish_reason: finish_reason.clone(),
            reply_assertions: Default::default(),
            token_scores: None,
        }
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
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let response = self.respond(&request);
        Ok(LlmStream::new(ReplyStream(Some(LlmStreamEvent::Done {
            message: response.message,
            usage: response.usage,
            finish_reason: response.finish_reason,
            reply_assertions: response.reply_assertions,
        }))))
    }
}

struct ExtractionPass {
    vault: Vault,
    _dir: tempfile::TempDir,
    attempt: AttemptId,
    backend: ScriptedBackend,
    report: WakePassReport,
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

    fn assert_retry(&self, reason: &str) -> TestResult {
        assert_eq!(self.report.completed, 0);
        assert_eq!(self.report.parked, 1);
        let park = DreamerRunnerStore::new(&self.vault)
            .parked_attempt(self.attempt)?
            .expect("the try's park");
        assert_eq!(park.cause, DreamerParkCause::Retry);
        assert_eq!(park.wait, None);
        assert!(
            park.reason.contains(reason),
            "expected park reason to contain {reason:?}, got {:?}",
            park.reason
        );
        Ok(())
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

    let deadline = frozen_deadline();
    let backend = ScriptedBackend {
        replies: replies.to_vec(),
        requests: Mutex::new(Vec::new()),
    };
    let guard = BudgetGuard::with_reserve_units(
        WAKE_LINE,
        BUDGET_TOTAL_UNITS,
        RESERVE_UNITS,
        BudgetExhaustionPolicy::Suspend,
    );
    let mut executor = doors::PartitionPassExecutor::new(&vault, &backend, &guard, RUN_ID);
    let node_id = release_doors::load_or_mint_client_id(&vault)?;
    let mut driver = DreamerWakeDriver::new(&vault, WAKE_LINE, deadline);
    let report = block_on_ready(driver.run_wake_pass(
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
    ))?;
    Ok(ExtractionPass {
        vault,
        _dir: dir,
        attempt,
        backend,
        report,
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
