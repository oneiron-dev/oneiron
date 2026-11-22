//! FIX-LIST COMPACTION-CHECK-JUDGE-READS-WHOLE-OVER-ROOM-TURN (Engine ruling
//! COMPACTION-CHECK-OVER-JUDGE-ROOM-INTENT = A): the Dreamer's check of a
//! self-written chat summary sends its judge the summary and the span whole.
//! A span past the judge model's context reached a call the provider refuses
//! for its context; the refusal parked the check as a Retry, and every later
//! pass sent the identical request again. The host now lends the judge
//! model's input window, and a judge input that does not fit it settles at
//! once as `unreadable_evidence`, reason `span_past_judge_room`, with no
//! judge call.
//!
//! A self agent's chat lands its own summary on the cheap writer, as
//! `ai_chat_self_compaction` lands it, and the landing declares the check.
//! The test admits that check and runs it as the Dreamer's host does, its
//! judge a network-free backend that records each request and refuses, as a
//! provider does, any request past its context.
//!
//! Red on main with this file and the lend field alone (the check ignores
//! it): the check sends the judge a request past its window, the judge
//! refuses it for its context, and the check parks to send it again. The
//! guard, a span that fits the window, is judged on both.
//!
//! With the host's decisions lent, the typed support read sends the judge's
//! model the same span inside its question turn, a larger request than the
//! diagnostic's. A window the diagnostic fits and the typed read runs past
//! settles the check the same way, before either call. Red at the first fix
//! (77c1bfff), which sized the diagnostic and the question's wording alone:
//! the diagnostic goes out, the typed read is refused for its context, and
//! the check parks to send both again.
//!
//! The served vault reads a clock the test owns, held at one time: the
//! landing declares the check at that time, and the test admits and runs the
//! check at the time the vault's clock reads, never the host's.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --lib -- api::tests::ai_chat_check_judge_room`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oneiron::dreamer_runner::maintenance::compaction_check::{
    COMPACTION_CHECK_FACET, COMPACTION_CHECK_PREDICATE, CompactionCheckDecisions,
    CompactionCheckModel, run_compaction_check,
};
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome};
use oneiron::llm::decision::{DecisionBand, DecisionDial, DecisionRung};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::store::ports::ManualClock;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, DreamerAdmittedAttempt,
    DreamerAttemptExecution, DreamerRunnerStore, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmCapability, LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality,
    UnsupportedCapability, WakeAttemptContext, WakePassDeadline,
};
use serde_json::Value;

use super::ai_chat_self_compaction::{
    SELF_ROW_CONTEXT_TOKENS, compaction_calls_report, log_report, reply, self_row_server_clocked,
    turns_until_compaction,
};
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{eventually, route_extraction};
use crate::decision_host::DecisionHost;
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::SyncServer;

/// The host's rubric under test: prompt data, never engine prose.
const RUBRIC: &str = "the test rubric the judge reads the summary against its span by";
/// A judge context no span of this chat fits beside the rubric: the span's
/// long answers alone run past it.
const SMALL_CONTEXT_TOKENS: u64 = 256;
/// A judge context every span of this chat fits.
const LARGE_CONTEXT_TOKENS: u64 = 1_000_000;
/// The host's wording of the typed support question under test: prompt
/// data, never engine prose.
const SUPPORT_WORDING: &str = "Does the retained span support everything the summary says?";

/// The judge: it records every request it is sent, refuses one whose text
/// runs past `context_tokens`, or one past its first `answered`, as a
/// provider refuses it for its context, and answers any other `supported`.
struct RecordingJudge {
    context_tokens: u64,
    answered: Option<usize>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl RecordingJudge {
    fn new(context_tokens: u64) -> Self {
        Self {
            context_tokens,
            answered: None,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// A judge that answers its first `answered` requests and refuses each
    /// later one for its context, whatever its size.
    fn answering_first(answered: usize) -> Self {
        Self {
            answered: Some(answered),
            ..Self::new(u64::MAX)
        }
    }

    fn requests(&self) -> Vec<LlmRequest> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Every text token `request` sends, by the context-pack tokenizer.
pub(super) fn request_tokens(request: &LlmRequest) -> u64 {
    request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .map(|part| match part {
            ContentPart::Text { text, .. } => oneiron::count_context_pack_tokens(text) as u64,
            _ => 0,
        })
        .sum()
}

/// The judge's `supported` reply, with nonzero usage.
fn supported() -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: serde_json::json!({
                    "verdict": "supported",
                    "conflicts": [],
                    "reason": "the span carries every assertion",
                })
                .to_string(),
                signature: None,
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 10,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 5,
                text: 5,
                reasoning: 0,
            },
            raw_provider: Value::Null,
            call_metadata: None,
        },
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    }
}

impl LlmBackend for RecordingJudge {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let tokens = request_tokens(&request);
        let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
        let past_answered = self
            .answered
            .is_some_and(|answered| requests.len() >= answered);
        requests.push(request);
        drop(requests);
        let answer = if tokens > self.context_tokens || past_answered {
            Err(LlmError::Fatal(FatalLlmError::ContextWindowExceeded {
                message: format!(
                    "a {tokens}-token request exceeds the {}-token context",
                    self.context_tokens
                ),
            }))
        } else {
            Ok(supported())
        };
        Box::pin(async move { answer })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

/// The egress verdict the check's host lends its judge: the fixture allows
/// it, as the Dreamer's own test doors do.
fn allow_judge_extraction(_: &LlmRequest) -> bool {
    true
}

/// The time the served vault's clock is held at, in Unix seconds.
const VAULT_NOW: u64 = 1_790_000_000;

/// The seconds `server`'s vault clock reads: the time it stamps its rows
/// at, which the queue admits by and the check runs at.
pub(super) fn vault_seconds(server: &SyncServer) -> u64 {
    server.vault().now_recorded_at()
}

/// What [`landed_check`] leaves: the served vault whose self agent's chat
/// landed its own summary, the agent, and the landing's admitted check.
struct LandedCheck {
    _dir: tempfile::TempDir,
    _prompts: tempfile::TempDir,
    server: Arc<SyncServer>,
    _host: AiHost,
    _fake: FakeLlm,
    agent: EntityId,
    check: DreamerAdmittedAttempt,
}

/// A self agent's chat lands its own summary, and the check its landing
/// declared is admitted.
async fn landed_check() -> LandedCheck {
    let fake = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(reply)))).await;
    let (dir, prompts, server, host) = self_row_server_clocked(
        &fake.base_url,
        oneiron::llm::SelfCompactionSource::RetainedTurns,
        SELF_ROW_CONTEXT_TOKENS,
        ManualClock::new(VAULT_NOW).bundle(),
    )
    .await;
    let (agent, _) = server
        .vault()
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .unwrap()
        .expect("seeded default agent");
    let conversation = EntityId::now().to_hex();
    let (owner, _) = turns_until_compaction(&server, &fake, &conversation).await;
    let id = EntityId::from_hex(&conversation).unwrap();
    let reader = server.vault().memory(owner, oneiron::EdgeActorClass::Human);
    let history_lines = server.ai.chat_settings().history_turns;
    let landed = eventually(Duration::from_secs(20), || {
        oneiron::compaction::read_chat_log(&reader, id, 1, history_lines)
            .ok()
            .is_some_and(|log| !log.summaries.is_empty())
    })
    .await;
    assert!(
        landed,
        "no summary landed; compaction calls: {:?}; owner's read: {}",
        compaction_calls_report(&fake),
        log_report(&server, owner, &conversation),
    );
    // The judge's call leaves the device as an extraction's does: the owner
    // routes extraction to this server, as the Dreamer's host needs.
    route_extraction(server.vault());
    let store = DreamerRunnerStore::new(server.vault());
    let mut admitted_types = Vec::new();
    let check = loop {
        let outcome = store
            .admit_next_maintenance(AdmitDreamerAttempt {
                lease_owner: "compaction-check-judge-room-test".to_owned(),
                now: vault_seconds(&server),
                budget_id: "wake".to_owned(),
                budget_total_units: 100_000,
                reserve_units: 100,
                started_milestone: None,
            })
            .unwrap();
        let DreamerAdmissionOutcome::Admitted(admitted) = outcome else {
            panic!(
                "no compaction check was declared; admitted {admitted_types:?}, then {outcome:?}"
            );
        };
        if admitted.status.payload.attempt_type == COMPACTION_CHECK_FACET {
            break *admitted;
        }
        admitted_types.push(admitted.status.payload.attempt_type.clone());
    };
    LandedCheck {
        _dir: dir,
        _prompts: prompts,
        server,
        _host: host,
        _fake: fake,
        agent,
        check,
    }
}

/// Runs `check` as the Dreamer's host runs it, its judge `judge` on the
/// window `window_tokens`, and answers how the attempt ended.
pub(super) async fn run_check(
    server: &SyncServer,
    check: &DreamerAdmittedAttempt,
    judge: &dyn LlmBackend,
    window_tokens: u64,
) -> DreamerAttemptExecution {
    run_check_lent(server, check, judge, Some(window_tokens), None).await
}

/// [`run_check`] on the window `window_tokens`, if any, with the typed
/// support verdict on `decisions`' ladder as the server's host lends it:
/// up to its Big rung, so no person is asked.
pub(super) async fn run_check_lent(
    server: &SyncServer,
    check: &DreamerAdmittedAttempt,
    judge: &dyn LlmBackend,
    window_tokens: Option<u64>,
    decisions: Option<&DecisionHost>,
) -> DreamerAttemptExecution {
    let model = ModelId::new("test/judge@r1").unwrap();
    let guard = BudgetGuard::with_reserve_units(
        "compaction-check-judge-room",
        100_000,
        500,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::new(60_000);
    let ctx = WakeAttemptContext {
        vault: server.vault(),
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "test",
        now_ms: vault_seconds(server) * 1_000,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let lent = CompactionCheckModel {
        backend: judge,
        guard: &guard,
        model: model.clone(),
        inference: HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model,
                locality: ModelLocality::OwnServer,
                keyless: false,
            },
            extraction_egress: Some(&allow_judge_extraction),
        },
        role: oneiron::dreamer_consolidation::DREAMER_NARRATIVE_ROLE,
        rubric: RUBRIC,
        window_tokens,
        decisions: decisions.map(|host| CompactionCheckDecisions {
            ladder: host.ladder().ladder(),
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: host.bands(),
            wording: SUPPORT_WORDING.to_owned(),
        }),
    };
    run_compaction_check(check, &ctx, lent).await.unwrap()
}

/// The check's finding about `writer`, its whole value.
pub(super) fn finding(server: &SyncServer, writer: &EntityId) -> Option<Value> {
    let vault = server.vault();
    vault
        .claims_for_subject(writer)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).ok().flatten())
        .filter(|body| body.predicate == COMPACTION_CHECK_PREDICATE)
        .find_map(|body| serde_json::from_str(body.value.as_str()?).ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_span_past_the_judges_window_settles_unreadable_with_no_judge_call() {
    let landed = landed_check().await;
    let judge = RecordingJudge::new(SMALL_CONTEXT_TOKENS);
    let execution = run_check(&landed.server, &landed.check, &judge, SMALL_CONTEXT_TOKENS).await;

    let requests = judge.requests();
    assert!(
        matches!(
            &execution,
            DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_bindings,
            } if step_bindings.is_empty()
        ),
        "the check completes having spent nothing, never parks to ask again: {execution:?}; \
         the judge was sent {} request(s) of {:?} tokens",
        requests.len(),
        requests.iter().map(request_tokens).collect::<Vec<_>>(),
    );
    assert!(
        requests.is_empty(),
        "no judge call goes out for an input past its window"
    );
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(finding["verdict"], "unreadable_evidence", "{finding}");
    assert_eq!(finding["reason"], "span_past_judge_room", "{finding}");
    assert_eq!(finding["judge"], Value::Null, "no judge read it: {finding}");
    assert_eq!(
        finding["evidence"]["read"], finding["evidence"]["declared"],
        "the span was read as its landing declared it: {finding}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_span_within_the_judges_window_is_judged() {
    let landed = landed_check().await;
    let judge = RecordingJudge::new(LARGE_CONTEXT_TOKENS);
    let execution = run_check(&landed.server, &landed.check, &judge, LARGE_CONTEXT_TOKENS).await;

    assert!(
        matches!(
            &execution,
            DreamerAttemptExecution::Completed { step_bindings, .. } if step_bindings.len() == 1
        ),
        "the judged check completes with its one judge step: {execution:?}"
    );
    let requests = judge.requests();
    assert_eq!(requests.len(), 1, "one judge call reads the span");
    assert!(
        request_tokens(&requests[0]) > SMALL_CONTEXT_TOKENS,
        "the span this guard judges is one the small window refuses"
    );
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(finding["verdict"], "supported", "{finding}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_typed_read_past_the_judges_window_settles_unreadable_with_no_judge_call() {
    let landed = landed_check().await;
    let decisions = DecisionHost::new(landed.server.vault());
    // The probe, with no window lent: the judge answers the diagnostic and
    // refuses the typed read for its context, so the check parks having sent
    // both, and their sizes place the window.
    let probe = RecordingJudge::answering_first(1);
    let probed = run_check_lent(
        &landed.server,
        &landed.check,
        &probe,
        None,
        Some(&decisions),
    )
    .await;
    let sizes: Vec<u64> = probe.requests().iter().map(request_tokens).collect();
    let [diagnostic, typed] = sizes[..] else {
        panic!("the probe sends the diagnostic and the typed read: {sizes:?} tokens; {probed:?}");
    };
    assert!(
        diagnostic < typed,
        "the typed read sends the span inside its question turn: {sizes:?} tokens"
    );
    // A window the diagnostic fits and the typed read runs past.
    let window = typed - 1;
    let judge = RecordingJudge::new(window);
    let execution = run_check_lent(
        &landed.server,
        &landed.check,
        &judge,
        Some(window),
        Some(&decisions),
    )
    .await;

    let requests = judge.requests();
    assert!(
        matches!(
            &execution,
            DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_bindings,
            } if step_bindings.is_empty()
        ),
        "the check completes having spent nothing, never parks to ask again: {execution:?}; \
         on a {window}-token window the judge was sent {} request(s) of {:?} tokens",
        requests.len(),
        requests.iter().map(request_tokens).collect::<Vec<_>>(),
    );
    assert!(
        requests.is_empty(),
        "no judge call goes out when the typed read runs past its window"
    );
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(finding["verdict"], "unreadable_evidence", "{finding}");
    assert_eq!(finding["reason"], "span_past_judge_room", "{finding}");
    assert_eq!(finding["judge"], Value::Null, "no judge read it: {finding}");
}
