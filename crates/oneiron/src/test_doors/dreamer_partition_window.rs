//! Door for `tests/dreamer_window_finish_order.rs` (FIX 21927): one real
//! Meso wake window whose second slot can finish while its first slot's
//! extraction is pending. The injected pass clock enters the finalize window
//! only after that finish replies, or after a bounded poll fallback. Conflict
//! scenarios also read the escalation rows a ready slot publishes or drops.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use rmpv::Value;

use crate::attempt_queue::{AttemptId, AttemptState};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::dreamer_consolidation::selection::SelectionConfig;
use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, decode_partition_payload,
    enqueue_partition_attempts, read_watermark, scan_dirty_turns,
};
use crate::dreamer_promotion::AttemptPromotionSink;
use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use crate::dreamer_wake::{
    DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassDeadline, WakeTrigger,
};
use crate::error::{Error, Result};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::write_envelope::{
    ClaimCandidate, SourceLineage, WriteActor, WriteEnvelope, WriteProvenance,
};
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ContentPart,
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, EdgeActorClass, EdgeKind, EntityId,
    FatalLlmError, FinishReason, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture,
    LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, UnsupportedCapability, Vault,
};

const FINALIZE_ELAPSED_MS: u64 = 170_000;
const SLOW_PREFIX_POLL_LIMIT: usize = 64;
const WAKE_PASS_POLL_LIMIT: usize = 100_000;
const MARKERS: [&str; 2] = ["marker-owen", "marker-yuki"];

/// What one two-partition Meso pass left.
#[derive(Debug, Clone)]
pub struct WindowFinish {
    /// Each slot's outcome in admission order: `landed` (completed with a
    /// stored claim), `completed-empty`, `parked:<cause>` or `other:<state>`.
    pub labels: Vec<String>,
    /// Every model call the backend saw, in order: its purpose, the
    /// partition marker of an extraction, and the pass clock at the call.
    pub calls: Vec<String>,
    /// Open-conflict CLAIM rows about the second slot's person.
    pub open_conflict_markers: usize,
    /// Contradiction gaps citing the second slot's turn in the origin queues.
    pub contradiction_gaps: usize,
    /// The second slot's durable park reason, if it parked.
    pub second_park_reason: Option<String>,
    /// Whether the second slot's conflict judge reply was answered.
    pub judge_answered: bool,
    /// Whether the wake driver returned the contained executor-panic error.
    pub executor_panicked: bool,
}

/// Runs one two-partition Meso pass and reads its labels in admission order.
///
/// Each extraction proposes a new hobby about a listed person. One prior
/// name claim makes the finish ask one correction question; answering `none`
/// needs no merge/value generation. Landings use the real promotion writer.
///
/// # Errors
///
/// Vault setup, wake execution, or reading the persisted attempt outcomes.
pub fn meso_window_finish() -> Result<WindowFinish> {
    run_window_finish(WindowScenario::Finish)
}

/// Runs an early escalation whose settle is stopped by its sibling's panic.
///
/// # Errors
///
/// Vault setup, unexpected wake errors, or reading the persisted outcomes.
pub fn meso_window_stop_drops_early_finish_conflict_rows() -> Result<WindowFinish> {
    run_window_finish(WindowScenario::StopAfterConflict)
}

/// Runs an early escalation whose settle publishes both held conflict rows.
///
/// # Errors
///
/// Vault setup, wake execution, or reading the persisted outcomes.
pub fn meso_window_publishes_early_finish_conflict_rows_at_settle() -> Result<WindowFinish> {
    run_window_finish(WindowScenario::PublishConflict)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowScenario {
    Finish,
    StopAfterConflict,
    PublishConflict,
}

fn run_window_finish(scenario: WindowScenario) -> Result<WindowFinish> {
    let directory = tempfile::tempdir()?;
    let store_clock = crate::ports::ManualClock::new(10);
    let mut config = crate::VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let vault = Arc::new(Vault::open(directory.path(), config)?);
    crate::test_fixtures::provision_engine_machines(&vault);
    authorize_fixture_inference(&vault)?;
    crate::test_fixtures::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest()?,
    )?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        partition_extraction_parallelism: 2,
        extraction_parallelism: 1,
        extraction_turns_per_child: 8,
        ..Default::default()
    })?;
    let conversations = [
        seed_conversation(&vault, 0x71, "owen", MARKERS[0])?,
        seed_conversation(&vault, 0x72, "yuki", MARKERS[1])?,
    ];
    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(&vault, scope)?;
    let dirty = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let queued =
        enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "window-finish", 20)?;
    let mut attempts = BTreeMap::new();
    for outcome in queued {
        let status = match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        };
        let branch = decode_partition_payload(&status.payload.input)?;
        for part in branch.parts {
            attempts.insert(part.conversation_ref, status.attempt.id);
        }
    }
    let backend = WindowBackend {
        scenario,
        elapsed_ms: Arc::new(AtomicU64::new(0)),
        state: Mutex::new(WindowState::default()),
    };
    let elapsed_ms = Arc::clone(&backend.elapsed_ms);
    let deadline =
        WakePassDeadline::with_clock(180_000, Arc::new(move || elapsed_ms.load(Ordering::SeqCst)));
    let guard = BudgetGuard::with_reserve_units(
        "window-finish",
        10_000,
        500,
        BudgetExhaustionPolicy::Suspend,
    );
    let mut sink = AttemptPromotionSink::new(Arc::clone(&vault));
    let model = ModelId::new("test/model@r1").expect("fixture model id");
    let actor = vault.dreamer_authority()?;
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor,
        model: model.clone(),
        inference: HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model,
                locality: ModelLocality::OwnServer,
                keyless: false,
            },
            extraction_egress: Some(&allow_fixture_extraction),
        },
        roles: Default::default(),
        sink: &mut sink,
        scope: None,
        decisions: ConsolidationDecisions::shipped()?,
    };
    let mut driver = DreamerWakeDriver::new(&vault, "window-finish", deadline);
    store_clock.set(21);
    let pass = ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope,
            local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
            lease_owner: "window-finish-worker".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 500,
            now: 21,
            host_scope: None,
            destination_bound: None,
        },
        &mut executor,
        &WakeCancellation::new(),
    ));
    // FIX 7322 ends the pass with this error after draining its window's
    // durable parks. Keep the readings instead of returning early on it.
    let executor_panicked = match pass {
        Ok(_) => false,
        Err(error)
            if scenario == WindowScenario::StopAfterConflict
                && crate::dreamer_wake::is_executor_panic_error(&error) =>
        {
            true
        }
        Err(error) => return Err(error),
    };
    // Prefixes are first polled in admission order. Never assume the queue's
    // generated attempt ids sort in the same order as conversation ids.
    let (order, calls, judge_answered) = {
        let state = backend.state.lock().expect("window state");
        (
            state.extraction_order.clone(),
            state.calls.clone(),
            state.judge_answered,
        )
    };
    let store = DreamerRunnerStore::new(&vault);
    let [_, second] = order.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "fixture expected two extractions; model calls: {calls:?}"
        )));
    };
    let second = &conversations[*second];
    let second_attempt = attempts
        .get(&second.conversation)
        .copied()
        .ok_or_else(|| Error::InvalidConfig("fixture second partition was not queued".into()))?;
    let second_park_reason = store
        .parked_attempt(second_attempt)?
        .map(|parked| parked.reason);
    let (open_conflict_markers, contradiction_gaps) = conflict_row_counts(&vault, second)?;
    let labels = order
        .into_iter()
        .map(|index| {
            let attempt = attempts
                .get(&conversations[index].conversation)
                .copied()
                .ok_or_else(|| Error::InvalidConfig("fixture partition was not queued".into()))?;
            finish_label(&vault, &store, attempt)
        })
        .collect::<Result<_>>()?;
    Ok(WindowFinish {
        labels,
        calls,
        open_conflict_markers,
        contradiction_gaps,
        second_park_reason,
        judge_answered,
        executor_panicked,
    })
}

#[derive(Default)]
struct WindowState {
    extraction_order: Vec<usize>,
    calls: Vec<String>,
    second_extraction_answered: bool,
    finish_answered: bool,
    judge_answered: bool,
}

struct WindowBackend {
    scenario: WindowScenario,
    elapsed_ms: Arc<AtomicU64>,
    state: Mutex<WindowState>,
}

impl LlmBackend for WindowBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        if request.envelope.purpose == CallPurpose::Extraction {
            let transcript = request.messages.last().expect("extraction transcript");
            let index = MARKERS
                .iter()
                .position(|marker| {
                    transcript.content.iter().any(|part| {
                        matches!(part, ContentPart::Text { text, .. } if text.contains(*marker))
                    })
                })
                .expect("one conversation marker in extraction transcript");
            let first = {
                let mut state = self.state.lock().expect("window state");
                let first = state.extraction_order.is_empty();
                state.extraction_order.push(index);
                let at = self.elapsed_ms.load(Ordering::SeqCst);
                state
                    .calls
                    .push(format!("extraction {} at {at}", MARKERS[index]));
                first
            };
            let response = if !first && self.scenario != WindowScenario::Finish {
                conflict_extraction_response(MARKERS[index])
            } else {
                extraction_response(MARKERS[index])
            };
            if first {
                let mut polls_after_second = 0;
                return Box::pin(poll_fn(move |_cx| {
                    let (second_answered, finish_answered) = {
                        let state = self.state.lock().expect("window state");
                        (state.second_extraction_answered, state.finish_answered)
                    };
                    if second_answered {
                        polls_after_second += 1;
                    }
                    if !finish_answered && polls_after_second < SLOW_PREFIX_POLL_LIMIT {
                        return Poll::Pending;
                    }
                    // Panic outside the mutex guard: B's settle and the
                    // outcome reader must still be able to use the backend.
                    if self.scenario == WindowScenario::StopAfterConflict {
                        panic!("fixture first extraction panicked after the conflict judge wait");
                    }
                    self.elapsed_ms.store(FINALIZE_ELAPSED_MS, Ordering::SeqCst);
                    Poll::Ready(Ok(response.clone()))
                }));
            }
            return Box::pin(async move {
                self.state
                    .lock()
                    .expect("window state")
                    .second_extraction_answered = true;
                Ok(response)
            });
        }
        // A's finish is refused before reaching the backend. In the
        // original scenario B has one correction question. The conflict
        // scenarios answer both corrections, then escalate the judge pack.
        let (response, judge) = if self.scenario == WindowScenario::Finish {
            (
                text_response(serde_json::json!({"Q1": {"none": 1.0, "C1": 0.0}})),
                false,
            )
        } else {
            conflict_decision_response(&request)
        };
        {
            let mut state = self.state.lock().expect("window state");
            let at = self.elapsed_ms.load(Ordering::SeqCst);
            state
                .calls
                .push(format!("{:?} at {at}", request.envelope.purpose));
        }
        Box::pin(async move {
            let mut state = self.state.lock().expect("window state");
            state.judge_answered |= judge;
            state.finish_answered = self.scenario == WindowScenario::Finish || judge;
            Ok(response)
        })
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

fn extraction_response(marker: &str) -> LlmResponse {
    text_response(serde_json::json!({"candidates": [{
        "subject": "P1",
        "predicate": "profile.hobby",
        "value": "tea",
        "confidence": 0.8,
        "evidence_refs": [{"source": "T1", "quote": marker}],
    }]}))
}

fn conflict_extraction_response(marker: &str) -> LlmResponse {
    let candidates: Vec<_> = ["tea", "coffee"]
        .into_iter()
        .map(|value| {
            serde_json::json!({
                "subject": "P1",
                "predicate": "profile.hobby",
                "value": value,
                "confidence": 0.8,
                "evidence_refs": [{"source": "T1", "quote": marker}],
            })
        })
        .collect();
    text_response(serde_json::json!({"candidates": candidates}))
}

fn conflict_decision_response(request: &LlmRequest) -> (LlmResponse, bool) {
    assert_eq!(request.envelope.purpose, CallPurpose::Consolidation);
    let turn = request.messages.last().expect("typed decision turn");
    let text = turn
        .content
        .iter()
        .find_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text),
            _ => None,
        })
        .expect("typed decision text");
    let pack: serde_json::Value = serde_json::from_str(text).expect("typed decision JSON");
    let questions = pack["questions"].as_array().expect("typed questions");
    let mut answers = serde_json::Map::new();
    let mut judge = false;
    for question in questions {
        let id = question["id"].as_str().expect("question label");
        let labels = question["labels"].as_array().expect("choice labels");
        let resolution = labels
            .iter()
            .any(|label| label.as_str() == Some("escalate"));
        judge |= resolution;
        let selected = if resolution { "escalate" } else { "none" };
        assert!(labels.iter().any(|label| label.as_str() == Some(selected)));
        let weights: serde_json::Map<String, serde_json::Value> = labels
            .iter()
            .map(|label| {
                let label = label.as_str().expect("choice label");
                let weight = if label == selected { 1.0 } else { 0.0 };
                (label.to_owned(), serde_json::json!(weight))
            })
            .collect();
        answers.insert(id.to_owned(), serde_json::Value::Object(weights));
    }
    (text_response(serde_json::Value::Object(answers)), judge)
}

fn text_response(reply: serde_json::Value) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: reply.to_string(),
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
            raw_provider: serde_json::Value::Null,
            call_metadata: None,
        },
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    }
}

struct ConversationFixture {
    conversation: EntityId,
    person: EntityId,
    turn: EntityId,
}

fn seed_conversation(
    vault: &Vault,
    seed: u8,
    name: &str,
    marker: &str,
) -> Result<ConversationFixture> {
    let conversation = EntityId::from_bytes([seed; 16])?;
    vault.put_entity(
        &conversation,
        ENTITY_TYPE_SESSION,
        occurred(1),
        1,
        b"session",
    )?;
    let person = EntityId::now();
    let named = encode(&Value::Map(vec![("name".into(), name.into())]))?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred(1), 1, &named)?;
    // The listed prior: a clean Dreamer claim of the name in the shape the
    // promotion writer stores one (source and taint `generated`), proposed
    // under the Dreamer's signed MACHINE authority, then approved by the
    // owner, so it stands as an admitted head the finish's correction read
    // asks about. A setup that did not reach Approved stops here.
    let prior = EntityId::now();
    let mut envelope = WriteEnvelope::with_lineage(
        vault.dreamer_authority()?,
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("window finish prior"))?,
        ClaimApprovalStatus::Proposed,
        SourceLineage::of(ClaimSource::Generated),
    );
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(person),
        Value::from(name),
        0.9,
    )
    .with_evidence_taint(ClaimSource::Generated)?;
    vault.sign_registered_machine_claim(&prior, &candidate, &mut envelope)?;
    vault
        .batch()
        .claim_candidate(&prior, candidate, &envelope, occurred(2), 2)
        .commit()?;
    vault.approve_machine_claim_as(
        prior,
        WriteActor::new(
            crate::vault::embedded_owner_actor_id()?,
            EdgeActorClass::Human,
        ),
    )?;
    let stored = vault.get_claim(&prior)?.ok_or(Error::EntityNotFound)?;
    if stored.approval != ClaimApprovalStatus::Approved {
        return Err(Error::InvalidConfig(format!(
            "fixture prior did not reach Approved: {:?}",
            stored.approval
        )));
    }
    let turn = EntityId::now();
    let body = Value::Map(vec![
        ("txt".into(), format!("{name} {marker} enjoys tea").into()),
        ("spkr".into(), "user".into()),
        ("actor".into(), person.to_hex().into()),
    ]);
    let encoded = encode(&body)?;
    vault
        .batch()
        .put(&turn, ENTITY_TYPE_TURN, occurred(10), 10, &encoded)
        .edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)
        .commit()?;
    Ok(ConversationFixture {
        conversation,
        person,
        turn,
    })
}

fn conflict_row_counts(vault: &Vault, fixture: &ConversationFixture) -> Result<(usize, usize)> {
    let mut markers = 0;
    for id in vault.claims_for_subject(&fixture.person)? {
        let body = vault.get_claim(&id)?.ok_or(Error::EntityNotFound)?;
        if body.predicate == crate::claim::PREDICATE_CONFLICT_OPEN {
            markers += 1;
        }
    }
    // The origin queue has no public decoder. Read its persisted namespace
    // directly, without the approval/lifecycle filters of claim retrieval.
    let txn = vault.store.env.read_txn()?;
    let mut gaps = 0;
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&txn, b"dreamer:gap-branch:v1:")?
    {
        let (_, raw) = row?;
        let gap = rmpv::decode::read_value(&mut &raw[..])
            .map_err(|_| Error::InvalidConfig("fixture gap row decoding".into()))?;
        let kind = map_field(&gap, "kind").and_then(Value::as_str);
        let subject_matches = matches!(
            map_field(&gap, "subject"),
            Some(Value::Binary(id)) if id.as_slice() == fixture.person.as_bytes()
        );
        let cites_turn = map_field(&gap, "evidence_turn_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.iter().any(|id| {
                    matches!(id, Value::Binary(id) if id.as_slice() == fixture.turn.as_bytes())
                })
            });
        if kind == Some("contradiction_left_standing") && subject_matches && cites_turn {
            gaps += 1;
        }
    }
    Ok((markers, gaps))
}

fn map_field<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value))
}

fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| Error::InvalidConfig("fixture body encoding".into()))?;
    Ok(encoded)
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn allow_fixture_extraction(_: &LlmRequest) -> bool {
    true
}

fn authorize_fixture_inference(vault: &Vault) -> Result<()> {
    let mut policy = vault.purpose_default_table()?;
    policy.extraction_max_locality = ModelLocality::OwnServer;
    policy
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .ok_or_else(|| Error::InvalidConfig("missing extraction row".into()))?
        .locality = ModelLocality::OwnServer;
    vault.set_purpose_default_table(&policy)
}

fn finish_label(
    vault: &Vault,
    store: &DreamerRunnerStore<'_>,
    attempt: AttemptId,
) -> Result<String> {
    let status = store
        .status(attempt)?
        .ok_or_else(|| Error::InvalidConfig("fixture attempt disappeared".into()))?;
    if let Some(parked) = store.parked_attempt(attempt)? {
        return Ok(format!("parked:{}", parked.cause.as_str()));
    }
    if status.attempt.state == AttemptState::Completed {
        // Its commit landed a claim, whatever approval the gate gave it:
        // the window's order, not the gate, is under test.
        let outputs =
            crate::dreamer_consolidation::nightly_merge::extraction_outputs(vault, attempt)?;
        for output in outputs {
            if vault.get_claim(&output)?.is_some() {
                return Ok("landed".to_owned());
            }
        }
        return Ok("completed-empty".to_owned());
    }
    Ok(format!("other:{:?}", status.attempt.state).to_lowercase())
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..WAKE_PASS_POLL_LIMIT {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
    panic!("Meso window wake pass exceeded 100000 polls; pending backend child was not re-polled");
}
