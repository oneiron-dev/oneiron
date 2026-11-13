//! Door for `tests/dreamer_window_finish_order.rs` (FIX 21927): one real
//! Meso wake window whose second slot can finish while its first slot's
//! extraction is pending. The injected pass clock enters the finalize window
//! only after that finish replies, or after a bounded poll fallback.

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
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
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
    ready(driver.run_wake_pass(
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
    ))?;
    // Prefixes are first polled in admission order. Never assume the queue's
    // generated attempt ids sort in the same order as conversation ids.
    let (order, calls) = {
        let state = backend.state.lock().expect("window state");
        (state.extraction_order.clone(), state.calls.clone())
    };
    let store = DreamerRunnerStore::new(&vault);
    let labels = order
        .into_iter()
        .map(|index| {
            let attempt = attempts
                .get(&conversations[index])
                .copied()
                .ok_or_else(|| Error::InvalidConfig("fixture partition was not queued".into()))?;
            finish_label(&vault, &store, attempt)
        })
        .collect::<Result<_>>()?;
    Ok(WindowFinish { labels, calls })
}

#[derive(Default)]
struct WindowState {
    extraction_order: Vec<usize>,
    calls: Vec<String>,
    second_extraction_answered: bool,
    finish_answered: bool,
}

struct WindowBackend {
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
            let response = extraction_response(MARKERS[index]);
            if first {
                let mut polls_after_second = 0;
                return Box::pin(poll_fn(move |_cx| {
                    let state = self.state.lock().expect("window state");
                    if state.second_extraction_answered {
                        polls_after_second += 1;
                    }
                    if !state.finish_answered && polls_after_second < SLOW_PREFIX_POLL_LIMIT {
                        return Poll::Pending;
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
        // A's finish is refused before reaching the backend. B's one typed
        // correction read chooses none rather than replacing its name claim.
        let response = text_response(serde_json::json!({"Q1": {"none": 1.0, "C1": 0.0}}));
        {
            let mut state = self.state.lock().expect("window state");
            let at = self.elapsed_ms.load(Ordering::SeqCst);
            state
                .calls
                .push(format!("{:?} at {at}", request.envelope.purpose));
        }
        Box::pin(async move {
            self.state.lock().expect("window state").finish_answered = true;
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

fn seed_conversation(vault: &Vault, seed: u8, name: &str, marker: &str) -> Result<EntityId> {
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
    // The listed prior: the owner's own statement of the name, written
    // through the envelope door as `prior_heads.rs`'s fixture writes its head.
    let owner = EntityId::now();
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("owner statement"))?,
        ClaimApprovalStatus::Approved,
    );
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(person),
        Value::from(name),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&EntityId::now(), candidate, &envelope, occurred(2), 2)
        .commit()?;
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
    Ok(conversation)
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
