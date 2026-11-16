//! Door for `tests/dreamer_meso_width.rs` (FIX 21927 P2): measure the
//! extraction calls in flight during one real Meso wake pass over stored
//! Dreamer-shaped priors, with no synthetic rows or provenance bypass.

use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use rmpv::Value;

use crate::attempt_queue::AttemptState;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject, claim_evidence_taint};
use crate::dreamer_consolidation::selection::SelectionConfig;
use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, enqueue_partition_attempts, read_watermark,
    scan_dirty_turns,
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

const EXTRACTION_SLICES: usize = 4;
const EXTRACTION_POLL_LIMIT: usize = 32;
const WAKE_PASS_POLL_LIMIT: usize = 100_000;

/// The admitted ancestry in the one conversation's prior heads.
#[derive(Debug, Clone, Copy)]
pub enum PriorScenario {
    /// A clean Generated/generated Dreamer head only.
    Generated,
    /// The clean head plus a ToolOutput/tool_output Dreamer head.
    ToolOutputDescended,
    /// The clean head plus an Imported/imported Dreamer head.
    Imported,
}

/// Measurements and provenance from the Meso pass, not from a Micro setup pass.
#[derive(Debug, Clone)]
pub struct ExtractionWidth {
    /// Maximum simultaneous unresolved extraction futures.
    pub peak_extraction_calls_in_flight: usize,
    /// Total Meso extraction calls, required by the door to equal four.
    pub extraction_calls: usize,
    /// Stored source, taint and approval of each prior, and every call's purpose
    /// and count of admitted heads actually rendered in its transcript.
    pub diagnostics: Vec<String>,
}

/// Runs a real Meso partition with four one-TURN slices and measures its width.
///
/// Priors use the promotion writer's source/taint/lineage shapes. The direct
/// envelope door first writes signed proposals under the Dreamer authority;
/// owner approval then vets them through the normal signed transition door.
/// In particular, a tainted Auto head cannot stand as an admitted prior.
///
/// # Errors
///
/// Vault setup, legitimate prior writes/approvals, wake execution, missing
/// admitted heads, an unexpected model call, or an incomplete partition.
pub fn meso_extraction_width(scenario: PriorScenario) -> Result<ExtractionWidth> {
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
        partition_extraction_parallelism: 1,
        extraction_parallelism: 8,
        extraction_turns_per_child: 1,
        ..Default::default()
    })?;
    let person = seed_conversation(&vault)?;
    let mut diagnostics = vec![format!("scenario={scenario:?}, slices={EXTRACTION_SLICES}")];
    let mut expected_heads = vec![seed_prior(
        &vault,
        person,
        ClaimSource::Generated,
        "profile.name",
        "owen",
        &mut diagnostics,
    )?];
    let tainted = match scenario {
        PriorScenario::Generated => None,
        PriorScenario::ToolOutputDescended => Some(ClaimSource::ToolOutput),
        PriorScenario::Imported => Some(ClaimSource::Imported),
    };
    if let Some(source) = tainted {
        expected_heads.push(seed_prior(
            &vault,
            person,
            source,
            "profile.hobby",
            "tea",
            &mut diagnostics,
        )?);
    }
    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(&vault, scope)?;
    let dirty = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let queued = enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "meso-width", 20)?;
    let [queued] = queued.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "expected one Meso partition, got {}; {diagnostics:?}",
            queued.len()
        )));
    };
    let status = match queued {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };
    let attempt = status.attempt.id;
    let backend = WidthBackend {
        expected_heads,
        state: Mutex::new(WidthState::default()),
    };
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0));
    let guard =
        BudgetGuard::with_reserve_units("meso-width", 10_000, 500, BudgetExhaustionPolicy::Suspend);
    let mut sink = AttemptPromotionSink::new(Arc::clone(&vault));
    let model = ModelId::new("test/model@r1").expect("fixture model id");
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
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
    let mut driver = DreamerWakeDriver::new(&vault, "meso-width", deadline);
    store_clock.set(21);
    ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope,
            local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
            lease_owner: "meso-width-worker".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 500,
            now: 21,
            host_scope: None,
            destination_bound: None,
        },
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    let state = backend.state.lock().expect("width backend state");
    diagnostics.extend(state.diagnostics.iter().cloned());
    let store = DreamerRunnerStore::new(&vault);
    let status = store.status(attempt)?.ok_or_else(|| {
        Error::InvalidConfig(format!("Meso attempt disappeared; {diagnostics:?}"))
    })?;
    let parked = store.parked_attempt(attempt)?;
    diagnostics.push(format!(
        "attempt_state={:?}, parked={parked:?}",
        status.attempt.state
    ));
    if status.attempt.state != AttemptState::Completed
        || parked.is_some()
        || state.extraction_calls != EXTRACTION_SLICES
        || state.non_extraction_calls != 0
        || state.in_flight != 0
        || state.missing_heads
    {
        return Err(Error::InvalidConfig(format!(
            "Meso width fixture did not complete four extraction-only calls over all admitted priors; {diagnostics:?}"
        )));
    }
    Ok(ExtractionWidth {
        peak_extraction_calls_in_flight: state.peak,
        extraction_calls: state.extraction_calls,
        diagnostics,
    })
}

#[derive(Default)]
struct WidthState {
    in_flight: usize,
    peak: usize,
    extraction_calls: usize,
    non_extraction_calls: usize,
    all_slices_started: bool,
    missing_heads: bool,
    diagnostics: Vec<String>,
}

struct WidthBackend {
    expected_heads: Vec<String>,
    state: Mutex<WidthState>,
}

impl LlmBackend for WidthBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let extraction = request.envelope.purpose == CallPurpose::Extraction;
        {
            let mut state = self.state.lock().expect("width backend state");
            state
                .diagnostics
                .push(format!("purpose={:?}", request.envelope.purpose));
            if extraction {
                let transcript: String = request
                    .messages
                    .last()
                    .expect("extraction transcript")
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ContentPart::Text { text, .. } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                // Listing pages render only heads in BranchResources::priors.
                // Checking every unique predicate/value line proves admission,
                // including the clean head in each mixed-ancestry scenario.
                let admitted = self
                    .expected_heads
                    .iter()
                    .filter(|head| transcript.contains(head.as_str()))
                    .count();
                state.missing_heads |= admitted != self.expected_heads.len();
                state.diagnostics.push(format!(
                    "admitted_priors_shown={admitted}/{}",
                    self.expected_heads.len()
                ));
                state.extraction_calls += 1;
                state.in_flight += 1;
                state.peak = state.peak.max(state.in_flight);
                state.all_slices_started |= state.in_flight == EXTRACTION_SLICES;
            } else {
                state.non_extraction_calls += 1;
            }
        }
        let response = text_response(serde_json::json!({"candidates": []}));
        if !extraction {
            return Box::pin(async move { Ok(response) });
        }
        let mut polls = 0;
        Box::pin(poll_fn(move |_cx| {
            polls += 1;
            let mut state = self.state.lock().expect("width backend state");
            if !state.all_slices_started && polls < EXTRACTION_POLL_LIMIT {
                return Poll::Pending;
            }
            state.in_flight -= 1;
            Poll::Ready(Ok(response.clone()))
        }))
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

fn seed_conversation(vault: &Vault) -> Result<EntityId> {
    let conversation = EntityId::now();
    vault.put_entity(
        &conversation,
        ENTITY_TYPE_SESSION,
        occurred(1),
        1,
        b"session",
    )?;
    let person = EntityId::now();
    let named = encode(&Value::Map(vec![("name".into(), "owen".into())]))?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred(1), 1, &named)?;
    for index in 0..EXTRACTION_SLICES {
        let turn = EntityId::now();
        let encoded = encode(&Value::Map(vec![
            (
                "txt".into(),
                format!("owen enjoys tea, note {index}").into(),
            ),
            ("spkr".into(), "user".into()),
            ("actor".into(), person.to_hex().into()),
        ]))?;
        vault
            .batch()
            .put(&turn, ENTITY_TYPE_TURN, occurred(10), 10, &encoded)
            .edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)
            .commit()?;
    }
    Ok(person)
}

fn seed_prior(
    vault: &Vault,
    person: EntityId,
    source: ClaimSource,
    predicate: &str,
    value: &str,
    diagnostics: &mut Vec<String>,
) -> Result<String> {
    let id = EntityId::now();
    let lineage = SourceLineage::of(ClaimSource::Generated).with(source);
    let mut envelope = WriteEnvelope::with_lineage(
        vault.dreamer_authority()?,
        source,
        WriteProvenance::new(Value::from("meso width prior"))?,
        ClaimApprovalStatus::Proposed,
        lineage,
    );
    let candidate = ClaimCandidate::new(predicate, ClaimSubject::Entity(person), value.into(), 0.9)
        .with_evidence_taint(source)?;
    vault.sign_registered_machine_claim(&id, &candidate, &mut envelope)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, occurred(2), 2)
        .commit()?;
    let owner = WriteActor::new(
        crate::vault::embedded_owner_actor_id()?,
        EdgeActorClass::Human,
    );
    vault.approve_machine_claim_as(id, owner)?;
    let stored = vault.get_claim(&id)?.ok_or(Error::EntityNotFound)?;
    let taint = claim_evidence_taint(&stored);
    diagnostics.push(format!(
        "prior={} predicate={} source={:?} evidence_taint={taint:?} approval={:?} lineage={:?}",
        id.to_hex(),
        stored.predicate,
        stored.source,
        stored.approval,
        envelope.lineage()
    ));
    if stored.source != Some(source)
        || taint != Some(source)
        || stored.approval != ClaimApprovalStatus::Approved
    {
        return Err(Error::InvalidConfig(format!(
            "prior provenance did not survive the write door; {diagnostics:?}"
        )));
    }
    Ok(format!("{predicate} = {}", serde_json::json!(value)))
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

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..WAKE_PASS_POLL_LIMIT {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
    panic!("Meso width wake pass exceeded 100000 polls; pending extraction was not re-polled");
}
