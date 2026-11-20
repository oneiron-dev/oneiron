//! Door for `tests/dreamer_extraction_room.rs` (FIX
//! DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW): one real Meso wake pass
//! over one conversation whose TURNs say the given words, with the
//! extraction model's input window lent or not, keeping every extraction
//! call's transcript.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use rmpv::Value;

use super::meso_extraction_width::{
    allow_fixture_extraction, authorize_fixture_inference, encode, occurred, text_response,
};
use crate::attempt_queue::AttemptState;
use crate::dreamer_consolidation::selection::SelectionConfig;
use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, RoleBackends, enqueue_partition_attempts,
    read_watermark, scan_dirty_turns,
};
use crate::dreamer_promotion::AttemptPromotionSink;
use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use crate::dreamer_wake::{
    DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassDeadline, WakeTrigger,
};
use crate::error::{Error, Result};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ContentPart,
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, EdgeKind, EntityId, FatalLlmError,
    LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
    ModelLocality, UnsupportedCapability, Vault,
};

const WAKE_PASS_POLL_LIMIT: usize = 100_000;

/// Runs one Meso pass over one conversation whose TURNs say `turns` in
/// order, at most `turns_per_child` TURNs a call, lending the extraction
/// model's input window `window_tokens` when given (as the host's factory
/// does from its model windows), and returns each extraction call's
/// transcript, its last user message, in call order.
///
/// # Errors
///
/// Vault setup, the wake pass, or an attempt that did not complete.
pub fn meso_extraction_transcripts(
    turns: &[String],
    turns_per_child: usize,
    window_tokens: Option<u64>,
) -> Result<Vec<String>> {
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
        extraction_parallelism: 1,
        extraction_turns_per_child: turns_per_child,
        ..Default::default()
    })?;
    seed_conversation(&vault, turns)?;
    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(&vault, scope)?;
    let dirty = scan_dirty_turns(&vault, scope, &watermark, turns.len() + 1)?;
    let queued = enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "room", 20)?;
    let [queued] = queued.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "expected one Meso partition, got {}",
            queued.len()
        )));
    };
    let attempt = match queued {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
    };
    let backend = TranscriptBackend::default();
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0));
    let guard =
        BudgetGuard::with_reserve_units("room", 10_000, 500, BudgetExhaustionPolicy::Suspend);
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
        roles: RoleBackends::default().with_follower_window(window_tokens),
        sink: &mut sink,
        scope: None,
        decisions: ConsolidationDecisions::shipped()?,
    };
    let mut driver = DreamerWakeDriver::new(&vault, "room", deadline);
    store_clock.set(21);
    ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope,
            local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
            lease_owner: "room-worker".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 500,
            now: 21,
            host_scope: None,
            destination_bound: None,
        },
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    let status = DreamerRunnerStore::new(&vault)
        .status(attempt)?
        .ok_or(Error::EntityNotFound)?;
    if status.attempt.state != AttemptState::Completed {
        return Err(Error::InvalidConfig(format!(
            "the Meso attempt ended {:?}",
            status.attempt.state
        )));
    }
    let transcripts = backend
        .transcripts
        .lock()
        .expect("transcript backend state")
        .clone();
    Ok(transcripts)
}

/// Answers every call with no candidates, keeping each extraction call's
/// transcript.
#[derive(Default)]
struct TranscriptBackend {
    transcripts: Mutex<Vec<String>>,
}

impl LlmBackend for TranscriptBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        if request.envelope.purpose == CallPurpose::Extraction {
            let transcript: String = request
                .messages
                .last()
                .map(|message| {
                    message
                        .content
                        .iter()
                        .filter_map(|part| match part {
                            ContentPart::Text { text, .. } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            self.transcripts
                .lock()
                .expect("transcript backend state")
                .push(transcript);
        }
        let response = text_response(serde_json::json!({"candidates": []}));
        Box::pin(async move { Ok(response) })
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

/// One conversation of `turns`, each a user TURN said by one person.
fn seed_conversation(vault: &Vault, turns: &[String]) -> Result<()> {
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
    for words in turns {
        let turn = EntityId::now();
        let encoded = encode(&Value::Map(vec![
            ("txt".into(), words.as_str().into()),
            ("spkr".into(), "user".into()),
            ("actor".into(), person.to_hex().into()),
        ]))?;
        vault
            .batch()
            .put(&turn, ENTITY_TYPE_TURN, occurred(10), 10, &encoded)
            .edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)
            .commit()?;
    }
    Ok(())
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..WAKE_PASS_POLL_LIMIT {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
    panic!("the extraction room wake pass did not end within its poll limit");
}
