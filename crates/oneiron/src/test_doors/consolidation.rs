//! One Dreamer consolidation pass, for integration tests (S63E live leak 1):
//! a witnessed TURN whose words are a relationship-scoped MESSAGE the Dreamer
//! may read, extracted on an unbound branch with a scripted model reply, and
//! landed through the promotion writer.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, enqueue_partition_attempts, read_watermark,
    scan_dirty_turns,
};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerRunnerStore,
};
use crate::dreamer_wake::{DreamerAttemptExecutor, WakeAttemptContext, WakePassDeadline};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ContentPart,
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, FatalLlmError, FinishReason,
    LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage,
    LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, ModelId,
    ModelLocality, UnsupportedCapability,
};

/// What one unbound pass did.
#[derive(Debug, Clone)]
pub struct UnboundPass {
    /// The TURN its words were witnessed into.
    pub turn: EntityId,
    /// The consolidation attempt that ran it.
    pub attempt: crate::attempt_queue::AttemptId,
    /// The relationship exposure each model call was bound to, in call
    /// order: `None` for an unbound call.
    pub call_relationships: Vec<Option<BTreeSet<EntityId>>>,
    /// The claims the pass landed.
    pub landed: Vec<EntityId>,
}

/// A scripted model that answers every call with `reply` and records each
/// call's relationship exposure.
struct ReplyBackend {
    reply: String,
    calls: Mutex<Vec<Option<BTreeSet<EntityId>>>>,
}

impl LlmBackend for ReplyBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls
            .lock()
            .expect("call log")
            .push(request.envelope.scope.relationship.clone());
        let response = LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: self.reply.clone(),
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
        };
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

fn ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the consolidation pass did not finish in one poll"),
    }
}

fn allow_fixture_extraction(_: &LlmRequest) -> bool {
    true
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Lets fixture extraction run on this server: the extraction purpose's
/// locality is the own server.
fn allow_own_server_extraction(vault: &Vault) -> Result<()> {
    let mut policy = vault.purpose_default_table()?;
    policy.extraction_max_locality = ModelLocality::OwnServer;
    policy
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .ok_or_else(|| Error::InvalidConfig("missing extraction row".into()))?
        .locality = ModelLocality::OwnServer;
    vault.set_purpose_default_table(&policy)
}

/// The shipped policy (the Dreamer's rows included) plus a `core:read`
/// grant for actor `reader`, so a test reads as a member would.
pub(super) fn shipped_policy_with_reader(vault: &Vault, reader: &str) -> Result<()> {
    shipped_policy_with_read_scope(
        vault,
        reader,
        &crate::federation::scope_codec::read_preset(),
    )
}

/// The shipped policy (the Dreamer's rows included) plus a `core:read`
/// grant of `scope` for actor `reader`.
pub(super) fn shipped_policy_with_read_scope(
    vault: &Vault,
    reader: &str,
    scope: &crate::federation::Scope,
) -> Result<()> {
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest()?.as_slice())
            .map_err(|_| Error::InvalidConfig("default policy".into()))?
    else {
        return Err(Error::InvalidConfig("default policy is not a map".into()));
    };
    let grant = rmpv::Value::Map(vec![
        (rmpv::Value::from("actor_ref"), rmpv::Value::from(reader)),
        (
            rmpv::Value::from("effector"),
            rmpv::Value::from("core:read"),
        ),
        (
            rmpv::Value::from("scope"),
            crate::federation::scope_codec::encode_scope_value(scope)?,
        ),
        (
            rmpv::Value::from("receipt_required"),
            rmpv::Value::Boolean(false),
        ),
    ]);
    match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("scoped_grants"))
    {
        Some((_, rmpv::Value::Array(rows))) => rows.push(grant),
        _ => entries.push((
            rmpv::Value::from("scoped_grants"),
            rmpv::Value::Array(vec![grant]),
        )),
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries))
        .map_err(|_| Error::InvalidConfig("encode policy".into()))?;
    crate::test_fixtures::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

/// A fixture vault for one Dreamer pass: engine machines provisioned,
/// fixture extraction allowed on this server, and the shipped policy plus a
/// `core:read` grant for `reader`.
///
/// # Errors
///
/// The vault's.
pub fn open_dreamer_vault(path: &std::path::Path, reader: &str) -> Result<Vault> {
    let vault = Vault::open(path, crate::VaultConfig::device())?;
    crate::test_fixtures::provision_engine_machines(&vault);
    allow_own_server_extraction(&vault)?;
    shipped_policy_with_reader(&vault, reader)?;
    Ok(vault)
}

/// Witnesses `words` as one visible user MESSAGE carrying `metadata` into a
/// fresh TURN, gives the Dreamer a live `MessagesRead` grant on
/// `readable_space` when one is named, then runs one Micro consolidation pass
/// with no caller scope (an unbound branch), the scripted model answering
/// every call with `reply`, and lands what it extracts through the promotion
/// writer.
///
/// # Errors
///
/// The vault's, or a pass that does not complete.
pub fn consolidate_unbound_turn(
    vault: &Vault,
    words: &str,
    metadata: Option<serde_json::Value>,
    readable_space: Option<EntityId>,
    reply: &str,
) -> Result<UnboundPass> {
    let speaker = EntityId::now();
    vault.put_entity(&speaker, ENTITY_TYPE_PERSON, occurred(1), 1, b"witness")?;
    let conversation = EntityId::now();
    let turn = EntityId::now();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: words.to_owned(),
                parts: None,
                metadata,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .map_err(|error| Error::InvalidConfig(format!("witness: {error:?}")))?;
    let actor = vault.dreamer_authority()?;
    if let Some(space) = readable_space {
        vault.create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                principal_ref: actor.entity_ref(),
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: None,
                authority_scope: crate::federation::scope_codec::read_preset(),
                companion_bounds: None,
            },
        )?;
    }

    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(vault, scope)?;
    let dirty = scan_dirty_turns(vault, scope, &watermark, 10)?;
    enqueue_partition_attempts(vault, scope, &dirty, &watermark, "run-1", 20)?;
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = DreamerRunnerStore::new(vault).admit_next_consolidation(
        AdmitDreamerConsolidationAttempt {
            scope,
            local_node_id: crate::identity::load_or_mint_client_id(vault)?,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "test-door".to_owned(),
                now: 21,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        },
    )?
    else {
        return Err(Error::InvalidConfig(
            "no consolidation attempt was admitted".into(),
        ));
    };

    let backend = ReplyBackend {
        reply: reply.to_owned(),
        calls: Mutex::new(Vec::new()),
    };
    let guard =
        BudgetGuard::with_reserve_units("wake", 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let mut sink = PromotionWriterSink::new(
        vault,
        DreamerRunContext {
            run_id: "run-1".into(),
            attempt_id: admitted.status.attempt.id,
            agent_actor: actor,
            now_ms: 21_000,
        },
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    {
        let mut executor = ConsolidationExecutor {
            roles: Default::default(),
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor,
            model: ModelId::new("test/model@r1")
                .map_err(|_| Error::InvalidConfig("model id".into()))?,
            inference: HostInferenceContext {
                binding: HostInferenceBinding::Advertised {
                    model: ModelId::new("test/model@r1")
                        .map_err(|_| Error::InvalidConfig("model id".into()))?,
                    locality: ModelLocality::OwnServer,
                    keyless: false,
                },
                extraction_egress: Some(&allow_fixture_extraction),
            },
            sink: &mut sink,
            scope: None,
            decisions: ConsolidationDecisions::shipped()?,
        };
        let outcome = ready(executor.execute(
            &admitted,
            &mut WakeAttemptContext {
                vault,
                deadline: &deadline,
                cancel: None,
                device_cancel: None,
                budget_id: "wake",
                now_ms: 21_000,
                prepared_wake: None,
                prepared_attempt: None,
                spend_meter: None,
            },
        ))?;
        if !matches!(
            outcome,
            crate::dreamer_wake::DreamerAttemptExecution::Completed { .. }
        ) {
            return Err(Error::InvalidConfig(
                "the consolidation pass did not complete".into(),
            ));
        }
    }
    let call_relationships = backend.calls.into_inner().expect("call log");
    Ok(UnboundPass {
        turn,
        attempt: admitted.status.attempt.id,
        call_relationships,
        landed: std::mem::take(&mut sink.outcome.landed),
    })
}
