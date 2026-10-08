//! The voice host attached to a real wake supervisor through the driver's
//! generic pass-attachment seam (moved here from oneiron-driver when the
//! driver stopped depending on this crate).
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::*;
use oneiron::attempt_queue::AttemptId;
use oneiron::interlocutor::InterlocutorResolutionInput;
use oneiron::llm::{
    BudgetDenied, BudgetLease, ContentPart, FatalLlmError, FinishReason, LlmGenerateFuture,
    LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult, LlmStreamResult, LlmUsage,
};
use oneiron::voice_cascade::{
    AsrUpdate, Brain, BrainRequest, CascadeControl, ControlEvent, GenerationEpoch, TtsCommand,
    TtsSeamClient, VoiceSessionConfig,
};
use oneiron::{
    ConsolidationSink, DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt, ModelId, Result, Vault,
    VaultConfig, WakeAttemptContext, WakePassDeadline, WriteActor,
};
use oneiron_driver::{
    ConsolidationExecutorFactory, HintSignal, PassAttachment, PassAttachmentSource,
    PassExecutorFactory, PushTick, Tick, TickSource, WakeSupervisor, WakeSupervisorConfig,
    WakeSupervisorReport,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};

use crate::runtime::RuntimeConfig;

struct Call {
    lease: BudgetLease,
    reply: oneshot::Sender<LlmResult<LlmResponse>>,
}

struct ControlledBackend(mpsc::UnboundedSender<Call>);

impl LlmBackend for ControlledBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let (reply, receive) = oneshot::channel();
            self.0
                .send(Call {
                    lease: lease.clone(),
                    reply,
                })
                .unwrap();
            receive.await.expect("test releases backend")
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

struct UnusedSink;

impl ConsolidationSink for UnusedSink {
    fn accept(
        &mut self,
        _candidates: Vec<oneiron::dreamer_consolidation::PromotionCandidate>,
    ) -> Result<()> {
        panic!("these passes promote no consolidation candidates")
    }
}

struct ScriptedTicks(Vec<Tick>);

impl TickSource for ScriptedTicks {
    async fn next_tick(&mut self) -> Option<Tick> {
        (!self.0.is_empty()).then(|| self.0.remove(0))
    }
}

fn provision(vault: &Vault) {
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(b"voice attachment test host")
        .expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
}

fn test_config() -> WakeSupervisorConfig {
    let mut config = WakeSupervisorConfig::new("driver-budget", "driver-worker", 1, 10_000);
    config.reserve_units = 100;
    config
}

fn seed_actor(vault: &Vault, seed: u8, entity_type: u8) -> oneiron::EntityId {
    let id = oneiron::EntityId::from_bytes([seed; 16]).expect("fixture id");
    vault
        .put_entity(
            &id,
            entity_type,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"voice attachment actor",
        )
        .expect("seed actor");
    id
}

fn enqueue_input(vault: &Vault, input: rmpv::Value, tag: &str, now: u64) -> AttemptId {
    match DreamerRunnerStore::new(vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input,
            parent_attempt: None,
            dedupe_key: Some(tag.to_owned()),
            run_id: Some(tag.to_owned()),
            now,
        })
        .expect("enqueue")
    {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        other => panic!("unexpected enqueue outcome: {other:?}"),
    }
}

fn admit(vault: &Vault, now: u64) -> DreamerAdmittedAttempt {
    let store = DreamerRunnerStore::new(vault);
    let node_id = store
        .local_home_node_candidate(false, false, false)
        .expect("client id")
        .node_id;
    let outcome = store
        .admit_next_consolidation(oneiron::dreamer_runner::AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: node_id,
            claim_authoring_tier: oneiron::dreamer_runner::DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: oneiron::dreamer_runner::DreamerClaimAuthoringAdmission::single_pass(),
            admission: oneiron::dreamer_runner::AdmitDreamerAttempt {
                lease_owner: "voice-attachment-test".to_owned(),
                now,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        })
        .expect("admit");
    let oneiron::dreamer_runner::DreamerConsolidationAdmissionOutcome::Admission(
        oneiron::dreamer_runner::DreamerAdmissionOutcome::Admitted(admitted),
    ) = outcome
    else {
        panic!("expected an admitted micro attempt, got {outcome:?}");
    };
    *admitted
}

fn empty_partition(conversation: oneiron::EntityId) -> rmpv::Value {
    rmpv::Value::Map(vec![
        (
            rmpv::Value::from("conversation_ref"),
            rmpv::Value::Binary(conversation.as_bytes().to_vec()),
        ),
        (rmpv::Value::from("watermark"), rmpv::Value::from(0)),
        (rmpv::Value::from("turns"), rmpv::Value::Array(Vec::new())),
    ])
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    backend: Arc<dyn LlmBackend>,
    calls: mpsc::UnboundedReceiver<Call>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
    provision(&vault);
    let mut policy = vault.purpose_default_table().expect("owner policy");
    policy.extraction_max_locality = oneiron::ModelLocality::OwnServer;
    policy
        .purposes
        .get_mut(&oneiron::CallPurpose::Extraction)
        .expect("extraction row")
        .locality = oneiron::ModelLocality::OwnServer;
    vault
        .set_purpose_default_table(&policy)
        .expect("owner-pinned test egress");
    let (send, calls) = mpsc::unbounded_channel();
    Fixture {
        _dir: dir,
        vault,
        backend: Arc::new(ControlledBackend(send)),
        calls,
    }
}

fn consolidation_factory(fixture: &Fixture) -> ConsolidationExecutorFactory {
    let model = ModelId::new("test/model@v1").unwrap();
    ConsolidationExecutorFactory::new(
        Arc::clone(&fixture.backend),
        DreamerClaimAuthoringStrategy::SinglePass,
        fixture.vault.dreamer_authority().unwrap(),
        model.clone(),
        oneiron::llm::HostInferenceBinding::Advertised {
            model,
            locality: oneiron::ModelLocality::OwnServer,
        },
        Some(Arc::new(|_: &oneiron::LlmRequest| true)),
        Box::new(UnusedSink),
    )
}

fn voice_config(vault: &Arc<Vault>) -> VoiceHostConfig {
    let mut runtime = RuntimeConfig::default();
    runtime.role_defaults.summarizer.model = "test/tiny@v1".to_owned();
    VoiceHostConfig::new(
        Arc::clone(vault),
        runtime,
        "Extract entity_labels and salient_terms as JSON.".to_owned(),
        VoiceSessionConfig::new(
            "driver-voice-test",
            InterlocutorResolutionInput {
                owner_session: false,
                parties: Vec::new(),
                voice_session_ref: None,
            },
        ),
        ManagedShutdown::new(),
    )
}

fn pass_guard(vault: &Vault) -> BudgetGuard {
    let config = test_config();
    vault
        .policy_budget_guard(
            "wake",
            config.budget_total_units,
            config.reserve_units,
            config.exhaustion_policy,
            vault.dreamer_authority().unwrap(),
        )
        .unwrap()
}

fn seven_units() -> LlmResponse {
    let mut usage = LlmUsage::zero();
    usage.output.total = 7;
    usage.output.text = 7;
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: r#"{"entity_labels":[],"salient_terms":[]}"#.to_owned(),
            }],
        },
        usage,
        finish_reason: FinishReason::Stop,
    }
}

#[test]
fn branch_read_fixture_grants_only_the_named_actor_and_class() {
    let fx = fixture();
    let vault = &fx.vault;
    let conversation = seed_actor(vault, 0x72, oneiron::registry::ENTITY_TYPE_SESSION);
    let actor = vault.dreamer_authority().unwrap();
    let reader = |class: &str| {
        oneiron::claim::ScopedReadActorKey::with_actor_class(actor.entity_ref().to_hex(), class)
            .unwrap()
    };
    let visible = |key| {
        vault
            .scoped_read(key)
            .read(&[oneiron::claim::PointRead::id(conversation)], None)
            .unwrap()
            .single()
            .is_some()
    };
    assert!(!visible(reader("agent")));
    let wrong = WriteActor::new(actor.entity_ref(), oneiron::EdgeActorClass::Agent);
    assert!(vault.install_read_permit_for_test(wrong).is_err());
    vault.install_read_permit_for_test(actor).unwrap();
    assert!(visible(reader("system")));
    assert!(!visible(reader("human")));
    assert!(!visible(
        oneiron::claim::ScopedReadActorKey::with_actor_class("other-reader", "agent").unwrap()
    ));
    assert!(
        vault.install_read_permit_for_test(actor).is_err(),
        "customized policy is never overwritten"
    );
}

#[tokio::test]
async fn factory_backend_and_executor_share_the_voice_pass_meter() {
    let mut fx = fixture();
    let vault = Arc::clone(&fx.vault);
    let config = voice_config(&vault);
    let mut factory = consolidation_factory(&fx);
    let guard = pass_guard(&vault);
    let host = config
        .host_for_pass(&vault, factory.backend(), &guard)
        .unwrap();
    assert!(Arc::ptr_eq(host.backend(), factory.backend()));
    let token = host.open("utterance".to_owned()).unwrap();
    for revision in 1..=2 {
        let work = host
            .prepare(&token, revision, format!("text {revision}"), false)
            .unwrap();
        let (result, ()) = tokio::join!(work.run(), async {
            let call = fx.calls.recv().await.unwrap();
            assert_eq!(guard.read().reserved_units, 100);
            call.reply.send(Ok(seven_units())).unwrap();
        });
        assert!(matches!(result.unwrap(), AsrUpdate::Partial(_)));
    }
    assert_eq!(guard.read().used_units, 14);
    assert_eq!(host.budget().read().used_units, 14);
    assert_eq!(host.budget().read().reserved_units, 0);

    // Drive the REAL factory executor to its backend await. The host
    // can release its lease only if this is the very same pass meter.
    vault
        .install_read_permit_for_test(vault.dreamer_authority().unwrap())
        .expect("explicit read grant for the queued branch actor");
    let conversation = seed_actor(&vault, 0x72, oneiron::registry::ENTITY_TYPE_SESSION);
    enqueue_input(
        &vault,
        empty_partition(conversation),
        "voice-shared-executor",
        10,
    );
    let admitted = admit(&vault, 11);
    let deadline = WakePassDeadline::new(180_000);
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 11_000,
        prepared_wake: None,
        prepared_attempt: None,
    };
    let mut executor = factory.executor(&guard).unwrap();
    let execution = executor.execute(&admitted, &mut ctx);
    tokio::pin!(execution);
    // A refused fixture must fail here, not wait forever for a backend call
    // that correct admission checks prevented.
    let call = tokio::select! {
        result = &mut execution => panic!("executor returned before backend admission: {result:?}"),
        call = fx.calls.recv() => call.expect("backend call"),
    };
    assert_eq!(host.budget().read().used_units, 14);
    assert_eq!(host.budget().read().reserved_units, 100);
    host.budget()
        .abort(&call.lease)
        .expect("factory executor lease belongs to host meter");
    call.reply
        .send(Err(FatalLlmError::InvalidRequest.into()))
        .unwrap();
    let result = execution.await;
    assert!(matches!(result, Ok(DreamerAttemptExecution::Park { .. })));
    assert_eq!(guard.read().used_units, 14);
    assert_eq!(guard.read().reserved_units, 0);
}

#[tokio::test]
async fn injected_host_releases_session_and_vault_locks_before_backend_await() {
    let mut fx = fixture();
    let vault = Arc::clone(&fx.vault);
    let guard = pass_guard(&vault);
    let host = voice_config(&vault)
        .host_for_pass(&vault, &fx.backend, &guard)
        .unwrap();
    let token = host.open("utterance".to_owned()).unwrap();
    let work = host.prepare(&token, 1, "old".to_owned(), false).unwrap();
    let (result, ()) = tokio::join!(work.run(), async {
        let call = fx.calls.recv().await.unwrap();
        // A second prepare takes the actual session lock, and these
        // operations take real vault read/write transactions.
        let newer = host.prepare(&token, 2, "new".to_owned(), false).unwrap();
        assert!(vault.retrieval_runs(10).unwrap().is_empty());
        seed_actor(&vault, 0x73, oneiron::registry::ENTITY_TYPE_PERSON);
        drop(newer);
        call.reply.send(Ok(seven_units())).unwrap();
    });
    assert!(matches!(result.unwrap(), AsrUpdate::Ignored));
    assert_eq!(guard.read().used_units, 7);
    assert_eq!(guard.read().reserved_units, 0);
}

#[test]
fn foreign_same_attempt_id_guard_cannot_settle_or_abort_voice_lease() {
    let fx = fixture();
    let vault = Arc::clone(&fx.vault);
    let guard = pass_guard(&vault);
    let foreign = pass_guard(&vault);
    let host = voice_config(&vault)
        .host_for_pass(&vault, &fx.backend, &guard)
        .unwrap();
    let owned = guard.admit().unwrap();
    let other = foreign.admit().unwrap();
    assert_eq!(owned.lease.id(), other.lease.id());
    let before = guard.read();
    assert!(matches!(
        host.budget().abort(&other.lease),
        Err(BudgetDenied::LeaseInvalid)
    ));
    assert!(matches!(
        host.budget()
            .settle_per_call(&other.lease, &seven_units().usage),
        Err(BudgetDenied::LeaseInvalid)
    ));
    assert_eq!(guard.read(), before);
    guard.abort(&owned.lease).unwrap();
    foreign.abort(&other.lease).unwrap();
}

#[tokio::test]
async fn either_shutdown_owner_cancels_voice_and_stops_existing_supervisor() {
    for managed_first in [true, false] {
        let mut fx = fixture();
        let vault = Arc::clone(&fx.vault);
        let config = voice_config(&vault);
        let shutdown = config.shutdown.clone();
        let guard = pass_guard(&vault);
        let host = config.host_for_pass(&vault, &fx.backend, &guard).unwrap();
        let factory = consolidation_factory(&fx).with_pass_attachment(Box::new(config));
        let token = host.open("pending".to_owned()).unwrap();
        let work = host.prepare(&token, 1, "text".to_owned(), false).unwrap();
        let (ticks, _wake, _hint) =
            PushTick::channel(oneiron_driver::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
        let handle = supervisor.shutdown_handle();
        let (result, report, call) = tokio::join!(work.run(), supervisor.run(), async {
            let call = fx.calls.recv().await.unwrap();
            if managed_first {
                shutdown.trigger();
            } else {
                handle.shutdown();
            }
            call
        });
        assert!(matches!(result, Err(HostError::Stopped)));
        assert_eq!(report, WakeSupervisorReport::default());
        assert!(shutdown.is_triggered());
        assert!(call.reply.send(Ok(seven_units())).is_err());
        assert_eq!(guard.read().reserved_units, 0);
        assert_eq!(guard.read().used_units, 0);
    }
}

#[tokio::test]
async fn unconfigured_voice_keeps_existing_constructor_and_wake_path() {
    let mut fx = fixture();
    let vault = Arc::clone(&fx.vault);
    let factory = consolidation_factory(&fx);
    let guard = pass_guard(&vault);
    assert!(factory.pass_attachment(&vault, &guard).unwrap().is_none());
    assert!(factory.linked_shutdown().is_none());
    let ticks = ScriptedTicks(vec![Tick::Hint(HintSignal::default())]);
    let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
    let report = supervisor.run().await;
    assert_eq!(report.passes_completed, 1);
    assert_eq!(report.passes_failed, 0);
    assert!(fx.calls.try_recv().is_err());
}

#[test]
fn configured_voice_cannot_attach_another_vault() {
    let fx = fixture();
    let other = fixture();
    let guard = pass_guard(&fx.vault);
    let config = voice_config(&fx.vault);
    assert!(
        config
            .host_for_pass(&other.vault, &fx.backend, &guard)
            .is_err()
    );
}

#[tokio::test]
async fn a_claimed_connection_with_a_refused_host_fails_closed() {
    let mut fx = fixture();
    let vault = Arc::clone(&fx.vault);
    let mut config = voice_config(&vault);
    config.runtime = RuntimeConfig::default(); // Unrevisioned placeholder is refused.
    let (_client, server) = UnixStream::pair().unwrap(); // Test-only owner stream.
    config.serve_bindings = Some(test_bindings(server, &TestOutputs::default()));
    let guard = pass_guard(&vault);
    // The driver turns this refusal into a pre-admission stop.
    assert!(matches!(
        config.attach(&vault, &fx.backend, &guard),
        Err(oneiron::Error::InvalidConfig(_)),
    ));
    assert!(fx.calls.try_recv().is_err());
}

#[test]
fn refused_attachment_preserves_the_host_error() {
    let fx = fixture();
    let config = voice_config(&fx.vault);
    assert!(config.serve_bindings.is_none());
    config.shutdown.trigger();
    let guard = pass_guard(&fx.vault);
    assert!(matches!(
        config.host_for_pass(&fx.vault, &fx.backend, &guard),
        Err(oneiron::Error::InvalidConfig(_)),
    ));
}

#[tokio::test]
async fn extraction_only_config_does_not_construct_a_host_during_the_pass() {
    let mut fx = fixture();
    let vault = Arc::clone(&fx.vault);
    let mut config = voice_config(&vault);
    assert!(config.serve_bindings.is_none());
    config.runtime = RuntimeConfig::default(); // Would fail if a dummy host were built.
    let guard = pass_guard(&vault);
    assert!(
        config
            .attach(&vault, &fx.backend, &guard)
            .unwrap()
            .is_none()
    );
    // The explicit extraction door still validates the same configuration.
    assert!(config.host_for_pass(&vault, &fx.backend, &guard).is_err());
    let factory = consolidation_factory(&fx).with_pass_attachment(Box::new(config));
    let ticks = ScriptedTicks(vec![Tick::Hint(HintSignal::default())]);
    let report = WakeSupervisor::new(&vault, ticks, factory, test_config())
        .run()
        .await;
    assert_eq!(report.passes_completed, 1);
    assert!(fx.calls.try_recv().is_err());
}

// Recording submissions only: these test doubles are not production clients.
#[derive(Clone, Default)]
struct TestOutputs(Arc<Mutex<Vec<&'static str>>>);

impl Brain for TestOutputs {
    fn start(&mut self, _request: &BrainRequest) -> Result<()> {
        self.0.lock().unwrap().push("brain.start");
        Ok(())
    }

    fn update_context(&mut self, _request: &BrainRequest) -> Result<()> {
        self.0.lock().unwrap().push("brain.update");
        Ok(())
    }

    fn cancel(&mut self, _generation: GenerationEpoch) -> Result<()> {
        self.0.lock().unwrap().push("brain.cancel");
        Ok(())
    }
}

impl TtsSeamClient for TestOutputs {
    fn submit(&mut self, command: TtsCommand) -> Result<()> {
        assert!(matches!(command, TtsCommand::Cancel { .. }));
        self.0.lock().unwrap().push("tts.cancel");
        Ok(())
    }
}

impl CascadeControl for TestOutputs {
    fn flush_queued_pcm(&mut self, _generation: GenerationEpoch) -> Result<()> {
        self.0.lock().unwrap().push("control.flush");
        Ok(())
    }

    fn submit(&mut self, event: ControlEvent) -> Result<()> {
        assert_eq!(event, ControlEvent::SessionEnded);
        self.0.lock().unwrap().push("control.end");
        Ok(())
    }
}

fn test_bindings(stream: UnixStream, outputs: &TestOutputs) -> VoiceServeBindings {
    VoiceServeBindings::new(
        stream,
        VoiceOutputs {
            brain: outputs.clone(),
            tts: outputs.clone(),
            control: outputs.clone(),
        },
    )
}

#[tokio::test]
async fn cloned_bindings_cannot_reuse_the_owner_connection() {
    let (_client, server) = UnixStream::pair().unwrap();
    let bindings = test_bindings(server, &TestOutputs::default());
    let cloned = bindings.clone();
    let connection = bindings.take().unwrap().expect("owner connection");
    assert!(cloned.take().unwrap().is_none());
    drop(connection);
    assert!(bindings.take().unwrap().is_none());
}

/// Records the pass meter the supervisor hands the executor.
struct ObservedFactory {
    inner: ConsolidationExecutorFactory,
    guard: Arc<Mutex<Option<BudgetGuard>>>,
}

impl PassExecutorFactory for ObservedFactory {
    type Exec<'p> = <ConsolidationExecutorFactory as PassExecutorFactory>::Exec<'p>;

    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>> {
        *self.guard.lock().unwrap() = Some(guard.clone());
        self.inner.executor(guard)
    }

    fn actor(&self) -> Option<WriteActor> {
        self.inner.actor()
    }

    fn pass_attachment(
        &self,
        vault: &Vault,
        guard: &BudgetGuard,
    ) -> Result<Option<Box<dyn PassAttachment>>> {
        self.inner.pass_attachment(vault, guard)
    }

    fn linked_shutdown(&self) -> Option<Arc<dyn oneiron_driver::LinkedShutdown>> {
        self.inner.linked_shutdown()
    }
}

#[tokio::test]
async fn owner_stream_serves_with_the_pass_meter_and_stops_on_pass_end_or_shutdown() {
    for managed_shutdown in [false, true] {
        let mut fx = fixture();
        let vault = Arc::clone(&fx.vault);
        let outputs = TestOutputs::default();
        let (client, server) = UnixStream::pair().unwrap(); // Not production admission.
        let mut config = voice_config(&vault);
        let shutdown = config.shutdown.clone();
        config.serve_bindings = Some(test_bindings(server, &outputs));
        let bindings = config.serve_bindings.clone().expect("bindings");
        let observed = Arc::new(Mutex::new(None));
        let factory = ObservedFactory {
            inner: consolidation_factory(&fx).with_pass_attachment(Box::new(config)),
            guard: Arc::clone(&observed),
        };
        vault
            .install_read_permit_for_test(vault.dreamer_authority().unwrap())
            .expect("explicit read grant for the queued branch actor");
        let conversation = seed_actor(&vault, 0x72, oneiron::registry::ENTITY_TYPE_SESSION);
        enqueue_input(
            &vault,
            empty_partition(conversation),
            "voice-serve-pass",
            10,
        );
        let mut pass_config = test_config();
        pass_config.local_node_id = DreamerRunnerStore::new(&vault)
            .local_home_node_candidate(false, false, false)
            .unwrap()
            .node_id;
        let supervisor = WakeSupervisor::new(
            &vault,
            ScriptedTicks(vec![Tick::Hint(HintSignal::default())]),
            factory,
            pass_config,
        )
        .with_clock(Arc::new(|| 11));
        let (read, mut write) = client.into_split();
        let mut read = BufReader::new(read);
        // A hang guard, not a latency bound; a loaded host needs well over 10s.
        let (report, ()) = tokio::time::timeout(Duration::from_secs(60), async {
            let run = supervisor.run();
            tokio::pin!(run);
            let executor_call = tokio::select! {
                _ = &mut run => panic!("pass ended before backend admission"),
                call = fx.calls.recv() => call.expect("consolidation backend call"),
            };
            tokio::join!(run, async {
                // Hold the real consolidation executor in its existing backend.
                let mut executor_call = Some(executor_call);
                let guard = observed.lock().unwrap().as_ref().unwrap().clone();
                assert_eq!(guard.read().reserved_units, 100);
                write.write_all(b"{\"op\":\"open\",\"utterance_id\":\"u\"}\n").await.unwrap();
                let mut line = String::new();
                assert!(read.read_line(&mut line).await.unwrap() > 0);
                assert_eq!(line.trim(), r#"{"op":"opened","handle":"1"}"#);
                write.write_all(b"{\"op\":\"final\",\"handle\":\"1\",\"revision\":1,\"text\":\"text\"}\n").await.unwrap();
                let final_call = fx.calls.recv().await.unwrap();
                assert_eq!(guard.read().reserved_units, 200, "same pass meter");
                final_call.reply.send(Ok(seven_units())).unwrap();
                line.clear();
                assert!(read.read_line(&mut line).await.unwrap() > 0);
                assert!(line.contains(r#""op":"final""#));
                assert_eq!(guard.read().used_units, 7);
                write.write_all(b"{\"op\":\"open\",\"utterance_id\":\"pending\"}\n").await.unwrap();
                line.clear();
                assert!(read.read_line(&mut line).await.unwrap() > 0);
                assert_eq!(line.trim(), r#"{"op":"opened","handle":"2"}"#);
                write.write_all(b"{\"op\":\"partial\",\"handle\":\"2\",\"revision\":1,\"text\":\"pending\"}\n").await.unwrap();
                let pending = fx.calls.recv().await.unwrap();
                assert_eq!(guard.read().reserved_units, 200);
                if managed_shutdown {
                    shutdown.trigger();
                } else {
                    executor_call.take().unwrap().reply
                        .send(Err(BudgetDenied::AdmissionDenied.into())).unwrap();
                }
                line.clear();
                assert_eq!(read.read_line(&mut line).await.unwrap(), 0, "serve must close");
                assert!(pending.reply.send(Ok(seven_units())).is_err());
                assert!(outputs.0.lock().unwrap().contains(&"control.end"));
                if let Some(call) = executor_call {
                    // ManagedShutdown cancels voice while wake remains cooperative.
                    assert_eq!(guard.read().reserved_units, 100);
                    call.reply.send(Err(BudgetDenied::AdmissionDenied.into())).unwrap();
                }
            })
        }).await.expect("bounded test-only pass and stream");
        assert_eq!(report.passes_completed, 1);
        assert_eq!(report.passes_failed, 0);
        assert_eq!(shutdown.is_triggered(), managed_shutdown);
        let guard = observed.lock().unwrap().as_ref().unwrap().clone();
        assert_eq!(guard.read().reserved_units, 0);
        assert_eq!(guard.read().used_units, 7);
        assert_eq!(
            *outputs.0.lock().unwrap(),
            [
                "brain.start",
                "control.flush",
                "brain.cancel",
                "tts.cancel",
                "control.end",
            ]
        );
        assert!(bindings.take().unwrap().is_none(), "one pass claims it");
    }
}
