use super::*;
use oneiron::interlocutor::InterlocutorResolutionInput;
use oneiron::llm::{
    BudgetDenied, BudgetLease, ContentPart, FatalLlmError, FinishReason, LlmGenerateFuture,
    LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult, LlmStreamResult, LlmUsage,
};
use oneiron::voice_cascade::{
    AsrUpdate, Brain, BrainRequest, CascadeControl, ControlEvent, GenerationEpoch, TtsCommand,
    TtsSeamClient, VoiceSessionConfig,
};
use oneiron_server::runtime::RuntimeConfig;
use oneiron_server::voice_host::{HostError, VoiceOutputs, VoiceServeBindings};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};

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

fn fixture() -> (
    tempfile::TempDir,
    Arc<Vault>,
    ConsolidationExecutorFactory,
    mpsc::UnboundedReceiver<Call>,
) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
    let actor = seed_actor(&vault, 0x71, oneiron::registry::ENTITY_TYPE_MACHINE);
    let (send, calls) = mpsc::unbounded_channel();
    let factory = ConsolidationExecutorFactory::new(
        Arc::new(ControlledBackend(send)),
        DreamerClaimAuthoringStrategy::SinglePass,
        WriteActor::new(actor, EdgeActorClass::System),
        ModelId::new("test/model@v1").unwrap(),
        Box::new(UnusedSink),
    );
    (dir, vault, factory, calls)
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

fn pass_guard(vault: &Vault, factory: &ConsolidationExecutorFactory) -> BudgetGuard {
    let config = test_config();
    vault
        .policy_budget_guard(
            "wake",
            pass_ordinary_budget_units(config.budget_total_units),
            config.reserve_units,
            config.exhaustion_policy,
            factory.actor,
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
fn local_runtime_factory_keeps_the_same_backend_allocation() {
    use oneiron_llm_local::{LocalAbortHandle, LocalGeneration, LocalModelMetadata};

    struct UnusedRuntime(LocalModelMetadata);

    impl LocalLlmRuntime for UnusedRuntime {
        fn metadata(&self) -> &LocalModelMetadata {
            &self.0
        }

        fn generate<'a>(
            &'a self,
            _request: LlmRequest,
            _abort: LocalAbortHandle,
        ) -> LlmResult<LocalGeneration<'a>> {
            panic!("construction must not call a model")
        }
    }

    let (_dir, vault, factory, _calls) = fixture();
    let model = ModelId::new("test/tiny@v1").unwrap();
    let factory = ConsolidationExecutorFactory::with_local_runtime(
        UnusedRuntime(LocalModelMetadata::new(model.clone(), "test", 1024)),
        DreamerClaimAuthoringStrategy::SinglePass,
        factory.actor,
        model,
        Box::new(UnusedSink),
    );
    assert!(factory.voice.is_none());
    let backend = Arc::clone(&factory.backend);
    let factory = factory.with_voice(voice_config(&vault));
    let guard = pass_guard(&vault, &factory);
    let host = factory.voice_host(&vault, &guard).unwrap().unwrap();
    assert!(Arc::ptr_eq(&backend, host.backend()));
}

#[tokio::test]
async fn factory_backend_and_executor_share_the_voice_pass_meter() {
    let (_dir, vault, factory, mut calls) = fixture();
    let mut factory = factory.with_voice(voice_config(&vault));
    let guard = pass_guard(&vault, &factory);
    let host = factory.voice_host(&vault, &guard).unwrap().unwrap();
    assert!(Arc::ptr_eq(&factory.backend, host.backend()));
    let token = host.open("utterance".to_owned()).unwrap();
    for revision in 1..=2 {
        let work = host
            .prepare(&token, revision, format!("text {revision}"), false)
            .unwrap();
        let (result, ()) = tokio::join!(work.run(), async {
            let call = calls.recv().await.unwrap();
            assert_eq!(guard.read().reserved_units, 100);
            call.reply.send(Ok(seven_units())).unwrap();
        });
        assert!(matches!(result.unwrap(), AsrUpdate::Partial(_)));
    }
    assert_eq!(guard.read().used_units, 14);
    assert_eq!(host.budget().read(), guard.read());

    // Drive the REAL factory executor to its backend await. The host
    // can release its lease only if this is the very same pass meter.
    let conversation = seed_actor(&vault, 0x72, oneiron::registry::ENTITY_TYPE_PERSON);
    let input = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("conversation_ref"),
            rmpv::Value::Binary(conversation.as_bytes().to_vec()),
        ),
        (rmpv::Value::from("watermark"), rmpv::Value::from(0)),
        (rmpv::Value::from("turns"), rmpv::Value::Array(Vec::new())),
    ]);
    enqueue_input(&vault, input, "voice-shared-executor", 10);
    let admitted = admit(&vault, 11);
    let deadline = WakePassDeadline::new(180_000);
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 11_000,
    };
    let mut executor = factory.executor(&guard).unwrap();
    let (result, ()) = tokio::join!(executor.execute(&admitted, &mut ctx), async {
        let call = calls.recv().await.unwrap();
        assert_eq!(host.budget().read().used_units, 14);
        assert_eq!(host.budget().read().reserved_units, 100);
        host.budget()
            .abort(&call.lease)
            .expect("factory executor lease belongs to host meter");
        call.reply
            .send(Err(FatalLlmError::InvalidRequest.into()))
            .unwrap();
    });
    assert!(matches!(result, Ok(DreamerAttemptExecution::Park { .. })));
    assert_eq!(guard.read().used_units, 14);
    assert_eq!(guard.read().reserved_units, 0);
}

#[tokio::test]
async fn injected_host_releases_session_and_vault_locks_before_backend_await() {
    let (_dir, vault, factory, mut calls) = fixture();
    let factory = factory.with_voice(voice_config(&vault));
    let guard = pass_guard(&vault, &factory);
    let host = factory.voice_host(&vault, &guard).unwrap().unwrap();
    let token = host.open("utterance".to_owned()).unwrap();
    let work = host.prepare(&token, 1, "old".to_owned(), false).unwrap();
    let (result, ()) = tokio::join!(work.run(), async {
        let call = calls.recv().await.unwrap();
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
    let (_dir, vault, factory, _calls) = fixture();
    let factory = factory.with_voice(voice_config(&vault));
    let guard = pass_guard(&vault, &factory);
    let foreign = pass_guard(&vault, &factory);
    let host = factory.voice_host(&vault, &guard).unwrap().unwrap();
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
        let (_dir, vault, factory, mut calls) = fixture();
        let config = voice_config(&vault);
        let shutdown = config.shutdown.clone();
        let factory = factory.with_voice(config);
        let guard = pass_guard(&vault, &factory);
        let host = factory.voice_host(&vault, &guard).unwrap().unwrap();
        let token = host.open("pending".to_owned()).unwrap();
        let work = host.prepare(&token, 1, "text".to_owned(), false).unwrap();
        let (ticks, _wake, _hint) =
            PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
        let handle = supervisor.shutdown_handle();
        let (result, report, call) = tokio::join!(work.run(), supervisor.run(), async {
            let call = calls.recv().await.unwrap();
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
    let (_dir, vault, factory, mut calls) = fixture();
    let guard = pass_guard(&vault, &factory);
    assert!(factory.voice_host(&vault, &guard).unwrap().is_none());
    assert!(factory.voice_shutdown().is_none());
    assert!(factory.voice_serve_bindings().unwrap().is_none());
    let ticks = ScriptedTicks {
        ticks: vec![Tick::Hint(crate::tick::HintSignal::default())],
    };
    let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
    let report = supervisor.run().await;
    assert_eq!(report.passes_completed, 1);
    assert_eq!(report.passes_failed, 0);
    assert!(calls.try_recv().is_err());
}

#[test]
fn configured_voice_cannot_attach_another_vault() {
    let (_dir, vault, factory, _calls) = fixture();
    let (_other_dir, other) = open_vault();
    let factory = factory.with_voice(voice_config(&vault));
    let guard = pass_guard(&vault, &factory);
    assert!(factory.voice_host(&other, &guard).is_err());
}

#[tokio::test]
async fn configured_voice_is_attached_after_guard_and_fails_closed() {
    let (_dir, vault, factory, mut calls) = fixture();
    let mut config = voice_config(&vault);
    config.runtime = RuntimeConfig::default(); // Unrevisioned placeholder is refused.
    let (_client, server) = UnixStream::pair().unwrap(); // Test-only owner stream.
    config.serve_bindings = Some(test_bindings(server, &TestOutputs::default()));
    let mut factory = factory.with_voice(config);
    let clock: NowSeconds = Arc::new(|| 10);
    let result = run_one_pass(
        &vault,
        &test_config(),
        "voice-pass:p0",
        &clock,
        &mut factory,
        &Tick::Hint(crate::tick::HintSignal::default()),
        &WakeCancellation::new(),
    )
    .await;
    let Err(PassRunError::PreAdmission(oneiron::Error::InvalidConfig(message))) = result else {
        panic!("invalid attachment must fail before admission");
    };
    assert_eq!(
        message,
        format!("voice attachment refused: {}", HostError::InvalidRequest)
    );
    assert!(
        DreamerRunnerStore::new(&vault)
            .budget("voice-pass:p0")
            .unwrap()
            .is_none()
    );
    assert!(calls.try_recv().is_err());
}

#[test]
fn refused_attachment_preserves_the_host_error() {
    let (_dir, vault, factory, _calls) = fixture();
    let config = voice_config(&vault);
    assert!(config.serve_bindings.is_none());
    config.shutdown.trigger();
    let factory = factory.with_voice(config);
    let guard = pass_guard(&vault, &factory);
    let Err(oneiron::Error::InvalidConfig(message)) = factory.voice_host(&vault, &guard) else {
        panic!("stopped attachment must be refused");
    };
    assert_eq!(
        message,
        format!("voice attachment refused: {}", HostError::Stopped)
    );
    assert_ne!(message, "voice attachment refused");
}

#[tokio::test]
async fn extraction_only_config_does_not_construct_a_host_during_the_pass() {
    let (_dir, vault, factory, mut calls) = fixture();
    let mut config = voice_config(&vault);
    assert!(config.serve_bindings.is_none());
    config.runtime = RuntimeConfig::default(); // Would fail if a dummy host were built.
    let mut factory = factory.with_voice(config);
    let clock: NowSeconds = Arc::new(|| 10);
    let result = run_one_pass(
        &vault,
        &test_config(),
        "extraction-only:p0",
        &clock,
        &mut factory,
        &Tick::Hint(crate::tick::HintSignal::default()),
        &WakeCancellation::new(),
    )
    .await;
    assert!(result.is_ok());
    assert!(calls.try_recv().is_err());
    // The explicit extraction door still validates the same configuration.
    let guard = pass_guard(&vault, &factory);
    assert!(factory.voice_host(&vault, &guard).is_err());
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

    fn voice_host(&self, vault: &Vault, guard: &BudgetGuard) -> Result<Option<VoiceHost>> {
        let host = self.inner.voice_host(vault, guard)?;
        assert!(Arc::ptr_eq(
            host.as_ref().unwrap().backend(),
            &self.inner.backend
        ));
        Ok(host)
    }

    fn voice_serve_bindings(&self) -> Result<Option<VoiceServeConnection>> {
        self.inner.voice_serve_bindings()
    }

    fn voice_shutdown(&self) -> Option<ManagedShutdown> {
        self.inner.voice_shutdown()
    }
}

#[tokio::test]
async fn owner_stream_serves_with_the_pass_meter_and_stops_on_pass_end_or_shutdown() {
    for managed_shutdown in [false, true] {
        let (_dir, vault, factory, mut calls) = fixture();
        let outputs = TestOutputs::default();
        let (client, server) = UnixStream::pair().unwrap(); // Not production admission.
        let mut config = voice_config(&vault);
        let shutdown = config.shutdown.clone();
        config.serve_bindings = Some(test_bindings(server, &outputs));
        let observed = Arc::new(Mutex::new(None));
        let mut factory = ObservedFactory {
            inner: factory.with_voice(config),
            guard: Arc::clone(&observed),
        };
        let conversation = seed_actor(&vault, 0x72, oneiron::registry::ENTITY_TYPE_PERSON);
        enqueue_input(
            &vault,
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("conversation_ref"),
                    rmpv::Value::Binary(conversation.as_bytes().to_vec()),
                ),
                (rmpv::Value::from("watermark"), rmpv::Value::from(0)),
                (rmpv::Value::from("turns"), rmpv::Value::Array(Vec::new())),
            ]),
            "voice-serve-pass",
            10,
        );
        let mut pass_config = test_config();
        pass_config.local_node_id = DreamerRunnerStore::new(&vault)
            .local_home_node_candidate(false, false, false)
            .unwrap()
            .node_id;
        let clock: NowSeconds = Arc::new(|| 11);
        let (_tx, rx) = watch::channel(false);
        let mut listener = ShutdownListener {
            rx,
            voice: Some(shutdown.clone()),
        };
        let (read, mut write) = client.into_split();
        let mut read = BufReader::new(read);
        let tick = Tick::Hint(crate::tick::HintSignal::default());
        let (outcome, ()) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(run_pass_supervised(
                &vault, &pass_config, "served:p0", &clock, &mut factory, &mut listener, &tick,
            ), async {
                // Hold the real consolidation executor in its existing backend.
                let mut executor_call = Some(calls.recv().await.unwrap());
                let guard = observed.lock().unwrap().as_ref().unwrap().clone();
                assert_eq!(guard.read().reserved_units, 100);
                write.write_all(b"{\"op\":\"open\",\"utterance_id\":\"u\"}\n").await.unwrap();
                let mut line = String::new();
                assert!(read.read_line(&mut line).await.unwrap() > 0);
                assert_eq!(line.trim(), r#"{"op":"opened","handle":"1"}"#);
                write.write_all(b"{\"op\":\"final\",\"handle\":\"1\",\"revision\":1,\"text\":\"text\"}\n").await.unwrap();
                let final_call = calls.recv().await.unwrap();
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
                let pending = calls.recv().await.unwrap();
                assert_eq!(guard.read().reserved_units, 200);
                if managed_shutdown {
                    shutdown.trigger();
                } else {
                    executor_call.take().unwrap().reply
                        .send(Err(FatalLlmError::InvalidRequest.into())).unwrap();
                }
                line.clear();
                assert_eq!(read.read_line(&mut line).await.unwrap(), 0, "serve must close");
                assert!(pending.reply.send(Ok(seven_units())).is_err());
                assert!(outputs.0.lock().unwrap().contains(&"control.end"));
                if let Some(call) = executor_call {
                    // ManagedShutdown cancels voice while wake remains cooperative.
                    assert_eq!(guard.read().reserved_units, 100);
                    call.reply.send(Err(FatalLlmError::InvalidRequest.into())).unwrap();
                }
            })
        }).await.expect("bounded test-only pass and stream");
        assert!(matches!(outcome, PassOutcome::Completed(_)));
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
        assert!(factory.voice_serve_bindings().unwrap().is_none());
    }
}
