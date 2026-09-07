//! Source-only proofs with a manually released backend. No provider or service.
use super::*;
use oneiron::interlocutor::InterlocutorResolutionInput;
use oneiron::llm::{
    BudgetExhaustionPolicy, BudgetLease, CallPurpose, ContentPart, FatalLlmError, FinishReason,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult,
    LlmStreamResult, LlmUsage, ResponseFormat, RetryableLlmError,
};
use oneiron::speculative::SpeculativeFireDecision;
use serde_json::json;
use tokio::sync::{mpsc, oneshot};

mod wire;

struct Call {
    request: LlmRequest,
    lease_id: String,
    reply: oneshot::Sender<LlmResult<LlmResponse>>,
}

struct ControlledBackend(mpsc::UnboundedSender<Call>);

impl LlmBackend for ControlledBackend {
    fn generate<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let (reply, receive) = oneshot::channel();
            self.0.send(Call { request, lease_id: lease.id().to_owned(), reply })
                .expect("test observer alive");
            receive.await.expect("test supplies response")
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn fixture() -> (tempfile::TempDir, Arc<oneiron::Vault>, VoiceHost, BudgetGuard, mpsc::UnboundedReceiver<Call>) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = oneiron::VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    let vault = Arc::new(oneiron::Vault::open(dir.path(), config).unwrap());
    let mut server_config = crate::config::SyncServerConfig::default();
    server_config.runtime.role_defaults.summarizer.model = "test/tiny@v1".to_owned();
    let server = SyncServer::new(Arc::clone(&vault), server_config).unwrap();
    let (send, calls) = mpsc::unbounded_channel();
    let budget = BudgetGuard::new("voice-test", 16_000, BudgetExhaustionPolicy::Suspend);
    let host = server.voice_host(VoiceHostBindings {
        backend: Arc::new(ControlledBackend(send)),
        budget: budget.clone(),
        extraction_prompt: "Extract entity_labels and salient_terms from text. Return the JSON schema, including empty arrays when appropriate.".to_owned(),
        session: VoiceSessionConfig::new("host-session", InterlocutorResolutionInput {
            owner_session: false,
            parties: Vec::new(),
            voice_session_ref: None,
        }),
        shutdown: ManagedShutdown::new(),
    }).unwrap();
    (dir, vault, host, budget, calls)
}

fn response(value: serde_json::Value) -> LlmResponse {
    let mut usage = LlmUsage::zero();
    usage.output.total = 7;
    usage.output.text = 7;
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text { text: value.to_string() }],
        },
        usage,
        finish_reason: FinishReason::Stop,
    }
}

fn empty() -> LlmResponse {
    response(json!({"entity_labels": [], "salient_terms": []}))
}

#[tokio::test]
async fn real_admission_exact_bounded_request_empty_signature_and_no_locks_across_await() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let token = host.open("u".to_owned()).unwrap();
    let text = "  exact Unicode 東京\n";
    let work = host.prepare(&token, 1, text.to_owned(), false).unwrap();
    let (result, ()) = tokio::join!(work.run(), async {
        let call = calls.recv().await.unwrap();
        assert_eq!(call.lease_id, "voice-test:metered:1");
        assert_eq!(budget.read().reserved_units, 8_000);
        assert!(host.state.try_lock().is_ok(), "session guard must be released during provider await");
        // Actual vault read and write while the backend is suspended.
        assert!(vault.retrieval_runs(200).unwrap().is_empty());
        let id = oneiron::EntityId::from_bytes([0x5e; 16]).unwrap();
        vault.batch().put(&id, 1, oneiron::temporal::TimeRange { start: 1, end: 1 }, 1, b"fixture").commit().unwrap();
        assert_eq!(call.request.model.as_str(), "test/tiny@v1");
        assert_eq!(call.request.envelope.purpose, CallPurpose::Extraction);
        assert_eq!(call.request.envelope.tier.resolved().as_str(), "tiny");
        assert_eq!(call.request.params["max_output_tokens"], json!(512));
        assert!(call.request.tools.is_empty());
        assert!(call.request.provider_options.is_empty());
        let ContentPart::Text { text: input } = &call.request.messages[1].content[0] else { panic!("text input") };
        assert_eq!(serde_json::from_str::<serde_json::Value>(input).unwrap(), json!({"text": text}));
        let ResponseFormat::Json { schema } = &call.request.envelope.response_format else { panic!("JSON schema") };
        assert_eq!(schema["additionalProperties"], json!(false));
        assert_eq!(schema["properties"]["entity_labels"]["maxItems"], json!(16));
        call.reply.send(Ok(empty())).unwrap();
    });
    let AsrUpdate::Partial(partial) = result.unwrap() else { panic!("partial") };
    assert_eq!(partial.decision, SpeculativeFireDecision::SkippedEmptySignature);
    assert!(partial.context.is_none());
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
    assert_eq!(budget.read().reserved_units, 0);
    assert_eq!(budget.read().used_units, 7);
    assert!(host.prepare(&token, 1, text.to_owned(), false).is_err(), "successful observation consumed once");
}

#[tokio::test]
async fn later_revision_prepared_while_backend_waits_rejects_old_result_before_effects() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let token = host.open("u".to_owned()).unwrap();
    let old = host.prepare(&token, 1, "old".to_owned(), true).unwrap();
    let mut newer = None;
    let (old_result, ()) = tokio::join!(old.run(), async {
        let call = calls.recv().await.unwrap();
        newer = Some(host.prepare(&token, 2, "new".to_owned(), true).unwrap());
        call.reply.send(Ok(response(json!({"entity_labels": ["old"], "salient_terms": ["old"]})))).unwrap();
    });
    assert!(matches!(old_result.unwrap(), AsrUpdate::Ignored));
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
    assert_eq!(budget.read().reserved_units, 0);
    assert_eq!(budget.read().used_units, 7, "stale provider work is still charged");
    let (result, ()) = tokio::join!(newer.take().unwrap().run(), async {
        let call = calls.recv().await.unwrap();
        let ContentPart::Text { text } = &call.request.messages[1].content[0] else { panic!("input") };
        assert_eq!(serde_json::from_str::<serde_json::Value>(text).unwrap(), json!({"text": "new"}));
        call.reply.send(Ok(empty())).unwrap();
    });
    let AsrUpdate::Final(request) = result.unwrap() else { panic!("new final") };
    assert_eq!(request.transcript, "new");
    assert_eq!(vault.retrieval_runs(200).unwrap().len(), 1);
    assert_eq!(budget.read().used_units, 14, "fresh work adds to stale work");
    assert_eq!(budget.read().reserved_units, 0);
}

#[tokio::test]
async fn close_and_reopen_same_label_during_provider_wait_drops_late_final() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let token = host.open("same".to_owned()).unwrap();
    let work = host.prepare(&token, 1, "old".to_owned(), true).unwrap();
    let (result, replacement) = tokio::join!(work.run(), async {
        let call = calls.recv().await.unwrap();
        host.close(&token).unwrap();
        let replacement = host.open("same".to_owned()).unwrap();
        assert_ne!(token, replacement);
        call.reply.send(Ok(empty())).unwrap();
        replacement
    });
    assert!(matches!(result.unwrap(), AsrUpdate::Ignored));
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
    assert_eq!(budget.read().reserved_units, 0);
    assert!(host.prepare(&replacement, 1, "new".to_owned(), true).is_ok());
}

#[tokio::test]
async fn budget_denial_and_provider_error_preserve_exact_revision_for_retry() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let token = host.open("u".to_owned()).unwrap();
    let held = budget.admit_reserve(16_000).unwrap();
    let before_denial = budget.read();
    let denied = host.prepare(&token, 1, "final".to_owned(), true).unwrap().run().await;
    assert!(matches!(denied, Err(HostError::Llm(LlmError::BudgetDenied(_)))));
    assert!(calls.try_recv().is_err());
    assert_eq!(budget.read(), before_denial, "denial creates no reservation or spend");
    assert!(host.prepare(&token, 0, "older".to_owned(), true).is_err());
    assert!(host.prepare(&token, 1, "changed".to_owned(), true).is_err());
    budget.abort(&held.lease).unwrap();
    let failed = host.prepare(&token, 1, "final".to_owned(), true).unwrap();
    let (result, ()) = tokio::join!(failed.run(), async {
        let call = calls.recv().await.unwrap();
        assert_eq!(call.lease_id, "voice-test:metered:2", "denial issued no lease");
        call.reply.send(Err(RetryableLlmError::ServerError.into())).unwrap();
    });
    assert!(matches!(result, Err(HostError::Llm(LlmError::Retryable(RetryableLlmError::ServerError)))));
    assert_eq!(budget.read().reserved_units, 0);
    assert_eq!(budget.read().used_units, 0);
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
    assert!(host.prepare(&token, 1, "changed".to_owned(), true).is_err());
    let retry = host.prepare(&token, 1, "final".to_owned(), true).unwrap();
    let (result, ()) = tokio::join!(retry.run(), async {
        calls.recv().await.unwrap().reply.send(Ok(empty())).unwrap();
    });
    let AsrUpdate::Final(request) = result.unwrap() else { panic!("final") };
    assert_eq!(request.transcript, "final");
    assert_eq!(vault.retrieval_runs(200).unwrap().len(), 1);
    assert!(host.lock().unwrap().open.is_none());
}

#[tokio::test]
async fn dropped_future_and_shutdown_release_reservation_without_consuming_observation() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let token = host.open("u".to_owned()).unwrap();
    let mut work = Box::pin(host.prepare(&token, 1, "pending".to_owned(), true).unwrap().run());
    let call = tokio::select! {
        result = &mut work => panic!("unexpected completion: {result:?}"),
        call = calls.recv() => call.unwrap(),
    };
    drop(work);
    assert!(call.reply.send(Ok(empty())).is_err(), "provider receiver was cancelled");
    assert_eq!(budget.read().reserved_units, 0);
    let work = host.prepare(&token, 1, "pending".to_owned(), true).unwrap();
    let (result, ()) = tokio::join!(work.run(), async {
        let call = calls.recv().await.unwrap();
        host.shutdown.trigger();
        // Both branches become ready: lifecycle cancellation wins.
        let _ = call.reply.send(Ok(empty()));
    });
    assert!(matches!(result, Err(HostError::Stopped)));
    assert_eq!(budget.read().reserved_units, 0);
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
}

#[tokio::test]
async fn malformed_truncated_and_injected_responses_never_retrieve() {
    for value in [
        json!({"entity_labels": [], "salient_terms": [], "query_vector": []}),
        json!({"entity_labels": [" "], "salient_terms": []}),
        json!({"entity_labels": [], "salient_terms": ["a".repeat(129)]}),
        json!({"entity_labels": vec!["label"; 17], "salient_terms": []}),
        json!({"entity_labels": []}),
        json!({"entity_labels": [42], "salient_terms": []}),
    ] {
        let (_dir, vault, host, budget, mut calls) = fixture();
        let token = host.open("u".to_owned()).unwrap();
        let work = host.prepare(&token, 1, "text".to_owned(), true).unwrap();
        let (result, ()) = tokio::join!(work.run(), async {
            calls.recv().await.unwrap().reply.send(Ok(response(value))).unwrap();
        });
        assert!(matches!(result, Err(HostError::InvalidResponse)));
        assert!(vault.retrieval_runs(200).unwrap().is_empty());
        assert_eq!(budget.read().used_units, 7, "malformed provider work still settles");
        assert_eq!(budget.read().reserved_units, 0);
        let retry = host.prepare(&token, 1, "text".to_owned(), true).unwrap();
        let (result, ()) = tokio::join!(retry.run(), async {
            let call = calls.recv().await.unwrap();
            assert_eq!(call.lease_id, "voice-test:metered:2");
            call.reply.send(Ok(empty())).unwrap();
        });
        assert!(matches!(result.unwrap(), AsrUpdate::Final(_)));
        assert_eq!(budget.read().used_units, 14, "retry adds to malformed work");
        assert_eq!(budget.read().reserved_units, 0);
    }
    let (_dir, vault, host, _, mut calls) = fixture();
    let token = host.open("u".to_owned()).unwrap();
    let work = host.prepare(&token, 1, "text".to_owned(), true).unwrap();
    let (result, ()) = tokio::join!(work.run(), async {
        let mut truncated = empty();
        truncated.finish_reason = FinishReason::Length;
        calls.recv().await.unwrap().reply.send(Ok(truncated)).unwrap();
    });
    assert!(matches!(result, Err(HostError::InvalidResponse)));
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
}

#[tokio::test]
async fn distinct_successful_extractions_charge_each_real_call() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let token = host.open("u".to_owned()).unwrap();
    for revision in 1..=2 {
        let work = host.prepare(&token, revision, format!("text {revision}"), false).unwrap();
        let (result, ()) = tokio::join!(work.run(), async {
            let call = calls.recv().await.unwrap();
            assert_eq!(call.lease_id, format!("voice-test:metered:{revision}"));
            assert_eq!(budget.read().reserved_units, 8_000);
            call.reply.send(Ok(empty())).unwrap();
        });
        let AsrUpdate::Partial(partial) = result.unwrap() else { panic!("partial") };
        assert_eq!(partial.decision, SpeculativeFireDecision::SkippedEmptySignature);
        assert_eq!(budget.read().used_units, revision * 7);
        assert_eq!(budget.read().reserved_units, 0);
    }
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
}
