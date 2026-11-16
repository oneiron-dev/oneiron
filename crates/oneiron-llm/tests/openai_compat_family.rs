//! L9-25 PR 4 (ARCH-0036 `#adapters`, MED-1 = A): the OpenAI-compatible media
//! backend splits by family over one shared client. The text family keeps the
//! embedding backend: it sends embeddings on their own path, and refuses every
//! other family's call before anything is sent.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::llm::media::{AiOperation, MediaBackend, MediaPart, MediaRequest};
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelTierRef, ResponseFormat, TierPrecedence,
};
use oneiron::{BudgetLease, FatalLlmError, LlmError, ModelId, ModelLocality};
use oneiron_llm::openai_compat::{
    OpenAiEmbedBackend, OpenAiMediaClient, OpenAiMediaHttpRequest, OpenAiMediaHttpResponse,
    OpenAiMediaMethod, OpenAiMediaTransport, OpenAiMediaTransportFuture,
};
use serde_json::{Value, json};

const MODEL: &str = "fake/media@v1";

/// The exchanges a transport was sent: each one's method and path.
type Sent = Arc<Mutex<Vec<(OpenAiMediaMethod, String)>>>;

/// A transport that answers every request with one canned JSON reply and
/// records each request it was sent.
struct Recording {
    sent: Sent,
    reply: Value,
}

impl OpenAiMediaTransport for Recording {
    fn execute<'a>(
        &'a self,
        request: OpenAiMediaHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiMediaTransportFuture<'a> {
        self.sent
            .lock()
            .expect("sent")
            .push((request.method, request.path));
        let body = serde_json::to_vec(&self.reply).expect("reply");
        Box::pin(async move {
            Ok(OpenAiMediaHttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body,
            })
        })
    }
}

fn backend(reply: Value) -> (OpenAiEmbedBackend<Recording>, Sent) {
    let sent = Sent::default();
    let transport = Recording {
        sent: Arc::clone(&sent),
        reply,
    };
    let models = BTreeMap::from([(ModelId::new(MODEL).expect("model"), "wire-model".to_owned())]);
    let client = OpenAiMediaClient::new(transport, models, "https://media.example".to_owned());
    (OpenAiEmbedBackend::new(Arc::new(client)), sent)
}

fn ready<F: Future>(future: F) -> F::Output {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the fake transport answers at once"),
    }
}

/// A call of `operation` with the one part its own family's builder takes.
fn call(operation: AiOperation) -> MediaRequest {
    let part = match operation {
        AiOperation::Transcribe => MediaPart::Audio {
            media_type: "audio/wav".to_owned(),
            bytes: vec![1, 2, 3],
        },
        _ => MediaPart::Text {
            text: "a lighthouse at dusk".to_owned(),
        },
    };
    let purpose = CallPurpose::Other {
        name: "openai-compat-family".to_owned(),
    };
    MediaRequest {
        model: ModelId::new(MODEL).expect("model"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("media".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
            host_keyless: false,
            host_paid: false,
        },
        operation,
        parts: vec![part],
        references: Vec::new(),
        mask: None,
        params: BTreeMap::new(),
        voice: None,
    }
}

#[test]
fn the_embedding_backend_refuses_every_other_familys_call_unsent() {
    let (backend, sent) = backend(json!({}));
    let lease = BudgetLease::for_test("openai-compat-embedding");
    let refused: Result<(), LlmError> = Err(FatalLlmError::InvalidRequest.into());
    for operation in [
        AiOperation::Image,
        AiOperation::Video,
        AiOperation::Speech,
        AiOperation::Transcribe,
        AiOperation::Text,
    ] {
        assert_eq!(
            backend.preflight(&call(operation)),
            refused,
            "{operation:?}"
        );
        let run = ready(backend.run(call(operation), &lease)).map(|_| ());
        assert_eq!(run, refused, "{operation:?}");
        let progress = ready(backend.run_progress_released(call(operation), &lease, None));
        assert!(progress.is_err(), "{operation:?}");
    }
    assert_eq!(*sent.lock().expect("sent"), Vec::new(), "nothing was sent");
}

#[test]
fn the_embedding_backend_sends_embeddings_on_their_own_path() {
    let (backend, sent) = backend(json!({
        "data": [{ "index": 0, "embedding": [0.5, 0.25] }],
        "usage": { "prompt_tokens": 4 },
    }));
    let lease = BudgetLease::for_test("openai-compat-embedding");
    assert_eq!(backend.preflight(&call(AiOperation::Embed)), Ok(()));

    let embedded = ready(backend.run(call(AiOperation::Embed), &lease)).expect("embedding");
    assert_eq!(
        embedded.parts,
        vec![MediaPart::Embedding {
            vector: vec![0.5, 0.25],
        }]
    );
    assert_eq!(embedded.usage.input_tokens, 4);
    assert_eq!(
        embedded.usage.raw_provider["remote_runtime"],
        json!("wire-model@https://media.example")
    );
    assert_eq!(
        *sent.lock().expect("sent"),
        vec![(OpenAiMediaMethod::Post, "/v1/embeddings".to_owned())]
    );
}
