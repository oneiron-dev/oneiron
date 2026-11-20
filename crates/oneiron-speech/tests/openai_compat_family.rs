//! L9-25 PR 4 (ARCH-0036 `#adapters`, MED-1 = A): the OpenAI-compatible media
//! backend splits by family over one shared client. The speech family's two
//! backends each send their own call on its own path, and refuse every other
//! call before anything is sent.
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
    OpenAiMediaClient, OpenAiMediaHttpRequest, OpenAiMediaHttpResponse, OpenAiMediaMethod,
    OpenAiMediaTransport, OpenAiMediaTransportFuture,
};
use oneiron_speech::asr::openai_compat::OpenAiAsrBackend;
use oneiron_speech::tts::openai_compat::OpenAiTtsBackend;
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

fn client(reply: Value) -> (Arc<OpenAiMediaClient<Recording>>, Sent) {
    let sent = Sent::default();
    let transport = Recording {
        sent: Arc::clone(&sent),
        reply,
    };
    let models = BTreeMap::from([(ModelId::new(MODEL).expect("model"), "wire-model".to_owned())]);
    let client = OpenAiMediaClient::new(transport, models, "https://media.example".to_owned());
    (Arc::new(client), sent)
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

const OPERATIONS: [AiOperation; 6] = [
    AiOperation::Image,
    AiOperation::Video,
    AiOperation::Speech,
    AiOperation::Transcribe,
    AiOperation::Embed,
    AiOperation::Text,
];

#[test]
fn the_speech_backends_refuse_every_call_but_their_own_unsent() {
    let (shared, sent) = client(json!({}));
    let speech = OpenAiTtsBackend::new(Arc::clone(&shared));
    let transcription = OpenAiAsrBackend::new(shared);
    let lease = BudgetLease::for_test("openai-compat-speech");
    let refused: Result<(), LlmError> = Err(FatalLlmError::InvalidRequest.into());
    for (backend, own) in [
        (&speech as &dyn MediaBackend, AiOperation::Speech),
        (&transcription as &dyn MediaBackend, AiOperation::Transcribe),
    ] {
        for operation in OPERATIONS.into_iter().filter(|operation| *operation != own) {
            assert_eq!(
                backend.preflight(&call(operation)),
                refused,
                "{own:?} {operation:?}"
            );
            let run = ready(backend.run(call(operation), &lease)).map(|_| ());
            assert_eq!(run, refused, "{own:?} {operation:?}");
            let progress = ready(backend.run_progress_released(call(operation), &lease, None));
            assert!(progress.is_err(), "{own:?} {operation:?}");
        }
    }
    assert_eq!(*sent.lock().expect("sent"), Vec::new(), "nothing was sent");
}

#[test]
fn the_speech_backends_send_speech_and_transcription_on_their_own_paths() {
    let (shared, sent) = client(json!({ "text": "a lighthouse at dusk" }));
    let speech = OpenAiTtsBackend::new(Arc::clone(&shared));
    let transcription = OpenAiAsrBackend::new(shared);
    let lease = BudgetLease::for_test("openai-compat-speech");
    assert_eq!(speech.preflight(&call(AiOperation::Speech)), Ok(()));
    assert_eq!(
        transcription.preflight(&call(AiOperation::Transcribe)),
        Ok(())
    );

    let spoken = ready(speech.run(call(AiOperation::Speech), &lease)).expect("speech");
    // No content type came back, so the asked format names the audio.
    assert!(
        matches!(&spoken.parts[..], [MediaPart::Audio { media_type, .. }] if media_type == "audio/mpeg"),
        "{:?}",
        spoken.parts
    );
    assert_eq!(spoken.usage.characters, 20);
    let heard = ready(transcription.run(call(AiOperation::Transcribe), &lease)).expect("heard");
    assert_eq!(
        heard.parts,
        vec![MediaPart::Text {
            text: "a lighthouse at dusk".to_owned(),
        }]
    );

    assert_eq!(
        *sent.lock().expect("sent"),
        vec![
            (OpenAiMediaMethod::Post, "/v1/audio/speech".to_owned()),
            (
                OpenAiMediaMethod::Post,
                "/v1/audio/transcriptions".to_owned()
            ),
        ]
    );
}
