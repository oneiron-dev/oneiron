//! UC-16 (census FD-07): a released media call re-checks its caller's
//! release before it sends. A generation call whose release refuses sends
//! nothing and answers the release's own not-sent refusal, as a speech call
//! does; one its release allows sends once.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::llm::media::{AiOperation, MediaBackend, MediaPart, MediaRequest};
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelTierRef, ResponseFormat, TierPrecedence,
};
use oneiron::{BudgetLease, LlmError, LlmResult, ModelId, ModelLocality, RetryableLlmError};
use oneiron_gen::gemini::{
    GeminiMediaBackend, GeminiMediaFuture, GeminiMediaHttpRequest, GeminiMediaHttpResponse,
    GeminiMediaTransport,
};
use oneiron_gen::openai_compat::OpenAiGenBackend;
use oneiron_llm::openai_compat::{
    OpenAiMediaClient, OpenAiMediaHttpRequest, OpenAiMediaHttpResponse, OpenAiMediaTransport,
    OpenAiMediaTransportFuture,
};
use serde_json::{Value, json};

const MODEL: &str = "fake/media@v1";
/// The stage a media release refusal names, as the ladder reads it.
const MEDIA_RELEASE: &str = "media_release";

/// The paths a fake transport was sent, in order.
type Sent = Arc<Mutex<Vec<String>>>;

fn reply(body: &Value) -> (u16, BTreeMap<String, String>, Vec<u8>) {
    (
        200,
        BTreeMap::new(),
        serde_json::to_vec(body).expect("reply"),
    )
}

/// An OpenAI-compatible transport that records each request and answers one
/// canned image.
struct OpenAiRecording {
    sent: Sent,
}

impl OpenAiMediaTransport for OpenAiRecording {
    fn execute<'a>(
        &'a self,
        request: OpenAiMediaHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiMediaTransportFuture<'a> {
        self.sent.lock().expect("sent").push(request.path);
        let (status, headers, body) = reply(&json!({ "data": [{ "b64_json": "AAAA" }] }));
        Box::pin(async move {
            Ok(OpenAiMediaHttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

/// A Gemini transport that records each request and answers one canned
/// image.
struct GeminiRecording {
    sent: Sent,
}

impl GeminiMediaTransport for GeminiRecording {
    fn execute<'a>(
        &'a self,
        request: GeminiMediaHttpRequest,
        _lease: &'a BudgetLease,
    ) -> GeminiMediaFuture<'a> {
        let path = match request {
            GeminiMediaHttpRequest::Post { path, .. } | GeminiMediaHttpRequest::Get { path } => {
                path
            }
            GeminiMediaHttpRequest::Fetch { uri } => uri,
        };
        self.sent.lock().expect("sent").push(path);
        let image = json!({ "inlineData": { "mimeType": "image/png", "data": "AAAA" } });
        let (status, headers, body) = reply(&json!({
            "candidates": [{ "content": { "parts": [image] } }]
        }));
        Box::pin(async move {
            Ok(GeminiMediaHttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

fn models() -> BTreeMap<ModelId, String> {
    BTreeMap::from([(ModelId::new(MODEL).expect("model"), "wire-model".to_owned())])
}

fn openai() -> (OpenAiGenBackend<OpenAiRecording>, Sent) {
    let sent = Sent::default();
    let transport = OpenAiRecording {
        sent: Arc::clone(&sent),
    };
    let client = OpenAiMediaClient::new(transport, models(), "https://media.example".to_owned());
    (OpenAiGenBackend::new(Arc::new(client)), sent)
}

fn gemini() -> (GeminiMediaBackend<GeminiRecording>, Sent) {
    let sent = Sent::default();
    let transport = GeminiRecording {
        sent: Arc::clone(&sent),
    };
    (GeminiMediaBackend::new(transport, models()), sent)
}

fn ready<F: Future>(future: F) -> F::Output {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the fake transport answers at once"),
    }
}

/// An image generation call: one prompt, no references.
fn image_call() -> MediaRequest {
    let purpose = CallPurpose::Other {
        name: "media-release".to_owned(),
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
        operation: AiOperation::Image,
        parts: vec![MediaPart::Text {
            text: "a lighthouse at dusk".to_owned(),
        }],
        references: Vec::new(),
        mask: None,
        params: BTreeMap::new(),
        voice: None,
    }
}

/// A release that refuses, as a revoked media credential's does, counting
/// each time it is asked.
fn refusing(asked: &AtomicUsize) -> impl Fn() -> LlmResult<()> + Sync + '_ {
    move || -> LlmResult<()> {
        asked.fetch_add(1, Ordering::SeqCst);
        Err(RetryableLlmError::not_sent(MEDIA_RELEASE, "the media credential was revoked").into())
    }
}

fn refused_by_release(error: &LlmError) -> bool {
    matches!(error, LlmError::Retryable(retry) if retry.is_not_sent_stage(MEDIA_RELEASE))
}

#[test]
fn an_openai_compatible_image_call_whose_release_refuses_sends_nothing() {
    let (backend, sent) = openai();
    let lease = BudgetLease::for_test("media-release-openai");
    let asked = AtomicUsize::new(0);
    let release = refusing(&asked);
    let answer = ready(backend.run_progress_released(image_call(), &lease, Some(&release)));
    let stopped = answer.expect_err("a refused release stops the call");
    assert!(
        refused_by_release(&stopped.error),
        "the release's own refusal: {:?}",
        stopped.error
    );
    assert!(stopped.progress.is_empty(), "nothing completed");
    assert!(asked.load(Ordering::SeqCst) >= 1, "the release was asked");
    assert_eq!(
        *sent.lock().expect("sent"),
        Vec::<String>::new(),
        "nothing was sent"
    );
}

#[test]
fn a_gemini_image_call_whose_release_refuses_sends_nothing() {
    let (backend, sent) = gemini();
    let lease = BudgetLease::for_test("media-release-gemini");
    let asked = AtomicUsize::new(0);
    let release = refusing(&asked);
    let answer = ready(backend.run_progress_released(image_call(), &lease, Some(&release)));
    let stopped = answer.expect_err("a refused release stops the call");
    assert!(
        refused_by_release(&stopped.error),
        "the release's own refusal: {:?}",
        stopped.error
    );
    assert!(stopped.progress.is_empty(), "nothing completed");
    assert!(asked.load(Ordering::SeqCst) >= 1, "the release was asked");
    assert_eq!(
        *sent.lock().expect("sent"),
        Vec::<String>::new(),
        "nothing was sent"
    );
}

#[test]
fn an_image_call_its_release_allows_sends_once_and_answers() {
    let allows = || -> LlmResult<()> { Ok(()) };
    let image = vec![MediaPart::Image {
        media_type: "image/png".to_owned(),
        bytes: vec![0, 0, 0],
    }];

    let (backend, sent) = openai();
    let lease = BudgetLease::for_test("media-release-openai-allowed");
    let answer = ready(backend.run_progress_released(image_call(), &lease, Some(&allows)))
        .map_err(|stopped| stopped.error)
        .expect("an allowed image call answers");
    assert_eq!(answer.parts, image);
    assert_eq!(
        *sent.lock().expect("sent"),
        vec!["/v1/images/generations".to_owned()]
    );

    let (backend, sent) = gemini();
    let lease = BudgetLease::for_test("media-release-gemini-allowed");
    let answer = ready(backend.run_progress_released(image_call(), &lease, Some(&allows)))
        .map_err(|stopped| stopped.error)
        .expect("an allowed image call answers");
    assert_eq!(answer.parts, image);
    assert_eq!(
        *sent.lock().expect("sent"),
        vec!["/v1beta/models/wire-model:generateContent".to_owned()]
    );
}
