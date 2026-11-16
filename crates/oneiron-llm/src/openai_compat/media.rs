//! The OpenAI-compatible media wire's shared seam, and its embeddings
//! (`/v1/embeddings`). One provider's [`OpenAiMediaClient`] sends every media
//! call; each family's backend speaks its own calls over it (ARCH-0036
//! `#adapters`): images and video jobs are `oneiron_gen::openai_compat`'s,
//! speech and transcription `oneiron_speech::{tts, asr}::openai_compat`'s,
//! and embeddings [`OpenAiEmbedBackend`]'s. HTTP and authentication stay
//! host-owned: the host's transport sends one request per call, so a run's
//! media gate may wrap each backend.
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use oneiron::llm::BrokerIsolation;
use oneiron::llm::media::{
    AiOperation, InterruptedMediaCall, MediaBackend, MediaFuture, MediaPart, MediaProgressFuture,
    MediaRequest, MediaResponse, MediaUsage,
};
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId};
use serde_json::{Value, json};

// FIX 866: each provider's own embedding shape.
mod embed_shape;
mod prepare;

use embed_shape::EmbedDocument;
pub use embed_shape::EmbedShape;
use prepare::prepare_embed;
pub use prepare::{audio_extension, form_fields, only_text, with_params};

/// Multipart parts are distinct so the host sends each ordered reference as `image[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiImagePart {
    pub name: &'static str,
    pub filename: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAiMediaMethod {
    Get,
    Post,
    Delete,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OpenAiMediaBody {
    Empty,
    Json(Value),
    /// Form fields and ordered file parts, each under its own part name.
    Multipart {
        fields: BTreeMap<String, String>,
        files: Vec<OpenAiImagePart>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiMediaHttpRequest {
    pub method: OpenAiMediaMethod,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: OpenAiMediaBody,
}

/// A finished exchange, its body as it came: JSON, or media bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiMediaHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl OpenAiMediaHttpResponse {
    /// The body as JSON; `null` when it is not JSON.
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The media type the reply's `content-type` header names, without its
    /// parameters.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .and_then(|(_, value)| value.split(';').next())
            .map(str::trim)
    }

    /// The provider's refusal, classified as a chat refusal is.
    fn refused(&self) -> Option<LlmError> {
        (!(200..300).contains(&self.status))
            .then(|| super::classify_openai_status(self.status, &self.headers, &self.json()))
    }
}

pub type OpenAiMediaTransportFuture<'a> =
    Pin<Box<dyn Future<Output = LlmResult<OpenAiMediaHttpResponse>> + Send + 'a>>;

pub trait OpenAiMediaTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: OpenAiMediaHttpRequest,
        lease: &'a BudgetLease,
    ) -> OpenAiMediaTransportFuture<'a>;

    /// [`Self::execute`] with the caller's release, for a transport that retries.
    fn execute_released<'a>(
        &'a self,
        request: OpenAiMediaHttpRequest,
        lease: &'a BudgetLease,
        _release: Option<oneiron::llm::DispatchRelease<'a>>,
    ) -> OpenAiMediaTransportFuture<'a> {
        self.execute(request, lease)
    }

    /// Every check the transport makes before it sends, with no I/O (a
    /// broker it cannot reach, a key its custody door would refuse); `Ok`,
    /// the default, for a transport that checks nothing first.
    fn preflight(&self) -> LlmResult<()> {
        Ok(())
    }

    /// How the credential broker that sends for this transport is kept apart
    /// from the daemon; `None`, the default, when no broker does.
    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        None
    }
}

/// One provider's media client. It serves each engine model it was built
/// for by the name the provider knows it by, at the provider's configured
/// `endpoint` (its base URL). Every family backend of the provider sends
/// through the one client it shares.
pub struct OpenAiMediaClient<T> {
    transport: T,
    wire_models: BTreeMap<ModelId, String>,
    endpoint: String,
}

impl<T> OpenAiMediaClient<T> {
    #[must_use]
    pub fn new(transport: T, wire_models: BTreeMap<ModelId, String>, endpoint: String) -> Self {
        Self {
            transport,
            wire_models,
            endpoint,
        }
    }

    /// The transport every call of this provider goes out on.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The provider's name for `model`; a model this client was not built
    /// for is refused.
    pub fn wire_model(&self, model: &ModelId) -> LlmResult<String> {
        self.wire_models
            .get(model)
            .cloned()
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }
}

impl<T: OpenAiMediaTransport> OpenAiMediaClient<T> {
    /// One exchange; a provider refusal is classified as a chat refusal is.
    pub async fn send(
        &self,
        method: OpenAiMediaMethod,
        path: String,
        body: OpenAiMediaBody,
        lease: &BudgetLease,
    ) -> LlmResult<OpenAiMediaHttpResponse> {
        self.send_released(method, path, body, lease, None).await
    }

    /// [`Self::send`] after the caller's release check.
    pub async fn send_released(
        &self,
        method: OpenAiMediaMethod,
        path: String,
        body: OpenAiMediaBody,
        lease: &BudgetLease,
        release: Option<oneiron::llm::DispatchRelease<'_>>,
    ) -> LlmResult<OpenAiMediaHttpResponse> {
        self.send_with_headers(method, path, body, BTreeMap::new(), lease, release)
            .await
    }

    /// [`Self::send_released`] with the call's own headers.
    pub async fn send_with_headers(
        &self,
        method: OpenAiMediaMethod,
        path: String,
        body: OpenAiMediaBody,
        headers: BTreeMap<String, String>,
        lease: &BudgetLease,
        release: Option<oneiron::llm::DispatchRelease<'_>>,
    ) -> LlmResult<OpenAiMediaHttpResponse> {
        if let Some(release) = release {
            release()?;
        }
        let reply = self
            .transport
            .execute_released(
                OpenAiMediaHttpRequest {
                    method,
                    path,
                    headers,
                    body,
                },
                lease,
                release,
            )
            .await?;
        match reply.refused() {
            Some(error) => Err(error),
            None => Ok(reply),
        }
    }
}

/// One provider's embedding calls over its shared client.
pub struct OpenAiEmbedBackend<T> {
    client: Arc<OpenAiMediaClient<T>>,
    /// The shape its embedding endpoint speaks (FIX 866).
    embed_shape: EmbedShape,
}

impl<T> OpenAiEmbedBackend<T> {
    #[must_use]
    pub fn new(client: Arc<OpenAiMediaClient<T>>) -> Self {
        Self {
            client,
            embed_shape: EmbedShape::default(),
        }
    }

    /// This client with its embedding calls in `shape`, its provider's own
    /// (FIX 866); vLLM's chat form until one is named.
    #[must_use]
    pub fn with_embed_shape(mut self, shape: EmbedShape) -> Self {
        self.embed_shape = shape;
        self
    }
}

impl<T: OpenAiMediaTransport> OpenAiEmbedBackend<T> {
    async fn embed(&self, request: MediaRequest, lease: &BudgetLease) -> LlmResult<MediaResponse> {
        self.embed_released(request, lease, None).await
    }

    async fn embed_released(
        &self,
        request: MediaRequest,
        lease: &BudgetLease,
        release: Option<oneiron::llm::DispatchRelease<'_>>,
    ) -> LlmResult<MediaResponse> {
        let wire = self.client.wire_model(&request.model)?;
        // The whole call is checked before its first document is sent.
        let plan = prepare_embed(&request, &wire)?;
        // Texts go as one batch; a call with an image or audio part goes in
        // its provider's own shape (FIX 866), one vector per part, in order.
        let shape = self.embed_shape;
        let documents = shape.documents(&request, plan, &wire)?;
        let (mut vectors, mut tokens, mut raws, mut served) =
            (Vec::new(), 0, Vec::new(), Value::Null);
        let mut marks = Vec::new();
        for EmbedDocument { count, path, body } in documents {
            let body = OpenAiMediaBody::Json(Value::Object(body.into_iter().collect()));
            let reply = self
                .client
                .send_released(OpenAiMediaMethod::Post, path.into(), body, lease, release)
                .await?;
            let mut reply = reply.json();
            vectors.extend(
                shape
                    .vectors(&reply, count)
                    .ok_or(FatalLlmError::EmptyResponse)?,
            );
            let raw = shape.take_usage(&mut reply);
            tokens += shape.tokens(&raw);
            raws.push(raw);
            served = reply
                .get_mut("model")
                .map(Value::take)
                .unwrap_or(Value::Null);
            // FIX 7796: the device and runtime this reply names, if it names one, kept for the
            // host to read as its vectors' mark; never checked here.
            marks.push(
                reply
                    .get_mut("provenance")
                    .map(Value::take)
                    .unwrap_or(Value::Null),
            );
        }
        // One width for every vector: the `dimensions` asked for, else the
        // first one's.
        let width = request
            .params
            .get("dimensions")
            .and_then(Value::as_u64)
            .and_then(|width| usize::try_from(width).ok())
            .or_else(|| vectors.first().map(Vec::len));
        if vectors.iter().any(|vector| Some(vector.len()) != width) {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let raw = if raws.len() == 1 {
            raws.swap_remove(0)
        } else {
            Value::Array(raws)
        };
        let mut raw_provider = json!({ "usage": raw, "served_model": served });
        // FIX 8984: what a remote mark of these vectors names when no reply names a device, as
        // the text endpoint names one: the model as sent, at the configured endpoint.
        raw_provider["remote_runtime"] = json!(format!("{wire}@{}", self.client.endpoint));
        // One mark per request, in request order, as the usage is, when any reply named one.
        if marks.iter().any(|mark| !mark.is_null()) {
            raw_provider["provenance"] = if marks.len() == 1 {
                marks.swap_remove(0)
            } else {
                Value::Array(marks)
            };
        }
        Ok(MediaResponse {
            parts: vectors
                .into_iter()
                .map(|vector| MediaPart::Embedding { vector })
                .collect(),
            usage: MediaUsage {
                input_tokens: tokens,
                raw_provider,
                ..MediaUsage::default()
            },
            model: request.model,
        })
    }
}

/// Serves embeddings alone: every other call is another family's, and is
/// refused here with `InvalidRequest` before anything is sent.
impl<T: OpenAiMediaTransport> MediaBackend for OpenAiEmbedBackend<T> {
    /// A model this client was not built for, a call its send's own
    /// builders refuse (a voice, a param naming a field the adapter sets, an
    /// embedding document it cannot carry, FIX 8616), or its transport's
    /// refusal: all before the call's permit starts, so none of them is
    /// charged.
    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        request.validate_image_mask()?;
        let wire = self.client.wire_model(&request.model)?;
        // A voice is a speech call's alone.
        if request.voice.is_some() || request.operation != AiOperation::Embed {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let plan = prepare_embed(request, &wire)?;
        self.embed_shape.check(request, plan)?;
        self.client.transport().preflight()
    }

    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        self.client.transport().broker_isolation()
    }

    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move {
            request.validate_image_mask()?;
            // A voice is a speech call's alone; text rides the chat wire.
            if request.voice.is_some() || request.operation != AiOperation::Embed {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            self.embed(request, lease).await
        })
    }

    fn run_progress_released<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
        release: Option<oneiron::llm::DispatchRelease<'a>>,
    ) -> MediaProgressFuture<'a> {
        if request.operation != AiOperation::Embed {
            return self.run_progress(request, lease);
        }
        Box::pin(async move {
            if request.voice.is_some() {
                return Err(InterruptedMediaCall::nothing(
                    FatalLlmError::InvalidRequest.into(),
                ));
            }
            self.embed_released(request, lease, release)
                .await
                .map_err(InterruptedMediaCall::nothing)
        })
    }
}

/// One vector per input, in input order: each index once, each vector
/// numbers. Anything else is no answer.
fn indexed_vectors(body: &Value, count: usize) -> Option<Vec<Vec<f32>>> {
    let rows = body.get("data")?.as_array()?;
    if rows.len() != count {
        return None;
    }
    let mut vectors = vec![None; count];
    for row in rows {
        let index = usize::try_from(row.get("index")?.as_u64()?).ok()?;
        let vector = row
            .get("embedding")?
            .as_array()?
            .iter()
            .map(|value| value.as_f64().map(|value| value as f32))
            .collect::<Option<Vec<f32>>>()?;
        if vector.is_empty() || vectors.get(index)?.is_some() {
            return None;
        }
        vectors[index] = Some(vector);
    }
    vectors.into_iter().collect()
}
