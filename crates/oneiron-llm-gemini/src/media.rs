//! Gemini API media wires for the `ai.*` calls past text. An image is
//! `models/{model}:generateContent` asked for image output, its reference
//! images sent inline. A video is a Veo job: `models/{model}:predictLongRunning`
//! starts it, its operation is polled until done, and each clip is fetched
//! from the file URI the operation names. HTTP and authentication stay
//! host-owned: the host's transport sends one request per call, so a run's
//! media gate may wrap this backend.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::BrokerIsolation;
use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaFuture, MediaJobState, MediaPart, MediaRequest, MediaResponse,
    MediaUsage, ReferenceCompatibility,
};
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId, RetryableLlmError};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::{future::Future, pin::Pin};

mod prepare;

use prepare::{
    PreparedImage, PreparedVideo, VIDEO_REFERENCE_SLOTS, inline_image, prepare_image,
    prepare_video,
};

/// Finish reasons that mean the provider withheld the answer.
const FILTERED: [&str; 6] = [
    "SAFETY",
    "IMAGE_SAFETY",
    "PROHIBITED_CONTENT",
    "BLOCKLIST",
    "SPII",
    "IMAGE_PROHIBITED_CONTENT",
];

/// One media exchange. Paths sit under the API's own root (`/v1beta/...`).
#[derive(Debug, Clone, PartialEq)]
pub enum GeminiMediaHttpRequest {
    Post {
        path: String,
        body: Value,
    },
    Get {
        path: String,
    },
    /// A file the provider named by its full URI: a finished job's clip.
    /// The host sends the key to the provider's own origin only.
    Fetch {
        uri: String,
    },
}

/// A finished exchange, its body as it came: JSON, or media bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct GeminiMediaHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl GeminiMediaHttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .and_then(|(_, value)| value.split(';').next())
            .map(str::trim)
    }
}

pub type GeminiMediaFuture<'a> =
    Pin<Box<dyn Future<Output = LlmResult<GeminiMediaHttpResponse>> + Send + 'a>>;

pub trait GeminiMediaTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: GeminiMediaHttpRequest,
        lease: &'a BudgetLease,
    ) -> GeminiMediaFuture<'a>;

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

/// One Gemini API media client. It serves each engine model it was built
/// for by the name the provider knows it by.
pub struct GeminiMediaBackend<T> {
    transport: T,
    wire_models: BTreeMap<ModelId, String>,
}

impl<T> GeminiMediaBackend<T> {
    #[must_use]
    pub fn new(transport: T, wire_models: BTreeMap<ModelId, String>) -> Self {
        Self {
            transport,
            wire_models,
        }
    }

    /// The provider's model name, a single path segment.
    fn wire_model(&self, model: &ModelId) -> LlmResult<&str> {
        self.wire_models
            .get(model)
            .map(String::as_str)
            .filter(|wire| {
                !wire.is_empty()
                    && wire
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }
}

impl<T: GeminiMediaTransport> GeminiMediaBackend<T> {
    async fn send(
        &self,
        request: GeminiMediaHttpRequest,
        lease: &BudgetLease,
    ) -> LlmResult<GeminiMediaHttpResponse> {
        let reply = self.transport.execute(request, lease).await?;
        if (200..300).contains(&reply.status) {
            Ok(reply)
        } else {
            Err(super::wire::classify_media_status(
                reply.status,
                &reply.headers,
                &reply.json(),
            ))
        }
    }

    async fn image(&self, request: MediaRequest, lease: &BudgetLease) -> LlmResult<MediaResponse> {
        let wire = self.wire_model(&request.model)?;
        let PreparedImage { prompt, config } = prepare_image(&request)?;
        // Every reference goes, in order (FIX 8612): none is dropped or cut.
        let mut parts = vec![json!({ "text": prompt })];
        for reference in &request.references {
            parts.push(inline_image(reference).ok_or(FatalLlmError::InvalidRequest)?);
        }
        let body = json!({
            "contents": [{ "role": "user", "parts": parts }],
            "generationConfig": config,
        });
        let reply = self
            .send(
                GeminiMediaHttpRequest::Post {
                    path: format!("/v1beta/models/{wire}:generateContent"),
                    body,
                },
                lease,
            )
            .await?;
        image_response(&reply.json(), request.model)
    }

    async fn submit_job(&self, request: MediaRequest, lease: &BudgetLease) -> LlmResult<String> {
        let wire = self.wire_model(&request.model)?;
        let PreparedVideo { prompt, parameters } = prepare_video(&request)?;
        let mut instance = json!({ "prompt": prompt });
        // The job's one start frame, when it has one; the builder refused a
        // call with more, so nothing is cut here.
        match request.references.as_slice() {
            [] => {}
            [start] => {
                instance["image"] = inline_image(start).ok_or(FatalLlmError::InvalidRequest)?;
            }
            _ => return Err(FatalLlmError::InvalidRequest.into()),
        }
        let body = json!({
            "instances": [instance],
            "parameters": parameters,
        });
        let reply = self
            .send(
                GeminiMediaHttpRequest::Post {
                    path: format!("/v1beta/models/{wire}:predictLongRunning"),
                    body,
                },
                lease,
            )
            .await?;
        reply
            .json()
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| operation_name(name))
            .map(str::to_owned)
            .ok_or_else(|| FatalLlmError::EmptyResponse.into())
    }

    async fn poll_job(
        &self,
        model: &ModelId,
        job: &str,
        lease: &BudgetLease,
    ) -> LlmResult<MediaJobState> {
        if !operation_name(job) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let status = self
            .send(
                GeminiMediaHttpRequest::Get {
                    path: format!("/v1beta/{job}"),
                },
                lease,
            )
            .await?
            .json();
        if status.get("done").and_then(Value::as_bool) != Some(true) {
            return Ok(MediaJobState::Running { progress: None });
        }
        let answer = status.pointer("/response/generateVideoResponse");
        let filtered = answer
            .and_then(|answer| answer.get("raiMediaFilteredCount"))
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0);
        if let Some(error) = status.get("error") {
            let message = error.get("message").and_then(Value::as_str).unwrap_or("");
            let moderated = filtered || message.to_ascii_lowercase().contains("safety");
            let error: LlmError = if moderated {
                FatalLlmError::ContentFiltered.into()
            } else {
                FatalLlmError::EmptyResponse.into()
            };
            return Ok(MediaJobState::Failed { error });
        }
        let uris = answer
            .and_then(|answer| answer.get("generatedSamples"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|sample| sample.pointer("/video/uri").and_then(Value::as_str))
            .collect::<Vec<_>>();
        if uris.is_empty() {
            let error = if filtered {
                FatalLlmError::ContentFiltered
            } else {
                FatalLlmError::EmptyResponse
            };
            return Ok(MediaJobState::Failed {
                error: error.into(),
            });
        }
        let mut parts = Vec::with_capacity(uris.len());
        for uri in uris {
            let clip = self
                .send(
                    GeminiMediaHttpRequest::Fetch {
                        uri: uri.to_owned(),
                    },
                    lease,
                )
                .await?;
            if clip.body.is_empty() {
                return Err(FatalLlmError::EmptyResponse.into());
            }
            let media_type = clip
                .content_type()
                .filter(|kind| kind.starts_with("video/"))
                .unwrap_or("video/mp4")
                .to_owned();
            parts.push(MediaPart::Video {
                media_type,
                bytes: clip.body,
                uri: None,
            });
        }
        // The operation names no clip length; the run charges the call's
        // reservation.
        Ok(MediaJobState::Done {
            response: MediaResponse {
                parts,
                usage: MediaUsage {
                    raw_provider: json!({ "job": job, "metadata": status.get("metadata") }),
                    ..MediaUsage::default()
                },
                model: model.clone(),
            },
        })
    }
}

impl<T: GeminiMediaTransport> MediaBackend for GeminiMediaBackend<T> {
    /// A Veo job carries one start frame; an image call every reference.
    fn reference_compatibility(&self, request: &MediaRequest) -> ReferenceCompatibility {
        match request.operation {
            AiOperation::Video => ReferenceCompatibility::Slots {
                slots: VIDEO_REFERENCE_SLOTS,
            },
            _ => ReferenceCompatibility::Whole,
        }
    }

    /// A model this client was not built for, a call its send's own
    /// builders refuse (an operation this wire does not serve, no prompt, a
    /// param that cannot be sent, FIX 8613), or its transport's refusal: all
    /// before the call's permit starts, so none of them is charged.
    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        self.wire_model(&request.model)?;
        match request.operation {
            AiOperation::Image => {
                prepare_image(request)?;
            }
            AiOperation::Video => {
                prepare_video(request)?;
            }
            _ => return Err(FatalLlmError::InvalidRequest.into()),
        }
        self.transport.preflight()
    }

    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        self.transport.broker_isolation()
    }

    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move {
            if request.voice.is_some() {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            match request.operation {
                AiOperation::Image => self.image(request, lease).await,
                // A video is a job; the rest are not this wire's.
                _ => Err(FatalLlmError::InvalidRequest.into()),
            }
        })
    }

    fn submit<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, String> {
        Box::pin(self.submit_job(request, lease))
    }

    fn poll<'a>(
        &'a self,
        model: &'a ModelId,
        job: &'a str,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaJobState> {
        Box::pin(self.poll_job(model, job, lease))
    }

    /// The Gemini API documents no way to stop a Veo operation: the job is
    /// let go here, and the provider's run ends unread.
    fn cancel<'a>(
        &'a self,
        _model: &'a ModelId,
        job: &'a str,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, ()> {
        Box::pin(async move {
            if operation_name(job) {
                Ok(())
            } else {
                Err(FatalLlmError::InvalidRequest.into())
            }
        })
    }
}

/// A generateContent answer as image parts, then any text the model wrote
/// beside them, counted by its tokens.
fn image_response(body: &Value, model: ModelId) -> LlmResult<MediaResponse> {
    let blocked = body.pointer("/promptFeedback/blockReason").is_some();
    let candidates = body
        .get("candidates")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let filtered = blocked
        || candidates.iter().any(|candidate| {
            candidate
                .get("finishReason")
                .and_then(Value::as_str)
                .is_some_and(|reason| FILTERED.contains(&reason))
        });
    let mut images = Vec::new();
    let mut texts = Vec::new();
    for part in candidates
        .iter()
        .filter_map(|candidate| candidate.pointer("/content/parts"))
        .filter_map(Value::as_array)
        .flatten()
    {
        if part.get("thought").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if let Some(inline) = part.get("inlineData").or_else(|| part.get("inline_data")) {
            let media_type = inline
                .get("mimeType")
                .or_else(|| inline.get("mime_type"))
                .and_then(Value::as_str)
                .filter(|kind| kind.starts_with("image/"));
            let data = inline.get("data").and_then(Value::as_str);
            if let (Some(media_type), Some(data)) = (media_type, data) {
                // Kept whole, however large (FIX 8615): its room is allocated
                // fallibly, and only memory this machine cannot give ends
                // the call.
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(data.len().div_ceil(4) * 3)
                    .map_err(|_| RetryableLlmError::ServerError)?;
                STANDARD
                    .decode_vec(data, &mut bytes)
                    .map_err(|_| FatalLlmError::EmptyResponse)?;
                if !bytes.is_empty() {
                    images.push(MediaPart::Image {
                        media_type: media_type.to_owned(),
                        bytes,
                    });
                }
            }
        } else if let Some(text) = part.get("text").and_then(Value::as_str)
            && !text.trim().is_empty()
        {
            texts.push(MediaPart::Text {
                text: text.to_owned(),
            });
        }
    }
    if images.is_empty() {
        return Err(if filtered {
            FatalLlmError::ContentFiltered.into()
        } else {
            FatalLlmError::EmptyResponse.into()
        });
    }
    let metadata = body.get("usageMetadata");
    let count = |key: &str| {
        metadata
            .and_then(|metadata| metadata.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let usage = MediaUsage {
        input_tokens: count("promptTokenCount"),
        output_tokens: count("candidatesTokenCount").saturating_add(count("thoughtsTokenCount")),
        images: images.len() as u64,
        raw_provider: json!({
            "usageMetadata": metadata,
            "modelVersion": body.get("modelVersion"),
            "responseId": body.get("responseId"),
        }),
        ..MediaUsage::default()
    };
    images.extend(texts);
    Ok(MediaResponse {
        parts: images,
        usage,
        model,
    })
}

/// A Veo operation's name, as its poll path takes it:
/// `models/{model}/operations/{id}`, plain segments only.
fn operation_name(name: &str) -> bool {
    let segments = name.split('/').collect::<Vec<_>>();
    name.len() <= 512
        && segments.len() == 4
        && segments[0] == "models"
        && segments[2] == "operations"
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && *segment != "."
                && *segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}
