//! Gemini API media wires for the `ai.*` calls past text. An image is
//! `models/{model}:generateContent` asked for image output, its reference
//! images sent inline. A video is a Veo job: `models/{model}:predictLongRunning`
//! starts it, its operation is polled until done, and each clip is fetched
//! from the file URI the operation names. HTTP and authentication stay
//! host-owned: the host's transport sends one request per call, so a run's
//! media gate may wrap this backend.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaFuture, MediaJobState, MediaPart, MediaRequest, MediaResponse,
    MediaUsage,
};
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::{future::Future, pin::Pin};

/// The most reference images one image call sends inline.
const MAX_IMAGE_REFERENCES: usize = 14;
/// The aspect ratios a Gemini image model draws, as `(width, height)`.
const IMAGE_RATIOS: [(u32, u32); 10] = [
    (1, 1),
    (2, 3),
    (3, 2),
    (3, 4),
    (4, 3),
    (4, 5),
    (5, 4),
    (9, 16),
    (16, 9),
    (21, 9),
];
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
        let prompt = request.text();
        let references = request
            .reference_images()
            .filter(|references| references.len() <= MAX_IMAGE_REFERENCES)
            .ok_or(FatalLlmError::InvalidRequest)?;
        if prompt.trim().is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let mut parts = vec![json!({ "text": prompt })];
        parts.extend(references.iter().map(|reference| {
            json!({ "inlineData": {
                "mimeType": reference.media_type,
                "data": STANDARD.encode(&reference.bytes),
            } })
        }));
        let body = json!({
            "contents": [{ "role": "user", "parts": parts }],
            "generationConfig": image_config(&request)?,
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
        let prompt = request.text();
        if request.operation != AiOperation::Video || prompt.trim().is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let references = request
            .reference_images()
            .filter(|references| references.len() <= 1)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let mut instance = json!({ "prompt": prompt });
        if let Some(start) = references.first() {
            instance["image"] = json!({ "inlineData": {
                "mimeType": start.media_type,
                "data": STANDARD.encode(&start.bytes),
            } });
        }
        let body = json!({
            "instances": [instance],
            "parameters": video_parameters(&request.params)?,
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

/// An image call's `generationConfig`: image output, its aspect ratio and
/// size from the call's `size` (`"WxH"`) or `width`/`height` when it names
/// one, then each other param as it came. Gemini's own `aspectRatio` and
/// `imageSize` params win over a named size.
fn image_config(request: &MediaRequest) -> LlmResult<Value> {
    let sized = ["size", "width", "height"]
        .iter()
        .any(|key| request.params.contains_key(*key));
    let intent = request.image_intent()?;
    let mut image = Map::new();
    if sized {
        if intent.width == 0 || intent.height == 0 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        image.insert(
            "aspectRatio".into(),
            json!(nearest_ratio(intent.width, intent.height)),
        );
        let side = intent.width.max(intent.height);
        let size = match side {
            ..=1024 => "1K",
            ..=2048 => "2K",
            _ => "4K",
        };
        image.insert("imageSize".into(), json!(size));
    }
    let mut config = Map::new();
    config.insert("responseModalities".into(), json!(["TEXT", "IMAGE"]));
    for (key, value) in intent.params {
        match key.as_str() {
            "aspect_ratio" | "aspectRatio" => {
                image.insert("aspectRatio".into(), value);
            }
            "image_size" | "imageSize" => {
                image.insert("imageSize".into(), value);
            }
            "" | "responseModalities" | "imageConfig" => {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            _ => {
                config.insert(key, value);
            }
        }
    }
    if !image.is_empty() {
        config.insert("imageConfig".into(), Value::Object(image));
    }
    Ok(Value::Object(config))
}

/// The drawn ratio closest to `width:height`.
fn nearest_ratio(width: u32, height: u32) -> String {
    let wanted = f64::from(width) / f64::from(height);
    let (w, h) = IMAGE_RATIOS
        .into_iter()
        .min_by(|a, b| {
            let off = |(w, h): (u32, u32)| (f64::from(w) / f64::from(h) / wanted).ln().abs();
            off(*a).total_cmp(&off(*b))
        })
        .unwrap_or((1, 1));
    format!("{w}:{h}")
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
                let bytes = STANDARD
                    .decode(data)
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

/// A Veo job's `parameters`: the call's `seconds` as `durationSeconds`, its
/// `size` (`"WxH"`) as an aspect ratio and resolution, then each other
/// param as it came. A param that names a field set here is refused.
fn video_parameters(params: &BTreeMap<String, Value>) -> LlmResult<Value> {
    fn set(out: &mut Map<String, Value>, key: &str, value: Value) -> LlmResult<()> {
        if key.is_empty() || out.insert(key.to_owned(), value).is_some() {
            Err(FatalLlmError::InvalidRequest.into())
        } else {
            Ok(())
        }
    }
    let mut out = Map::new();
    for (key, value) in params {
        match key.as_str() {
            "seconds" | "durationSeconds" => {
                let seconds = value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
                    .filter(|seconds| *seconds > 0)
                    .ok_or(FatalLlmError::InvalidRequest)?;
                set(&mut out, "durationSeconds", json!(seconds))?;
            }
            "size" => {
                let (width, height) = value
                    .as_str()
                    .and_then(|size| size.split_once('x'))
                    .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?)))
                    .filter(|(w, h)| *w > 0 && *h > 0)
                    .ok_or(FatalLlmError::InvalidRequest)?;
                let ratio = if width >= height { "16:9" } else { "9:16" };
                let resolution = match width.min(height) {
                    ..=720 => "720p",
                    ..=1080 => "1080p",
                    _ => "4k",
                };
                set(&mut out, "aspectRatio", json!(ratio))?;
                set(&mut out, "resolution", json!(resolution))?;
            }
            _ => set(&mut out, key, value.clone())?,
        }
    }
    Ok(Value::Object(out))
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
