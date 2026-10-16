//! OpenAI-compatible media wires for the `ai.*` calls past text: images
//! (`/v1/images/generations`, `/v1/images/edits`), video jobs
//! (`/v1/videos`), speech (`/v1/audio/speech`), transcription
//! (`/v1/audio/transcriptions`) and embeddings (`/v1/embeddings`). HTTP and
//! authentication stay host-owned: the host's transport sends one request
//! per call, so a run's media gate may wrap this backend.
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::media::wav::WavClip;
use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaFuture, MediaJobState, MediaPart, MediaRequest, MediaResponse,
    MediaUsage,
};
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId};
use serde_json::{Value, json};

use super::image::{
    OpenAiImageHttpResponse, OpenAiImagePart, decode_response, fields, form_fields, reference_part,
};

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
}

/// One provider's media client. It serves each engine model it was built
/// for by the name the provider knows it by.
pub struct OpenAiMediaBackend<T> {
    transport: T,
    wire_models: BTreeMap<ModelId, String>,
}

impl<T> OpenAiMediaBackend<T> {
    #[must_use]
    pub fn new(transport: T, wire_models: BTreeMap<ModelId, String>) -> Self {
        Self {
            transport,
            wire_models,
        }
    }

    fn wire_model(&self, model: &ModelId) -> LlmResult<String> {
        self.wire_models
            .get(model)
            .cloned()
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }
}

impl<T: OpenAiMediaTransport> OpenAiMediaBackend<T> {
    async fn send(
        &self,
        method: OpenAiMediaMethod,
        path: String,
        body: OpenAiMediaBody,
        lease: &BudgetLease,
    ) -> LlmResult<OpenAiMediaHttpResponse> {
        let reply = self
            .transport
            .execute(OpenAiMediaHttpRequest { method, path, body }, lease)
            .await?;
        match reply.refused() {
            Some(error) => Err(error),
            None => Ok(reply),
        }
    }

    async fn image(&self, request: MediaRequest, lease: &BudgetLease) -> LlmResult<MediaResponse> {
        let wire = self.wire_model(&request.model)?;
        let references = request
            .reference_images()
            .filter(|references| references.len() <= 8)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let (model, mut fields) = fields(&request.image_intent()?)?;
        fields.insert("model".into(), json!(wire));
        let (path, body) = if references.is_empty() {
            let body = Value::Object(fields.clone().into_iter().collect());
            ("/v1/images/generations", OpenAiMediaBody::Json(body))
        } else {
            let files = references
                .into_iter()
                .enumerate()
                .map(|(i, reference)| reference_part("image[]", i, reference))
                .collect::<LlmResult<Vec<_>>>()?;
            let fields = form_fields(&fields);
            (
                "/v1/images/edits",
                OpenAiMediaBody::Multipart { fields, files },
            )
        };
        let reply = self
            .transport
            .execute(
                OpenAiMediaHttpRequest {
                    method: OpenAiMediaMethod::Post,
                    path: path.to_owned(),
                    body,
                },
                lease,
            )
            .await?;
        let image = decode_response(
            OpenAiImageHttpResponse {
                status: reply.status,
                body: reply.json(),
                headers: reply.headers,
            },
            model,
            &fields,
        )?;
        let mut response = MediaResponse::from_image(image);
        // Token-priced image models report tokens; the rest are counted by
        // the image.
        if let Some(usage) = response.usage.raw_provider.get("usage") {
            let count = |key: &str| usage.get(key).and_then(Value::as_u64).unwrap_or(0);
            response.usage.input_tokens = count("input_tokens");
            response.usage.output_tokens = count("output_tokens");
        }
        Ok(response)
    }

    async fn speech(&self, request: MediaRequest, lease: &BudgetLease) -> LlmResult<MediaResponse> {
        let wire = self.wire_model(&request.model)?;
        let input = request.text();
        if input.trim().is_empty() || !only_text(&request) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let mut body = with_params(
            [("model", json!(wire)), ("input", json!(input))],
            &request.params,
        )?;
        match &request.voice {
            // A typed voice is the call's one voice: a `voice` param beside
            // it is refused, so a raw name never stands in for a banked
            // identity.
            Some(voice) => {
                if body
                    .insert("voice".into(), json!(voice.wire_id()))
                    .is_some()
                {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
            }
            None => {
                body.entry("voice".into()).or_insert_with(|| json!("alloy"));
            }
        }
        let format = body
            .entry("response_format".into())
            .or_insert_with(|| json!("mp3"))
            .as_str()
            .and_then(audio_type)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let body = OpenAiMediaBody::Json(Value::Object(body.into_iter().collect()));
        let reply = self
            .send(
                OpenAiMediaMethod::Post,
                "/v1/audio/speech".into(),
                body,
                lease,
            )
            .await?;
        if reply.body.is_empty() {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let media_type = reply
            .content_type()
            .filter(|kind| kind.starts_with("audio/"))
            .unwrap_or(format)
            .to_owned();
        Ok(MediaResponse {
            parts: vec![MediaPart::Audio {
                media_type,
                bytes: reply.body,
            }],
            usage: MediaUsage {
                characters: u64::try_from(input.chars().count()).unwrap_or(u64::MAX),
                ..MediaUsage::default()
            },
            model: request.model,
        })
    }

    async fn transcribe(
        &self,
        request: MediaRequest,
        lease: &BudgetLease,
    ) -> LlmResult<MediaResponse> {
        let wire = self.wire_model(&request.model)?;
        let [MediaPart::Audio { media_type, bytes }] = request.parts.as_slice() else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        if bytes.is_empty() || !request.references.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let measured_ms = WavClip::parse(bytes).map(|clip| clip.duration_ms());
        let mut body = with_params([("model", json!(wire))], &request.params)?;
        body.entry("response_format".into())
            .or_insert_with(|| json!("json"));
        let file = OpenAiImagePart {
            name: "file",
            filename: format!("audio.{}", audio_extension(media_type)),
            media_type: media_type.clone(),
            bytes: bytes.clone(),
        };
        let body = OpenAiMediaBody::Multipart {
            fields: form_fields(&body),
            files: vec![file],
        };
        let reply = self
            .send(
                OpenAiMediaMethod::Post,
                "/v1/audio/transcriptions".into(),
                body,
                lease,
            )
            .await?;
        let mut reply = reply.json();
        let text = reply
            .get("text")
            .and_then(Value::as_str)
            .ok_or(FatalLlmError::EmptyResponse)?
            .to_owned();
        let raw = reply
            .get_mut("usage")
            .map(Value::take)
            .unwrap_or(Value::Null);
        let count = |key: &str| raw.get(key).and_then(Value::as_u64).unwrap_or(0);
        let (input_tokens, output_tokens) = (count("input_tokens"), count("output_tokens"));
        // A duration-priced model reports seconds; a verbose reply its
        // length.
        let seconds = raw
            .get("seconds")
            .or_else(|| reply.get("duration"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        // A provider that reports neither is charged the length of the WAV
        // it was sent, read from the audio's own header.
        let audio_ms = match (seconds.max(0.0) * 1_000.0).ceil() as u64 {
            0 => measured_ms.unwrap_or(0),
            reported => reported,
        };
        let usage = MediaUsage {
            input_tokens,
            output_tokens,
            audio_ms,
            raw_provider: json!({ "usage": raw }),
            ..MediaUsage::default()
        };
        Ok(MediaResponse {
            parts: vec![MediaPart::Text { text }],
            usage,
            model: request.model,
        })
    }

    async fn embed(&self, request: MediaRequest, lease: &BudgetLease) -> LlmResult<MediaResponse> {
        let wire = self.wire_model(&request.model)?;
        if request.parts.is_empty() || !request.references.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        // Texts go as one batch. A call with an image or audio sends each part
        // as its own chat-form document (`messages` in place of `input`, as
        // vLLM serves multimodal embedding models): one vector each, in order.
        let documents: Vec<(usize, &'static str, Value)> = if only_text(&request) {
            let texts: Vec<&str> = request.texts().collect();
            vec![(texts.len(), "input", json!(texts))]
        } else {
            request
                .parts
                .iter()
                .map(|part| -> LlmResult<(usize, &'static str, Value)> {
                    let content = embed_content(part)?;
                    Ok((
                        1,
                        "messages",
                        json!([{ "role": "user", "content": [content] }]),
                    ))
                })
                .collect::<LlmResult<_>>()?
        };
        let (mut vectors, mut tokens, mut raws, mut served) =
            (Vec::new(), 0, Vec::new(), Value::Null);
        for (count, field, input) in documents {
            let mut body = with_params([("model", json!(wire)), (field, input)], &request.params)?;
            body.entry("encoding_format".into())
                .or_insert_with(|| json!("float"));
            let body = OpenAiMediaBody::Json(Value::Object(body.into_iter().collect()));
            let reply = self
                .send(
                    OpenAiMediaMethod::Post,
                    "/v1/embeddings".into(),
                    body,
                    lease,
                )
                .await?;
            let mut reply = reply.json();
            vectors.extend(indexed_vectors(&reply, count).ok_or(FatalLlmError::EmptyResponse)?);
            let raw = reply
                .get_mut("usage")
                .map(Value::take)
                .unwrap_or(Value::Null);
            tokens += raw
                .get("prompt_tokens")
                .or_else(|| raw.get("total_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            raws.push(raw);
            served = reply
                .get_mut("model")
                .map(Value::take)
                .unwrap_or(Value::Null);
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
        Ok(MediaResponse {
            parts: vectors
                .into_iter()
                .map(|vector| MediaPart::Embedding { vector })
                .collect(),
            usage: MediaUsage {
                input_tokens: tokens,
                raw_provider: json!({ "usage": raw, "served_model": served }),
                ..MediaUsage::default()
            },
            model: request.model,
        })
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
        let fields = with_params(
            [("model", json!(wire)), ("prompt", json!(prompt))],
            &request.params,
        )?;
        let body = match references.into_iter().next() {
            None => OpenAiMediaBody::Json(Value::Object(fields.into_iter().collect())),
            Some(reference) => OpenAiMediaBody::Multipart {
                fields: form_fields(&fields),
                files: vec![reference_part("input_reference", 0, reference)?],
            },
        };
        let reply = self
            .send(OpenAiMediaMethod::Post, "/v1/videos".into(), body, lease)
            .await?;
        reply
            .json()
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| job_id(id))
            .map(str::to_owned)
            .ok_or_else(|| FatalLlmError::EmptyResponse.into())
    }

    async fn poll_job(
        &self,
        model: &ModelId,
        job: &str,
        lease: &BudgetLease,
    ) -> LlmResult<MediaJobState> {
        if !job_id(job) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let reply = self
            .send(
                OpenAiMediaMethod::Get,
                format!("/v1/videos/{job}"),
                OpenAiMediaBody::Empty,
                lease,
            )
            .await?;
        let status = reply.json();
        let progress = status
            .get("progress")
            .and_then(Value::as_u64)
            .and_then(|progress| u8::try_from(progress.min(100)).ok());
        let state = status
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_owned);
        match state.as_deref() {
            Some("queued") => Ok(MediaJobState::Queued),
            Some("completed") => {
                let content = self
                    .send(
                        OpenAiMediaMethod::Get,
                        format!("/v1/videos/{job}/content"),
                        OpenAiMediaBody::Empty,
                        lease,
                    )
                    .await?;
                if content.body.is_empty() {
                    return Err(FatalLlmError::EmptyResponse.into());
                }
                let media_type = content
                    .content_type()
                    .filter(|kind| kind.starts_with("video/"))
                    .unwrap_or("video/mp4")
                    .to_owned();
                let seconds = status
                    .get("seconds")
                    .and_then(|seconds| {
                        seconds
                            .as_f64()
                            .or_else(|| seconds.as_str().and_then(|s| s.parse().ok()))
                    })
                    .unwrap_or(0.0);
                Ok(MediaJobState::Done {
                    response: MediaResponse {
                        parts: vec![MediaPart::Video {
                            media_type,
                            bytes: content.body,
                            uri: None,
                        }],
                        usage: MediaUsage {
                            video_ms: (seconds.max(0.0) * 1_000.0).ceil() as u64,
                            raw_provider: json!({ "job": job, "status": status }),
                            ..MediaUsage::default()
                        },
                        model: model.clone(),
                    },
                })
            }
            Some("failed") => {
                let moderated = status
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .is_some_and(|code| code.contains("moderation"));
                let error = if moderated {
                    FatalLlmError::ContentFiltered
                } else {
                    FatalLlmError::EmptyResponse
                };
                Ok(MediaJobState::Failed {
                    error: error.into(),
                })
            }
            _ => Ok(MediaJobState::Running { progress }),
        }
    }

    async fn cancel_job(&self, job: &str, lease: &BudgetLease) -> LlmResult<()> {
        if !job_id(job) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.send(
            OpenAiMediaMethod::Delete,
            format!("/v1/videos/{job}"),
            OpenAiMediaBody::Empty,
            lease,
        )
        .await?;
        Ok(())
    }
}

impl<T: OpenAiMediaTransport> MediaBackend for OpenAiMediaBackend<T> {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move {
            // A voice is a speech call's alone.
            if request.voice.is_some() && request.operation != AiOperation::Speech {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            match request.operation {
                AiOperation::Image => self.image(request, lease).await,
                AiOperation::Speech => self.speech(request, lease).await,
                AiOperation::Transcribe => self.transcribe(request, lease).await,
                AiOperation::Embed => self.embed(request, lease).await,
                // Text rides the chat wire; a video is a job.
                AiOperation::Text | AiOperation::Video => Err(FatalLlmError::InvalidRequest.into()),
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

    fn cancel<'a>(
        &'a self,
        _model: &'a ModelId,
        job: &'a str,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, ()> {
        Box::pin(self.cancel_job(job, lease))
    }
}

/// The call's fixed fields, then each param of the caller's. A param that
/// names a fixed field is refused: the adapter sets those.
fn with_params<const N: usize>(
    fixed: [(&str, Value); N],
    params: &BTreeMap<String, Value>,
) -> LlmResult<BTreeMap<String, Value>> {
    let mut body: BTreeMap<String, Value> = fixed
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    for (key, value) in params {
        if body.contains_key(key) || key.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        body.insert(key.clone(), value.clone());
    }
    Ok(body)
}

fn only_text(request: &MediaRequest) -> bool {
    request.references.is_empty()
        && request
            .parts
            .iter()
            .all(|part| matches!(part, MediaPart::Text { .. }))
}

/// One embedding document's part as a chat content part: an image as a data
/// URL, audio as `input_audio`.
fn embed_content(part: &MediaPart) -> LlmResult<Value> {
    Ok(match part {
        MediaPart::Text { text } => json!({ "type": "text", "text": text }),
        MediaPart::Image { media_type, bytes } if !bytes.is_empty() => json!({
            "type": "image_url",
            "image_url": { "url": format!("data:{media_type};base64,{}", STANDARD.encode(bytes)) },
        }),
        MediaPart::Audio { media_type, bytes } if !bytes.is_empty() => json!({
            "type": "input_audio",
            "input_audio": {
                "data": STANDARD.encode(bytes),
                "format": audio_extension(media_type),
            },
        }),
        _ => return Err(FatalLlmError::InvalidRequest.into()),
    })
}

/// A provider job id is a path segment: letters, digits, `_` and `-` only.
fn job_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// The media type a speech `response_format` names.
fn audio_type(format: &str) -> Option<&'static str> {
    Some(match format {
        "mp3" => "audio/mpeg",
        "opus" => "audio/opus",
        "aac" => "audio/aac",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "pcm" => "audio/pcm",
        _ => return None,
    })
}

/// The file extension a transcription upload is named with.
fn audio_extension(media_type: &str) -> &'static str {
    match media_type {
        "audio/mpeg" | "audio/mp3" => "mp3",
        "audio/mp4" | "audio/m4a" | "audio/x-m4a" => "m4a",
        "audio/webm" => "webm",
        "audio/ogg" | "audio/opus" => "ogg",
        "audio/flac" => "flac",
        _ => "wav",
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
