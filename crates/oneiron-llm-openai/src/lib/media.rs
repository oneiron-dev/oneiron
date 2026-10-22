//! OpenAI-compatible media wires for the `ai.*` calls past text: images
//! (`/v1/images/generations`, `/v1/images/edits`), video jobs
//! (`/v1/videos`), speech (`/v1/audio/speech`), transcription
//! (`/v1/audio/transcriptions`) and embeddings (`/v1/embeddings`). HTTP and
//! authentication stay host-owned: the host's transport sends one request
//! per call, so a run's media gate may wrap this backend.
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use oneiron::llm::BrokerIsolation;
use oneiron::llm::image::ImageBytes;
use oneiron::llm::media::wav::WavClip;
use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaFuture, MediaJobState, MediaPart, MediaRequest, MediaResponse,
    MediaUsage, ReferenceCompatibility,
};
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId};
use serde_json::{Value, json};

use super::image::{
    OpenAiImageHttpResponse, OpenAiImagePart, decode_response, form_fields, reference_part,
};

mod prepare;

use prepare::{
    EmbedPlan, PreparedImage, PreparedSpeech, PreparedTranscribe, PreparedVideo,
    VIDEO_REFERENCE_SLOTS, embed_content, prepare_embed, prepare_image, prepare_speech,
    prepare_transcribe, prepare_video, with_params,
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
        let PreparedImage { model, fields } = prepare_image(&request, &wire)?;
        // Every reference goes, in order (FIX 8614): none is dropped or cut.
        let (path, body) = if request.references.is_empty() {
            let body = Value::Object(fields.clone().into_iter().collect());
            ("/v1/images/generations", OpenAiMediaBody::Json(body))
        } else {
            let files = request
                .references
                .into_iter()
                .enumerate()
                .map(|(i, reference)| reference_file("image[]", i, reference))
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
        let PreparedSpeech {
            body,
            format,
            characters,
        } = prepare_speech(&request, &wire)?;
        let body = OpenAiMediaBody::Json(body);
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
                characters,
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
        let PreparedTranscribe {
            fields,
            filename,
            media_type,
        } = prepare_transcribe(&request, &wire)?;
        // The one audio part the builder checked, taken, not copied.
        let Some(MediaPart::Audio { bytes, .. }) = request.parts.into_iter().next() else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        let measured_ms = WavClip::parse(&bytes).map(|clip| clip.duration_ms());
        let file = OpenAiImagePart {
            name: "file",
            filename,
            media_type,
            bytes,
        };
        let body = OpenAiMediaBody::Multipart {
            fields,
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
        // The whole call is checked before its first document is sent.
        let plan = prepare_embed(&request, &wire)?;
        // Texts go as one batch. A call with an image or audio sends each part
        // as its own chat-form document (`messages` in place of `input`, as
        // vLLM serves multimodal embedding models): one vector each, in order.
        let documents: Vec<(usize, &'static str, Value)> = if plan == EmbedPlan::Texts {
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
        let mut marks = Vec::new();
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

    async fn submit_job(&self, request: MediaRequest, lease: &BudgetLease) -> LlmResult<String> {
        let wire = self.wire_model(&request.model)?;
        let PreparedVideo { fields } = prepare_video(&request, &wire)?;
        // The job's one start frame, when it has one; the builder refused a
        // call with more, so nothing is cut here.
        let mut references = request.references;
        let body = match (references.pop(), references.is_empty()) {
            (None, _) => OpenAiMediaBody::Json(Value::Object(fields.into_iter().collect())),
            (Some(reference), true) => OpenAiMediaBody::Multipart {
                fields: form_fields(&fields),
                files: vec![reference_file("input_reference", 0, reference)?],
            },
            (Some(_), false) => return Err(FatalLlmError::InvalidRequest.into()),
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
    /// A video job carries one `input_reference`; an image call every
    /// reference.
    fn reference_compatibility(&self, request: &MediaRequest) -> ReferenceCompatibility {
        match request.operation {
            AiOperation::Video => ReferenceCompatibility::Slots {
                slots: VIDEO_REFERENCE_SLOTS,
            },
            _ => ReferenceCompatibility::Whole,
        }
    }

    /// A model this client was not built for, a call its send's own
    /// builders refuse (a voice off a speech call, conflicting speech
    /// params, a param naming a field the adapter sets, an embedding
    /// document it cannot carry, FIX 8616), or its transport's refusal: all
    /// before the call's permit starts, so none of them is charged.
    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        let wire = self.wire_model(&request.model)?;
        if request.voice.is_some() && request.operation != AiOperation::Speech {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        match request.operation {
            AiOperation::Image => {
                prepare_image(request, &wire)?;
            }
            AiOperation::Speech => {
                prepare_speech(request, &wire)?;
            }
            AiOperation::Transcribe => {
                prepare_transcribe(request, &wire)?;
            }
            AiOperation::Embed => {
                prepare_embed(request, &wire)?;
            }
            AiOperation::Video => {
                prepare_video(request, &wire)?;
            }
            // Text rides the chat wire.
            AiOperation::Text => return Err(FatalLlmError::InvalidRequest.into()),
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

/// One reference part as the multipart file part `name`, its bytes taken,
/// not copied.
fn reference_file(name: &'static str, index: usize, part: MediaPart) -> LlmResult<OpenAiImagePart> {
    let MediaPart::Image { media_type, bytes } = part else {
        return Err(FatalLlmError::InvalidRequest.into());
    };
    reference_part(name, index, ImageBytes { bytes, media_type })
}

/// A provider job id is a path segment: letters, digits, `_` and `-` only.
fn job_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
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
