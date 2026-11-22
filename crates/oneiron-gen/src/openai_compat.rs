//! OpenAI-compatible image and video job wires: images
//! (`/v1/images/generations`, `/v1/images/edits`) and video jobs
//! (`/v1/videos`). [`OpenAiGenBackend`] speaks them over the provider's
//! shared `oneiron_llm::openai_compat::OpenAiMediaClient`, whose transport
//! seam is `oneiron_llm`'s; [`DirectOpenAiImageBackend`] serves the image seam
//! on its own transport. HTTP and authentication stay host-owned: the host's
//! transport sends one request per call, so a run's media gate may wrap this
//! backend.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::image::ImageBytes;
use oneiron::llm::media::{
    AiOperation, InterruptedMediaCall, MediaBackend, MediaFuture, MediaJobState, MediaPart,
    MediaProgressFuture, MediaRequest, MediaResponse, MediaUsage, ReferenceCompatibility,
    run_once_released,
};
use oneiron::llm::{BrokerIsolation, DispatchRelease};
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId};
use oneiron_llm::openai_compat::{
    OpenAiImagePart, OpenAiMediaBody, OpenAiMediaClient, OpenAiMediaHttpRequest,
    OpenAiMediaHttpResponse, OpenAiMediaMethod, OpenAiMediaTransport, form_fields,
};
use serde_json::{Value, json};

mod image;
mod prepare;

pub use self::image::{
    DirectOpenAiImageBackend, OpenAiImageBody, OpenAiImageHttpRequest, OpenAiImageHttpResponse,
    OpenAiImageTransport, OpenAiImageTransportFuture,
};
use self::image::{decode_response, masked_edit_body, reference_part};
use self::prepare::{
    PreparedImage, PreparedVideo, VIDEO_REFERENCE_SLOTS, prepare_image, prepare_video,
};

/// One provider's image calls and video jobs over its shared client.
pub struct OpenAiGenBackend<T> {
    client: Arc<OpenAiMediaClient<T>>,
}

impl<T> OpenAiGenBackend<T> {
    #[must_use]
    pub fn new(client: Arc<OpenAiMediaClient<T>>) -> Self {
        Self { client }
    }
}

impl<T: OpenAiMediaTransport> OpenAiGenBackend<T> {
    /// One image call, under the caller's release when there is one: it is
    /// checked before the send, and the transport re-checks it before each
    /// physical request.
    async fn image(
        &self,
        request: MediaRequest,
        lease: &BudgetLease,
        release: Option<DispatchRelease<'_>>,
    ) -> LlmResult<MediaResponse> {
        let wire = self.client.wire_model(&request.model)?;
        let PreparedImage { model, fields } = prepare_image(&request, &wire)?;
        // Every reference goes, in order (FIX 8614): none is dropped or cut.
        let (path, body) = if let Some(mask) = request.mask {
            let references = request
                .references
                .into_iter()
                .map(|reference| {
                    let MediaPart::Image { media_type, bytes } = reference else {
                        return Err(FatalLlmError::InvalidRequest.into());
                    };
                    Ok(ImageBytes { bytes, media_type })
                })
                .collect::<LlmResult<Vec<_>>>()?;
            (
                "/v1/images/edits",
                OpenAiMediaBody::Json(masked_edit_body(fields.clone(), references, mask)?),
            )
        } else if request.references.is_empty() {
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
        if let Some(release) = release {
            release()?;
        }
        let reply = self
            .client
            .transport()
            .execute_released(
                OpenAiMediaHttpRequest {
                    method: OpenAiMediaMethod::Post,
                    path: path.to_owned(),
                    headers: BTreeMap::new(),
                    body,
                },
                lease,
                release,
            )
            .await?;
        // The reply's raw bytes go once its JSON is read, before the image
        // is decoded, so the two are never held with the decoded image
        // (FIX 8615).
        let json = reply.json();
        let OpenAiMediaHttpResponse {
            status,
            headers,
            body,
        } = reply;
        drop(body);
        let image = decode_response(
            OpenAiImageHttpResponse {
                status,
                body: json,
                headers,
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

    async fn submit_job(
        &self,
        request: MediaRequest,
        key: Option<&str>,
        lease: &BudgetLease,
    ) -> LlmResult<String> {
        let wire = self.client.wire_model(&request.model)?;
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
        let mut headers = BTreeMap::new();
        if let Some(key) = key.filter(|key| !key.is_empty()) {
            headers.insert("idempotency-key".to_owned(), key.to_owned());
        }
        let reply = self
            .client
            .send_with_headers(
                OpenAiMediaMethod::Post,
                "/v1/videos".into(),
                body,
                headers,
                lease,
                None,
            )
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
            .client
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
                    .client
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
        self.client
            .send(
                OpenAiMediaMethod::Delete,
                format!("/v1/videos/{job}"),
                OpenAiMediaBody::Empty,
                lease,
            )
            .await?;
        Ok(())
    }
}

/// Serves image calls and video jobs alone: every other call is another
/// family's, and is refused here with `InvalidRequest` before anything is
/// sent.
impl<T: OpenAiMediaTransport> MediaBackend for OpenAiGenBackend<T> {
    fn supports_mask(&self) -> bool {
        true
    }

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
    /// builders refuse (a voice, a param naming a field the adapter sets, a
    /// reference it cannot carry, FIX 8616), or its transport's refusal: all
    /// before the call's permit starts, so none of them is charged.
    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        request.validate_image_mask()?;
        let wire = self.client.wire_model(&request.model)?;
        // A voice is a speech call's alone.
        if request.voice.is_some() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        match request.operation {
            AiOperation::Image => {
                prepare_image(request, &wire)?;
            }
            AiOperation::Video => {
                prepare_video(request, &wire)?;
            }
            // Text rides the chat wire; speech, transcription and
            // embeddings are other families' calls.
            _ => return Err(FatalLlmError::InvalidRequest.into()),
        }
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
            // A voice is a speech call's alone; a video is a job.
            if request.voice.is_some() || request.operation != AiOperation::Image {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            self.image(request, lease, None).await
        })
    }

    /// An image call under the caller's release (UC-16): a refused release
    /// sends nothing. Every other call is refused as [`Self::run`] refuses
    /// it.
    fn run_progress_released<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
        release: Option<DispatchRelease<'a>>,
    ) -> MediaProgressFuture<'a> {
        if request.voice.is_some() || request.operation != AiOperation::Image {
            return run_once_released(self, request, lease, None);
        }
        Box::pin(async move {
            if let Err(error) = request.validate_image_mask() {
                return Err(InterruptedMediaCall::nothing(error));
            }
            self.image(request, lease, release)
                .await
                .map_err(InterruptedMediaCall::nothing)
        })
    }

    /// Forwards a video's submit key without claiming the provider honours
    /// it (FIX 2248): this wire still reports that it does not dedupe.
    fn submit<'a>(
        &'a self,
        request: MediaRequest,
        key: Option<&'a str>,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, String> {
        Box::pin(self.submit_job(request, key, lease))
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

#[cfg(test)]
mod tests;
