//! The `ai.*` verbs past text: `GET /v1/ai/options`, `POST /v1/ai/image`,
//! `/video`, `/speech`, `/transcribe` and `/embed`, and a video job's
//! `GET`/`DELETE /v1/ai/video/{job}`. Each call is the owner's: the vault's
//! inference policy admits its model, then its seat's ladder admits, sends
//! and settles each rung it reaches on the media meter (ARCH-0053
//! `#run-admission`). Bytes travel as base64 on this wire.
//!
//! A speech call may name its `voice`: a provider's stock voice by name, or
//! a banked identity (`{"kind": "bank", "voice_id": ...}`). A banked voice
//! renders on the first rung of the call's ladder whose target holds its
//! current clone, and on that rung alone; with none, or once withdrawn, the
//! call is refused rather than spoken in another voice (ARCH-0061 §5).
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::llm::media::{
    AiOperation, MediaJobState, MediaPart, MediaRequest, MediaResponse, MediaUsage, MediaVoice,
    Modality,
};
use oneiron::voice_cascade::media::BankVoiceBinding;
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, FatalLlmError, LlmError, ModelId, ModelTierRef,
    ResponseFormat, RetryableLlmError, TierPrecedence,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::refusal;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OptionsQuery {
    /// The operation whose rows to list; every one when absent.
    operation: Option<String>,
    /// The modalities a call would send, comma-separated (`text,image`).
    inputs: Option<String>,
}

/// The rows a call could use: each text seat's rungs and each media row
/// that serves the operation over those inputs, where each runs, what it
/// takes, the rates its native counts settle at, and what the media meter
/// has left.
pub(super) async fn options(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Query(query): Query<OptionsQuery>,
) -> Response {
    if let Err(error) = auth.require(CoreScope::Read) {
        return error.into_response();
    }
    let operation = match query.operation.as_deref().map(AiOperation::parse) {
        None => None,
        Some(Some(operation)) => Some(operation),
        Some(None) => {
            return refusal(
                StatusCode::BAD_REQUEST,
                "unknown_operation",
                "operation is one of text, image, video, speech, transcribe, embed",
            );
        }
    };
    let mut inputs = BTreeSet::new();
    for name in query.inputs.iter().flat_map(|inputs| inputs.split(',')) {
        match serde_json::from_value::<Modality>(JsonValue::String(name.trim().to_owned())) {
            Ok(modality) => {
                inputs.insert(modality);
            }
            Err(_) => {
                return refusal(
                    StatusCode::BAD_REQUEST,
                    "unknown_modality",
                    "inputs are text, image, audio, video or embedding",
                );
            }
        }
    }
    let runtime = server.ai.model_runtime();
    Json(serde_json::json!({
        "options": runtime.ai_options(operation, &inputs),
        "media_units_left": runtime.media().units_left(),
    }))
    .into_response()
}

/// One part on this wire: text, or bytes as base64.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WirePart {
    Text {
        text: String,
    },
    Image {
        media_type: String,
        data: String,
    },
    Audio {
        media_type: String,
        data: String,
    },
    Video {
        media_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uri: Option<String>,
    },
    Embedding {
        vector: Vec<f32>,
    },
}

impl WirePart {
    fn into_part(self) -> Option<MediaPart> {
        let bytes = |data: &str| STANDARD.decode(data).ok().filter(|bytes| !bytes.is_empty());
        Some(match self {
            Self::Text { text } => MediaPart::Text { text },
            Self::Image { media_type, data } => MediaPart::Image {
                bytes: bytes(&data)?,
                media_type,
            },
            Self::Audio { media_type, data } => MediaPart::Audio {
                bytes: bytes(&data)?,
                media_type,
            },
            // A caller sends no clip or vector in.
            Self::Video { .. } | Self::Embedding { .. } => return None,
        })
    }

    fn from_part(part: MediaPart) -> Self {
        match part {
            MediaPart::Text { text } => Self::Text { text },
            MediaPart::Image { media_type, bytes } => Self::Image {
                media_type,
                data: STANDARD.encode(bytes),
            },
            MediaPart::Audio { media_type, bytes } => Self::Audio {
                media_type,
                data: STANDARD.encode(bytes),
            },
            MediaPart::Video {
                media_type,
                bytes,
                uri,
            } => Self::Video {
                media_type,
                data: (!bytes.is_empty()).then(|| STANDARD.encode(bytes)),
                uri,
            },
            MediaPart::Embedding { vector } => Self::Embedding { vector },
        }
    }
}

/// One `ai.*` media call as its caller writes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AiCallBody {
    /// A row's id to use it alone, or its seat's id; the operation's seat
    /// when absent.
    model: Option<ModelId>,
    /// The instruction, the script or the one text: a first text part.
    prompt: Option<String>,
    #[serde(default)]
    input: Vec<WirePart>,
    /// The images an image call edits, or a video call starts from.
    #[serde(default)]
    references: Vec<WirePart>,
    #[serde(default)]
    params: BTreeMap<String, JsonValue>,
    /// A speech call's voice; the provider's default when absent.
    #[serde(default)]
    voice: Option<VoiceChoice>,
}

/// The voice a speech call names.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum VoiceChoice {
    /// A provider's own voice, by its name.
    Stock { name: String },
    /// A banked identity, rendered as its clone on the call's target.
    Bank {
        voice_id: String,
        #[serde(default)]
        include_generated: bool,
    },
}

/// One call's answer on this wire.
#[derive(Serialize)]
struct AiAnswer {
    model: String,
    parts: Vec<WirePart>,
    usage: MediaUsage,
}

impl AiAnswer {
    fn new(response: MediaResponse) -> Self {
        Self {
            model: response.model.to_string(),
            parts: response
                .parts
                .into_iter()
                .map(WirePart::from_part)
                .collect(),
            usage: response.usage,
        }
    }
}

/// The owner's call of `operation`, admitted against the vault's inference
/// policy for the model it names, ready for its seat's ladder, with the
/// banked voice it renders in, if any.
fn admit(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    body: AiCallBody,
) -> Result<(MediaRequest, Option<BankVoiceBinding>), Response> {
    if !auth.is_owner_grade() {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "owner_required",
            "ai.* media calls are the owner's",
        ));
    }
    let media = server.ai.model_runtime().media();
    let Some((seat, _)) = media.seat(operation) else {
        return Err(refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "media_unavailable",
            format!("no [models.media.{}] seat serves", operation.as_str()),
        ));
    };
    let mut model = body.model.unwrap_or(seat);
    if media.locality(operation, &model).is_none() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "unknown_model",
            format!("{model} serves no {} call here", operation.as_str()),
        ));
    }
    let (voice, binding) = match body.voice {
        None => (None, None),
        Some(_) if operation != AiOperation::Speech => {
            return Err(refusal(
                StatusCode::BAD_REQUEST,
                "voice_not_speech",
                "only a speech call names a voice",
            ));
        }
        Some(VoiceChoice::Stock { name }) if name.trim().is_empty() => {
            return Err(refusal(
                StatusCode::BAD_REQUEST,
                "invalid_voice",
                "a stock voice has a name",
            ));
        }
        Some(VoiceChoice::Stock { name }) => (Some(MediaVoice::Stock { name }), None),
        Some(VoiceChoice::Bank {
            voice_id,
            include_generated,
        }) => {
            // The clone is the target's: the call takes the first rung
            // holding a current one, alone, so no fallback carries its id
            // to another provider. A rung that renders from the bank's
            // refs binds the identity's fenced source clip instead.
            let bound = media.rung_targets(operation, &model).into_iter().find_map(
                |(rung, target, locality)| {
                    let binding = if media.renders_from_refs(&target) {
                        BankVoiceBinding::bind_reference(
                            &server.vault,
                            &voice_id,
                            &target,
                            None,
                            locality,
                        )
                    } else {
                        BankVoiceBinding::bind(
                            &server.vault,
                            &voice_id,
                            &target,
                            include_generated,
                            locality,
                        )
                    };
                    binding.ok().map(|binding| (rung, binding))
                },
            );
            let Some((rung, binding)) = bound else {
                return Err(refusal(
                    StatusCode::CONFLICT,
                    "voice_not_provisioned",
                    "no rung this call may reach holds a current clone or reference of the voice",
                ));
            };
            model = rung;
            (Some(binding.voice()), Some(binding))
        }
    };
    let Some(locality) = media.locality(operation, &model) else {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "unknown_model",
            format!("{model} serves no {} call here", operation.as_str()),
        ));
    };
    let mut parts = Vec::new();
    if let Some(prompt) = body.prompt {
        parts.push(MediaPart::Text { text: prompt });
    }
    let decoded = |parts: Vec<WirePart>| {
        parts
            .into_iter()
            .map(WirePart::into_part)
            .collect::<Option<Vec<_>>>()
    };
    let (Some(input), Some(references)) = (decoded(body.input), decoded(body.references)) else {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "invalid_part",
            "each part is text, or an image or audio with base64 data",
        ));
    };
    parts.extend(input);
    let purpose = CallPurpose::Other {
        name: format!("ai.{}", operation.as_str()),
    };
    let mut request = MediaRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(
                &purpose,
                ModelTierRef(format!("media-{}", operation.as_str())),
            ),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality,
            seat_effort: None,
        },
        operation,
        parts,
        references,
        params: body.params,
        voice,
    };
    if let Some(key) = request.admission_request().route_selector_override() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": {"code": "route_selector_forbidden", "key": key}})),
        )
            .into_response());
    }
    let context = oneiron::llm::HostInferenceContext {
        binding: oneiron::llm::HostInferenceBinding::Advertised { model, locality },
        extraction_egress: server.extraction_egress.as_deref(),
    };
    let authorized = server
        .vault
        .authorize_raw_inference(request.admission_request(), &context)
        .map_err(|_| {
            refusal(
                StatusCode::FORBIDDEN,
                "inference_denied",
                "the vault's inference policy refuses this call",
            )
        })?;
    request.envelope = authorized.into_request().envelope;
    // The world a caller names does not vouch for what it sends: a
    // fallback judges the call as naming none, as a raw text call is.
    request.envelope.scope.world = None;
    Ok((request, binding))
}

pub(super) fn failure(error: &LlmError) -> Response {
    let (status, code) = match error {
        LlmError::BudgetDenied(_) => (StatusCode::PAYMENT_REQUIRED, "budget_denied"),
        LlmError::Fatal(FatalLlmError::Auth) => (StatusCode::BAD_GATEWAY, "provider_auth"),
        LlmError::Fatal(FatalLlmError::ContentFiltered) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "content_filtered")
        }
        LlmError::Fatal(FatalLlmError::EmptyResponse) => {
            (StatusCode::BAD_GATEWAY, "empty_response")
        }
        LlmError::Fatal(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        LlmError::Retryable(RetryableLlmError::RateLimited { .. }) => {
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        }
        // A spent window or spent credit: the owner's quota question in
        // `GET /v1/ai/status` says what to do.
        LlmError::Retryable(RetryableLlmError::QuotaSpent { .. }) => {
            (StatusCode::TOO_MANY_REQUESTS, "quota_spent")
        }
        LlmError::Retryable(RetryableLlmError::KeptOnDevice { .. }) => {
            (StatusCode::CONFLICT, "kept_on_device")
        }
        LlmError::Retryable(_) => (StatusCode::BAD_GATEWAY, "provider_unavailable"),
    };
    (
        status,
        Json(serde_json::json!({"error": {"code": code, "llm": error}})),
    )
        .into_response()
}

/// The call's answer. A banked voice withdrawn or re-recorded while it
/// rendered is not handed back.
async fn answered(
    server: &SyncServer,
    request: MediaRequest,
    binding: Option<BankVoiceBinding>,
) -> Response {
    match server.ai.model_runtime().media().run(request).await {
        Ok(_)
            if binding
                .as_ref()
                .is_some_and(|binding| !binding.is_current(&server.vault)) =>
        {
            refusal(
                StatusCode::CONFLICT,
                "voice_withdrawn",
                "the voice was withdrawn or its clone replaced while it rendered",
            )
        }
        Ok(response) => Json(AiAnswer::new(response)).into_response(),
        Err(error) => failure(&error),
    }
}

macro_rules! media_verb {
    ($name:ident, $operation:expr) => {
        pub(super) async fn $name(
            auth: CoreAuth,
            State(server): State<Arc<SyncServer>>,
            Json(body): Json<AiCallBody>,
        ) -> Response {
            match admit(&server, &auth, $operation, body) {
                Ok((request, binding)) => answered(&server, request, binding).await,
                Err(refused) => refused,
            }
        }
    };
}

media_verb!(image, AiOperation::Image);
media_verb!(speech, AiOperation::Speech);
media_verb!(transcribe, AiOperation::Transcribe);
media_verb!(embed, AiOperation::Embed);

/// `ai.video`: the clip renders as a provider job; the answer is its ticket.
pub(super) async fn video(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(body): Json<AiCallBody>,
) -> Response {
    let request = match admit(&server, &auth, AiOperation::Video, body) {
        Ok((request, _)) => request,
        Err(refused) => return refused,
    };
    match server.ai.model_runtime().media().submit(request).await {
        Ok(ticket) => (StatusCode::ACCEPTED, Json(ticket)).into_response(),
        Err(error) => failure(&error),
    }
}

/// Where a video job stands; a finished one answers with its clip on every
/// poll until its caller deletes it.
pub(super) async fn video_job(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(job): Path<String>,
) -> Response {
    if !auth.is_owner_grade() {
        return refusal(
            StatusCode::FORBIDDEN,
            "owner_required",
            "video jobs are the owner's",
        );
    }
    match server.ai.model_runtime().media().poll(&job).await {
        Ok(MediaJobState::Done { response }) => Json(serde_json::json!({
            "state": "done",
            "answer": AiAnswer::new(response),
        }))
        .into_response(),
        Ok(MediaJobState::Failed { error }) => Json(serde_json::json!({
            "state": "failed",
            "error": {"llm": error},
        }))
        .into_response(),
        Ok(state) => Json(state).into_response(),
        Err(error) => failure(&error),
    }
}

/// Stops a video job at its provider.
pub(super) async fn cancel_video_job(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(job): Path<String>,
) -> Response {
    if !auth.is_owner_grade() {
        return refusal(
            StatusCode::FORBIDDEN,
            "owner_required",
            "video jobs are the owner's",
        );
    }
    match server.ai.model_runtime().media().cancel(&job).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => failure(&error),
    }
}
