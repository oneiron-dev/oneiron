//! The host doors of the verb-table rows only a server's own state answers:
//! the owner's `vault.packs.put` and the `ai.*` model calls past text. The
//! generated HTTP facade handler and the MCP dispatcher both call these, so
//! a tool call, a code-mode call and an SDK call meet one admission.
//!
//! The `ai.*` doors admit as `/v1/ai/<operation>` does (api/ai/media.rs):
//! the call is the owner's, the vault's inference policy admits its model,
//! then its seat's ladder admits, sends and settles each rung it reaches.
use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest, Modality};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use oneiron::task_verb::sdk::{
    AiAnswer, AiCallRequest, AiOptions, AiOptionsRequest, AiVideoCancelled, AiVideoJob,
    AiVideoJobRequest, AiVideoTicket, PackPutReceipt, PackPutRequest,
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, FatalLlmError, LlmError, ModelId, ModelTierRef,
    ResponseFormat, RetryableLlmError, TierPrecedence,
};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.packs.put`: the owner installs a pack folder, or replaces the one
/// installed under its name, under the proof `/v1/owner` takes from the
/// request. The put is the consent for the pack's hooks.
pub(crate) async fn vault_packs_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "vault.packs.put is the vault owner's",
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::put_pack_as_owner(server.vault(), &owner, input)
    })
    .await
    .map_err(|_| internal("vault.packs.put"))?
}

/// `ai.options`: the rows a call could use, where each runs, what it takes,
/// the rates its native counts settle at, and what the media meter has left.
pub(crate) async fn ai_options(
    server: &Arc<SyncServer>,
    _auth: &CoreAuth,
    input: AiOptionsRequest,
) -> MemoryResult<AiOptions> {
    let operation = input
        .operation
        .as_deref()
        .map(|name| {
            AiOperation::parse(name).ok_or_else(|| {
                MemoryError::bad_request(
                    "operation is one of text, image, video, speech, transcribe, embed",
                )
            })
        })
        .transpose()?;
    let mut inputs = BTreeSet::new();
    for name in &input.inputs {
        let modality =
            serde_json::from_value::<Modality>(serde_json::Value::String(name.trim().to_owned()))
                .map_err(|_| {
                MemoryError::bad_request("inputs are text, image, audio, video or embedding")
            })?;
        inputs.insert(modality);
    }
    let runtime = server.ai.model_runtime();
    let options = runtime
        .ai_options(operation, &inputs)
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|_| internal("ai.options"))?;
    Ok(AiOptions {
        options,
        media_units_left: runtime.media().units_left(),
    })
}

/// One media call's answer, from its seat's ladder.
async fn answered(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    let request = admit(server, auth, operation, input)?;
    let response = server
        .ai
        .model_runtime()
        .media()
        .run(request)
        .await
        .map_err(|error| failure(operation, &error))?;
    Ok(response.into())
}

/// `ai.image`: one image out; reference images make it an edit.
pub(crate) async fn ai_image(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    answered(server, auth, AiOperation::Image, input).await
}

/// `ai.speech`: speech audio out of text.
pub(crate) async fn ai_speech(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    answered(server, auth, AiOperation::Speech, input).await
}

/// `ai.transcribe`: text out of speech audio.
pub(crate) async fn ai_transcribe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    answered(server, auth, AiOperation::Transcribe, input).await
}

/// `ai.embed`: one vector per input text.
pub(crate) async fn ai_embed(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    answered(server, auth, AiOperation::Embed, input).await
}

/// `ai.video`: the clip renders as a provider job; the answer is its ticket.
pub(crate) async fn ai_video(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MemoryResult<AiVideoTicket> {
    let request = admit(server, auth, AiOperation::Video, input)?;
    let ticket = server
        .ai
        .model_runtime()
        .media()
        .submit(request)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoTicket {
        job: ticket.job,
        model: ticket.model,
        operation: ticket.operation,
    })
}

/// `ai.video.poll`: where a video job stands; a finished one answers with
/// its clip, once.
pub(crate) async fn ai_video_poll(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoJob> {
    owner_grade(auth, "video jobs are the owner's")?;
    let state = server
        .ai
        .model_runtime()
        .media()
        .poll(&input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(state.into())
}

/// `ai.video.cancel`: stops a video job at its provider.
pub(crate) async fn ai_video_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoCancelled> {
    owner_grade(auth, "video jobs are the owner's")?;
    server
        .ai
        .model_runtime()
        .media()
        .cancel(&input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoCancelled { job: input.job })
}

fn owner_grade(auth: &CoreAuth, message: &str) -> MemoryResult<()> {
    if auth.is_owner_grade() {
        return Ok(());
    }
    Err(MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        message,
        &["Present a verified, unattenuated owner credential."],
    ))
}

fn internal(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{verb} did not finish on this server"),
        &["Report this SDK host-door failure."],
    )
}

/// The owner's call of `operation`, admitted against the vault's inference
/// policy for the model it names, ready for its seat's ladder.
fn admit(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<MediaRequest> {
    owner_grade(auth, "ai.* media calls are the owner's")?;
    let media = server.ai.model_runtime().media();
    let Some((seat, _)) = media.seat(operation) else {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!("no [models.media.{}] seat serves", operation.as_str()),
            &["Configure the operation's media seat on this server."],
        ));
    };
    let model = match input.model {
        Some(model) => {
            ModelId::new(model).map_err(|_| MemoryError::bad_request("model is not a model id"))?
        }
        None => seat,
    };
    let Some(locality) = media.locality(operation, &model) else {
        return Err(MemoryError::bad_request(format!(
            "{model} serves no {} call here",
            operation.as_str()
        )));
    };
    let mut parts = Vec::new();
    if let Some(prompt) = input.prompt {
        parts.push(MediaPart::Text { text: prompt });
    }
    let decoded = |parts: Vec<oneiron::task_verb::sdk::AiPart>| {
        parts
            .into_iter()
            .map(oneiron::task_verb::sdk::AiPart::into_media)
            .collect::<Option<Vec<_>>>()
    };
    let (Some(sent), Some(references)) = (decoded(input.input), decoded(input.references)) else {
        return Err(MemoryError::bad_request(
            "each part is text, or an image or audio with base64 data",
        ));
    };
    parts.extend(sent);
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
        params: input.params,
    };
    if let Some(key) = request.admission_request().route_selector_override() {
        return Err(MemoryError::bad_request(format!(
            "{key} would pick the model or the route; name the model instead"
        )));
    }
    let context = oneiron::llm::HostInferenceContext {
        binding: oneiron::llm::HostInferenceBinding::Advertised { model, locality },
        extraction_egress: server.extraction_egress.as_deref(),
    };
    let authorized = server
        .vault
        .authorize_raw_inference(request.admission_request(), &context)
        .map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the vault's inference policy refuses this call",
                &["Name a model the vault's inference policy admits."],
            )
        })?;
    request.envelope = authorized.into_request().envelope;
    // The world a caller names does not vouch for what it sends: a
    // fallback judges the call as naming none, as a raw text call is.
    request.envelope.scope.world = None;
    Ok(request)
}

/// A media call's refusal, under the facade's codes: a spent line or window
/// is `BUDGET_SPENT`, a model that did not answer `MODEL_UNAVAILABLE`, and
/// a call its provider refused as written `BAD_REQUEST`.
fn failure(operation: AiOperation, error: &LlmError) -> MemoryError {
    let (code, suggestion) = match error {
        LlmError::BudgetDenied(_) => (MEMORY_CODE_BUDGET_SPENT, "The media meter is spent."),
        LlmError::Retryable(RetryableLlmError::QuotaSpent { .. }) => (
            MEMORY_CODE_BUDGET_SPENT,
            "A usage window or prepaid credit is spent: answer the quota question in GET /v1/ai/status at POST /v1/ai/quota/{question}.",
        ),
        LlmError::Fatal(FatalLlmError::Auth | FatalLlmError::EmptyResponse)
        | LlmError::Retryable(_) => (
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "Retry later, or name another row ai.options lists.",
        ),
        LlmError::Fatal(_) => (
            MEMORY_CODE_BAD_REQUEST,
            "Change the call as its provider asks.",
        ),
    };
    let detail = serde_json::to_string(error).unwrap_or_default();
    MemoryError::new(
        code,
        format!("ai.{}: {error} {detail}", operation.as_str()),
        &[suggestion],
    )
}
