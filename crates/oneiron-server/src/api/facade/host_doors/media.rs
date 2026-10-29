//! The `ai.*` media doors past text: options, image, speech, transcription, embedding and video.
//! `ai_options`, `ai_media_as_owner` and the `ai_video*` doors are its call surface.
//! `crate::api::ai` admits the media call; `oneiron::llm::media` owns its records.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::llm::media::{AiOperation, MediaReplayKey, MediaRequest, Modality};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use oneiron::task_verb::sdk::{
    AiAnswer, AiCallRequest, AiOptions, AiOptionsRequest, AiVideoCancelled, AiVideoJob,
    AiVideoJobRequest, AiVideoTicket, AiVoice,
};
use oneiron::{EntityId, ModelId};

use super::support::{
    Listed, MEDIA_OWNERS, MaybeListed, VIDEO_JOB_OWNERS, failure, internal, owner_grade, rendered,
};
use crate::api::ai::{
    MediaCallParts, MediaCallRefusal, VoiceRefusal, caller_options, prepare_media_call,
};
use crate::auth::CoreAuth;
use crate::models::RungVoices;
use crate::server::{MediaRefusal, SyncServer};

/// `ai.options`: the rows the credential could call now, where each runs,
/// what it takes, its price, the rates its native counts settle at, and
/// what its meter has left (FIX 2942).
///
/// Its answer is the host runtime's seats, rates and meters, each row
/// filtered by the vault's inference-policy admission and priced from the
/// model registry, none of which is a record, or from the installed model
/// catalog pack when the registry holds no row for the model: that pack's
/// source is the one row it lists. A caller shown no option lists none; a
/// catalog that cannot be read leaves the answer unlisted.
pub(crate) async fn ai_options(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiOptionsRequest,
) -> (MemoryResult<AiOptions>, Option<Vec<EntityId>>) {
    let answer = ai_options_answer(server, auth, &input);
    let listed = match &answer {
        Ok(options) if !options.options.is_empty() => server
            .vault
            .model_catalog_source()
            .ok()
            .map(|source| source.into_iter().collect()),
        _ => Some(Vec::new()),
    };
    (answer, listed)
}

pub(super) fn ai_options_answer(
    server: &SyncServer,
    auth: &CoreAuth,
    input: &AiOptionsRequest,
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
    let listed = caller_options(server, auth.is_owner_grade(), operation, &inputs);
    let options = listed
        .options
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|_| internal("ai.options"))?;
    Ok(AiOptions {
        options,
        media_units_left: listed.media_units_left,
    })
}

/// One owner's media call's answer, from its seat's ladder, on the media
/// meter. Only an owner-grade credential reaches it: the facade's, or an
/// MCP `execute_code` run's, whose calls spend under no scope. No room pays
/// for it, so it bills the vault owner (FIX 805).
pub(super) async fn answered(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    owner_grade(auth, MEDIA_OWNERS)?;
    ai_media_as_owner(server, operation, input).await
}

/// [`answered`] past its credential check, for a caller its own door proved
/// the vault's live recorded owner with no credential behind it: an owner's
/// own program (FIX 5911). It bills the vault owner, as his call does.
pub(crate) async fn ai_media_as_owner(
    server: &SyncServer,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    // Its parts come inline; a banked voice is read from its person.
    let sources = match &input.voice {
        Some(AiVoice::Bank { voice_id, .. }) => voice_owner(server, voice_id),
        Some(AiVoice::Stock { .. }) | None => Some(Vec::new()),
    };
    let key = input.idempotency_key.clone();
    let (request, voices) = prepare(server, operation, input)?;
    let replay = owner_replay(key, &request);
    rendered(server, operation, request, voices, None, sources, replay).await
}

/// The partition an owner's own keyed media call is kept in (FIX 2962):
/// every door that reaches these calls is the vault owner's.
const OWNER_REPLAY_PARTITION: &str = "owner";

/// The replay key an owner's call sent as `key` for `request` (FIX 2962);
/// none without a key, or with an empty one.
fn owner_replay(key: Option<String>, request: &MediaRequest) -> Option<MediaReplayKey> {
    let key = key.filter(|key| !key.is_empty())?;
    MediaReplayKey::caller(OWNER_REPLAY_PARTITION.to_owned(), key, request).ok()
}

/// `ai.speech` for a pumped agent run (FIX 3194): prepared as the owner's
/// call is, and spent on `run`, the run's own line, as its other model calls
/// are. The run's door admitted it; no owner credential stands behind it.
pub(crate) async fn ai_speech_for_run(
    server: &SyncServer,
    run: &RunAdmission,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    let (request, voices) = prepare(server, AiOperation::Speech, input)?;
    rendered(server, AiOperation::Speech, request, voices, Some(run), None, None).await
}

/// `ai.image`: one image out; reference images make it an edit. Beside it,
/// no row: its parts come inline and its model from the seat's ladder, and
/// the inference policy only admits it.
pub(crate) async fn ai_image(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> Listed<AiAnswer> {
    record_free(answered(server, auth, AiOperation::Image, input).await)
}

/// `ai.speech`: speech audio out of text, in the voice the call names.
/// Beside it, for a banked voice, the person whose voice it renders: the
/// owner of the voice's identity. The bank's packs, clips, targets and
/// render consent are side tables. A stock voice lists no row, as
/// [`ai_image`] lists none; `None` when the identity cannot be read again.
pub(crate) async fn ai_speech(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MaybeListed<AiAnswer> {
    let banked = match &input.voice {
        Some(AiVoice::Bank { voice_id, .. }) => Some(voice_id.clone()),
        Some(AiVoice::Stock { .. }) | None => None,
    };
    let answer = answered(server, auth, AiOperation::Speech, input).await;
    let rows = match (&answer, banked) {
        (Ok(_), Some(voice_id)) => voice_owner(server, &voice_id),
        _ => Some(Vec::new()),
    };
    (answer, rows)
}

/// The person a banked voice is: its identity's owner, `None` when the
/// identity cannot be read.
pub(super) fn voice_owner(server: &SyncServer, voice_id: &str) -> Option<Vec<EntityId>> {
    server
        .vault
        .voice_identity(voice_id)
        .ok()
        .flatten()
        .map(|identity| vec![identity.owner])
}

/// `ai.transcribe`: text out of speech audio. Beside it, no row, as
/// [`ai_image`] lists none.
pub(crate) async fn ai_transcribe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> Listed<AiAnswer> {
    record_free(answered(server, auth, AiOperation::Transcribe, input).await)
}

/// `ai.embed`: one vector per input text. Beside it, no row, as
/// [`ai_image`] lists none.
pub(crate) async fn ai_embed(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> Listed<AiAnswer> {
    record_free(answered(server, auth, AiOperation::Embed, input).await)
}

/// A media door's answer, which no row derives: beside it, an empty list.
pub(super) fn record_free<T>(answer: MemoryResult<T>) -> Listed<T> {
    (answer, Vec::new())
}

/// `ai.video`: the clip renders as a provider job; the answer is its ticket.
/// It is the owner's call, as [`answered`]'s is, so its job bills the vault
/// owner, and so does each later take-up of it. Beside it, no row: its job
/// lives at its provider and in the media runtime.
pub(crate) async fn ai_video(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> Listed<AiVideoTicket> {
    record_free(ai_video_answer(server, auth, input).await)
}

pub(super) async fn ai_video_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MemoryResult<AiVideoTicket> {
    owner_grade(auth, MEDIA_OWNERS)?;
    ai_video_as_owner(server, input, auth.principal_entity()).await
}

/// [`ai_video`] past its credential check, for an owner's own program
/// ([`ai_media_as_owner`]): its job bills the vault owner. Its row is
/// stamped with `actor`, who asked, when the caller names one (KS-2B2).
pub(crate) async fn ai_video_as_owner(
    server: &SyncServer,
    input: AiCallRequest,
    actor: Option<EntityId>,
) -> MemoryResult<AiVideoTicket> {
    let key = input.idempotency_key.clone();
    let (request, _) = prepare(server, AiOperation::Video, input)?;
    // A repeat under its key answers its first's ticket (FIX 2962).
    let replay = owner_replay(key, &request);
    let ticket = server
        .ai
        .model_runtime()
        .media()
        // Its parts come inline: it reads no row.
        .submit_replayed(request, None, actor, Some(Vec::new()), replay)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoTicket {
        job: ticket.job,
        model: ticket.model,
        operation: ticket.operation,
    })
}

/// `ai.video.poll`: where a video job stands; a finished one answers with
/// its clip on every poll until `ai.video.cancel` deletes it. Beside it, no
/// row, as [`ai_video`] lists none.
pub(crate) async fn ai_video_poll(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> Listed<AiVideoJob> {
    record_free(ai_video_poll_answer(server, auth, input).await)
}

pub(super) async fn ai_video_poll_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoJob> {
    owner_grade(auth, VIDEO_JOB_OWNERS)?;
    ai_video_poll_as_owner(server, input).await
}

/// [`ai_video_poll`] past its credential check, for an owner's own program
/// ([`ai_media_as_owner`]).
pub(crate) async fn ai_video_poll_as_owner(
    server: &SyncServer,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoJob> {
    let state = server
        .ai
        .model_runtime()
        .media()
        .poll(&input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(state.into())
}

/// `ai.video.cancel`: stops a video job at its provider. Beside it, no
/// row, as [`ai_video`] lists none.
pub(crate) async fn ai_video_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> Listed<AiVideoCancelled> {
    record_free(ai_video_cancel_answer(server, auth, input).await)
}

pub(super) async fn ai_video_cancel_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoCancelled> {
    owner_grade(auth, VIDEO_JOB_OWNERS)?;
    ai_video_cancel_as_owner(server, input).await
}

/// [`ai_video_cancel`] past its credential check, for an owner's own
/// program ([`ai_media_as_owner`]).
pub(crate) async fn ai_video_cancel_as_owner(
    server: &SyncServer,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoCancelled> {
    server
        .ai
        .model_runtime()
        .media()
        .cancel(&input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoCancelled { job: input.job })
}

/// A call of `operation`, prepared and admitted as `/v1/ai/<operation>`
/// prepares it ([`prepare_media_call`]), each refusal under the facade's
/// codes. Its caller's door admitted the caller: the owner's
/// ([`answered`], [`ai_media_as_owner`]) or a run's ([`ai_speech_for_run`]).
pub(super) fn prepare(
    server: &SyncServer,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<(MediaRequest, Option<RungVoices>)> {
    let model = match input.model {
        Some(model) => Some(
            ModelId::new(model).map_err(|_| MemoryError::bad_request("model is not a model id"))?,
        ),
        None => None,
    };
    let decoded = |parts: Vec<oneiron::task_verb::sdk::AiPart>| {
        parts
            .into_iter()
            .map(oneiron::task_verb::sdk::AiPart::into_media)
            .collect::<Option<Vec<_>>>()
    };
    let call = MediaCallParts {
        model,
        prompt: input.prompt,
        input: decoded(input.input),
        references: decoded(input.references),
        params: input.params,
        voice: input.voice,
    };
    prepare_media_call(server, operation, call).map_err(|refused| media_refused(operation, refused))
}

/// A refused media call, under the facade's codes: no seat is
/// `MODEL_UNAVAILABLE`, the vault's inference policy `FORBIDDEN`, a voice
/// as [`voice_refused`] says, and the call's own shape `BAD_REQUEST`.
pub(super) fn media_refused(operation: AiOperation, refused: MediaCallRefusal) -> MemoryError {
    let unserved = |model: &str| {
        MemoryError::bad_request(format!(
            "{model} serves no {} call here",
            operation.as_str()
        ))
    };
    match refused {
        MediaCallRefusal::NoSeat => MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!("no [models.media.{}] seat serves", operation.as_str()),
            &["Configure the operation's media seat on this server."],
        ),
        MediaCallRefusal::UnservedModel(model) => unserved(&model.to_string()),
        MediaCallRefusal::Admission(MediaRefusal::UnknownModel) => unserved("the model"),
        MediaCallRefusal::Voice(refused) => voice_refused(refused),
        MediaCallRefusal::InvalidPart => {
            MemoryError::bad_request("each part is text, or an image or audio with base64 data")
        }
        MediaCallRefusal::Admission(MediaRefusal::SelectorOverride(key)) => {
            MemoryError::bad_request(format!(
                "{key} would pick the model or the route; name the model instead"
            ))
        }
        MediaCallRefusal::Admission(MediaRefusal::Denied(_)) => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the vault's inference policy refuses this call",
            &["Name a model the vault's inference policy admits."],
        ),
    }
}

/// A refused voice, under the facade's codes: a banked voice no rung holds
/// is the bank's state (`INVALID_STATE`), any other refusal `BAD_REQUEST`.
pub(super) fn voice_refused(refused: VoiceRefusal) -> MemoryError {
    let (code, suggestion) = match refused {
        VoiceRefusal::NotSpeech => (MEMORY_CODE_BAD_REQUEST, "Name a voice on ai.speech alone."),
        VoiceRefusal::Unnamed => (MEMORY_CODE_BAD_REQUEST, "Name the provider's voice."),
        VoiceRefusal::NotProvisioned => (
            MEMORY_CODE_INVALID_STATE,
            "Provision the voice on a target this call's ladder reaches: POST /v1/ai/voices/{voice_id}/targets/{target}.",
        ),
    };
    MemoryError::new(code, refused.message(), &[suggestion])
}
