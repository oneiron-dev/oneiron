//! The `ai.*` media doors past text: options, image, speech, transcription, embedding and video.
//! `ai_options`, `ai_media_as_owner`, `ai_media_for_run` and the `ai_video*` doors are its call
//! surface. A code-mode run's call spends on the line its dispatch bound (`with_calling_line`).
//! `crate::api::ai` admits the media call; `oneiron::llm::media` owns its records.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::llm::media::{AiOperation, MediaRequest, Modality};
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
    Listed, MEDIA_OWNERS, MaybeListed, RUN_LINE_SPENT, VIDEO_JOB_OWNERS, failure, internal,
    owner_grade, rendered,
};
use crate::api::ai::{
    CallerOptions, MediaCallParts, MediaCallRefusal, VoiceRefusal, caller_options,
    granted_operations, line_options, prepare_media_call, video_granted_agent,
};
use crate::auth::CoreAuth;
use crate::models::RungVoices;
use crate::server::{MediaRefusal, SyncServer};

tokio::task_local! {
    /// The line the code-mode run calling an `ai.*` door spends on (FIX
    /// 780): code mode's own meter, under the run's name, which the run's
    /// verb dispatch bound. A request never names it.
    static CALLING_LINE: RunAdmission;
}

/// Runs `call` as a code-mode run on `line`: every `ai.*` door inside it
/// spends on that line, as the run's steps do, instead of the owner's media
/// meter. `None` runs `call` as it is.
pub(crate) async fn with_calling_line<F: std::future::Future>(
    line: Option<RunAdmission>,
    call: F,
) -> F::Output {
    match line {
        Some(line) => CALLING_LINE.scope(line, call).await,
        None => call.await,
    }
}

/// The line the calling code-mode run spends on, when its dispatch bound one.
pub(crate) fn calling_line() -> Option<RunAdmission> {
    CALLING_LINE.try_with(Clone::clone).ok()
}

/// `ai.options`: the rows the credential could call now, where each runs,
/// what it takes, its price, the rates its native counts settle at, and
/// what its meter has left (FIX 2942). A code-mode run's rows are the media
/// rows its line pays for, with what that line has left (FIX 780).
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
    let (operation, inputs) = options_filter(input)?;
    let listed = match calling_line() {
        // An owner-grade credential still reaches the raw text routes.
        Some(line) => line_options(
            server,
            Some(line.read().remaining_units),
            operation,
            &inputs,
            |row_operation| row_operation != AiOperation::Text || auth.is_owner_grade(),
        ),
        None => caller_options(
            server,
            auth.is_owner_grade(),
            &granted_operations(server, auth),
            operation,
            &inputs,
        ),
    };
    options_answer(listed)
}

/// `ai.options` for an owner's own program (FIX 6083): the media rows its
/// owner rows and its `ai.speech` call, each on `line`, its run's line, with
/// what that line has left. A run its door bound no line to calls its media
/// rows on the owner's media meter, with what that meter has left, and no
/// speech.
pub(crate) fn ai_options_for_program(
    server: &SyncServer,
    line: Option<&RunAdmission>,
    input: &AiOptionsRequest,
) -> MemoryResult<AiOptions> {
    let (operation, inputs) = options_filter(input)?;
    let listed = match line {
        Some(line) => line_options(
            server,
            Some(line.read().remaining_units),
            operation,
            &inputs,
            |row_operation| row_operation != AiOperation::Text,
        ),
        None => line_options(
            server,
            server.ai.model_runtime().media().units_left(),
            operation,
            &inputs,
            |row_operation| !matches!(row_operation, AiOperation::Text | AiOperation::Speech),
        ),
    };
    options_answer(listed)
}

/// The operation and inputs an `ai.options` request narrows its rows to.
fn options_filter(
    input: &AiOptionsRequest,
) -> MemoryResult<(Option<AiOperation>, BTreeSet<Modality>)> {
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
    Ok((operation, inputs))
}

fn options_answer(listed: CallerOptions) -> MemoryResult<AiOptions> {
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

/// One media call's answer, from its seat's ladder. A code-mode run's call
/// spends on the run's line its dispatch bound, as its steps do (FIX 780):
/// the credential's own binding and live gate admitted it there. Any other
/// call is the owner's, on the media meter, and only an owner-grade
/// credential reaches it, or an agent whose live Grant the owner minted
/// names `operation` ([`owner_or_granted`]). No room pays for it, so it
/// bills the vault owner (FIX 805).
pub(super) async fn answered(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    if let Some(line) = calling_line() {
        return ai_media_for_run(server, &line, operation, input).await;
    }
    owner_or_granted(server, auth, operation, MEDIA_OWNERS)?;
    ai_media_as_owner(server, operation, input).await
}

/// [`owner_grade`]'s check at the owner's door for `operation`, which also
/// admits an agent whose live Grant the owner minted names the operation
/// (FIX 3208): its call is then the owner's, as he minted it. Any other
/// caller is refused with `message`, as before.
fn owner_or_granted(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    message: &str,
) -> MemoryResult<()> {
    if granted_operations(server, auth).contains(&operation) {
        return Ok(());
    }
    owner_grade(auth, message)
}

/// [`answered`] past its credential check, for a caller its own door proved
/// the vault's live recorded owner with no credential behind it: an owner's
/// own program whose run binds no line (FIX 5911). It bills the vault
/// owner, as his call does.
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
    let (request, voices) = prepare(server, operation, input)?;
    rendered(server, operation, request, voices, None, sources).await
}

/// One media call of a program's run (FIX 3194, FIX 780, FIX 6083):
/// prepared as the owner's call is, and spent on `run`, the run's own line,
/// as its other model calls are. The run's door admitted it; no owner
/// credential stands behind it.
pub(crate) async fn ai_media_for_run(
    server: &SyncServer,
    run: &RunAdmission,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    let (request, voices) = prepare(server, operation, input)?;
    rendered(server, operation, request, voices, Some(run), None).await
}

/// `ai.speech` for a pumped agent run (FIX 3194): [`ai_media_for_run`]'s.
pub(crate) async fn ai_speech_for_run(
    server: &SyncServer,
    run: &RunAdmission,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    ai_media_for_run(server, run, AiOperation::Speech, input).await
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
/// A code-mode run's job spends on its line, as [`answered`]'s call does
/// (FIX 780); any other is the owner's, so its job bills the vault owner,
/// and so does each later take-up of it. Beside it, no row: its job lives
/// at its provider and in the media runtime.
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
    if let Some(line) = calling_line() {
        return ai_video_for_run(server, &line, input, auth.principal_entity()).await;
    }
    owner_or_granted(server, auth, AiOperation::Video, MEDIA_OWNERS)?;
    ai_video_as_owner(server, input, auth.principal_entity()).await
}

/// [`ai_video`] for a program's run (FIX 780, FIX 6083): its job is
/// submitted on `run`, the run's own line, which holds it until it ends and
/// settles its end, its cancel and its take-up after a restart. Its row is
/// stamped with `actor`, who asked, when the caller names one (KS-2B2).
pub(crate) async fn ai_video_for_run(
    server: &SyncServer,
    run: &RunAdmission,
    input: AiCallRequest,
    actor: Option<EntityId>,
) -> MemoryResult<AiVideoTicket> {
    let (request, _) = prepare(server, AiOperation::Video, input)?;
    let ticket = server
        .ai
        .model_runtime()
        .media()
        .submit_run_admitted(run, request, actor)
        .await
        .map_err(|error| {
            let mut refusal = failure(AiOperation::Video, &error);
            if matches!(error, oneiron::LlmError::BudgetDenied(_)) {
                refusal.suggestions = vec![RUN_LINE_SPENT.to_owned()];
            }
            refusal
        })?;
    Ok(AiVideoTicket {
        job: ticket.job,
        model: ticket.model,
        operation: ticket.operation,
    })
}

/// [`ai_video`] past its credential check, for an owner's own program whose
/// run binds no line ([`ai_media_as_owner`]): its job bills the vault
/// owner. Its row is stamped with `actor`, who asked, when the caller names
/// one (KS-2B2).
pub(crate) async fn ai_video_as_owner(
    server: &SyncServer,
    input: AiCallRequest,
    actor: Option<EntityId>,
) -> MemoryResult<AiVideoTicket> {
    let (request, _) = prepare(server, AiOperation::Video, input)?;
    let ticket = server
        .ai
        .model_runtime()
        .media()
        // Its parts come inline: it reads no row.
        .submit(request, None, actor, Some(Vec::new()))
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoTicket {
        job: ticket.job,
        model: ticket.model,
        operation: ticket.operation,
    })
}

/// `ai.video.poll`: where a video job stands; a finished one answers with
/// its clip on every poll until `ai.video.cancel` deletes it. An owner-grade
/// credential reaches every job; a code-mode run of any other credential
/// reaches the jobs its own run submitted (FIX 780), and an agent the
/// owner's `ai.video` Grant admits the jobs it asked for (FIX 3208). Beside
/// it, no row, as [`ai_video`] lists none.
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
    if !auth.is_owner_grade()
        && let Some(line) = calling_line()
    {
        return ai_video_poll_for_run(server, &line, input).await;
    }
    if let Some(agent) = video_granted_agent(server, auth) {
        let state = server
            .ai
            .model_runtime()
            .media()
            .poll_asked_by(agent, &input.job)
            .await
            .map_err(|error| failure(AiOperation::Video, &error))?;
        return Ok(state.into());
    }
    owner_grade(auth, VIDEO_JOB_OWNERS)?;
    ai_video_poll_as_owner(server, input).await
}

/// [`ai_video_poll`] for a run that is not the owner's: a job its own run
/// submitted on `run`, its line (FIX 780); any other job is no job of the
/// run's. A pumped run's agent the owner's `ai.video` Grant names reaches
/// its jobs so too (FIX 3208).
pub(crate) async fn ai_video_poll_for_run(
    server: &SyncServer,
    run: &RunAdmission,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoJob> {
    let state = server
        .ai
        .model_runtime()
        .media()
        .poll_on_line(run, &input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(state.into())
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

/// `ai.video.cancel`: stops a video job at its provider, reaching a job as
/// [`ai_video_poll`] does. Beside it, no row, as [`ai_video`] lists none.
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
    if !auth.is_owner_grade()
        && let Some(line) = calling_line()
    {
        return ai_video_cancel_for_run(server, &line, input).await;
    }
    if let Some(agent) = video_granted_agent(server, auth) {
        server
            .ai
            .model_runtime()
            .media()
            .cancel_asked_by(agent, &input.job)
            .await
            .map_err(|error| failure(AiOperation::Video, &error))?;
        return Ok(AiVideoCancelled { job: input.job });
    }
    owner_grade(auth, VIDEO_JOB_OWNERS)?;
    ai_video_cancel_as_owner(server, input).await
}

/// [`ai_video_cancel`] for a run that is not the owner's, reaching a job as
/// [`ai_video_poll_for_run`] does.
pub(crate) async fn ai_video_cancel_for_run(
    server: &SyncServer,
    run: &RunAdmission,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoCancelled> {
    server
        .ai
        .model_runtime()
        .media()
        .cancel_on_line(run, &input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoCancelled { job: input.job })
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
/// ([`answered`], [`ai_media_as_owner`]) or a run's ([`ai_media_for_run`]).
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
