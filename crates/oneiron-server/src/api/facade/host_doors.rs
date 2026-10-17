//! The host doors of the verb-table rows only a server's own state answers:
//! the owner's `vault.packs.put`, `vault.hooks.replay` and
//! `vault.authority.audit`, the `ai.*` model calls past text, and
//! `ai.verdict` through the host's decision ladder. The
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
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use oneiron::runtime_hooks::HookVerdict;
use oneiron::task_verb::sdk::{
    AiAnswer, AiCallRequest, AiOptions, AiOptionsRequest, AiVerdict, AiVerdictRequest,
    AiVideoCancelled, AiVideoJob, AiVideoJobRequest, AiVideoTicket, HookReplayRow,
    HooksReplayRequest, PackPutReceipt, PackPutRequest,
};
use oneiron::voice_cascade::media::BankVoiceBinding;
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EdgeActorClass, EntityId, FatalLlmError, LlmError,
    ModelId, ModelTierRef, ResponseFormat, RetryableLlmError, TierPrecedence,
};

use oneiron::lens::{LensActivateRequest, LensDeactivateRequest};
use oneiron::receipt::LensActivationReceipt;
use oneiron::task_verb::sdk::{
    PackSetupAnswerRequest, PackSetupReceipt, PackSetupRequest, PackSetupVerifyRequest,
};

use crate::api::ai::{VoiceRefusal, bind_voice};
use crate::auth::CoreAuth;
use crate::builtin_host::HostConnectionChecks;
use crate::server::SyncServer;

// The shared-vault doors live beside these; the generated callers name them here.
pub(crate) use super::shared_act_doors::*;
// The shared-vault invitation doors (OF-531) too.
pub(crate) use super::shared_member_doors::*;
// The owner's legal-hold doors (OF-470) too.
pub(crate) use super::legal_hold_doors::*;
// The owner's guest revoke door (OF-232) too.
pub(crate) use super::guest_doors::*;
// The weave lens's human doors, likewise.
pub(crate) use super::weave_doors::*;
// The graph ask and standing-question doors (OF-506), likewise.
pub(crate) use super::graph_ask_doors::*;
// The share doors past create (OF-491), likewise.
pub(crate) use super::share_doors::*;
// The role-holder decision-ask doors (OF-493), likewise.
pub(crate) use super::decision_ask_doors::*;
// The vault shape's apply door (ARCH-0070), likewise.
pub(crate) use super::vault_shape_doors::*;
// The owner's embedding-space doors (OF-370), likewise.
pub(crate) use super::embedding_space_doors::*;
// The owner's fan-out ruling doors (OF-393), likewise.
pub(crate) use super::fanout_doors::*;
// The owner's learned-setting doors, likewise.
pub(crate) use super::setting_doors::*;
// The owner's historical secret lift sweep door (OF-067), likewise.
pub(crate) use super::secret_lift_doors::*;
// The owner's root wave door (OF-427), likewise.
pub(crate) use super::wave_doors::*;
// The owner's context-widen proposal doors (OF-568), likewise.
pub(crate) use super::widen_proposal_doors::*;
// The app's policy-action doors (OF-181), likewise.
pub(crate) use super::policy_doors::*;
// The generic connector call's door (ONE-2510), likewise.
pub(crate) use super::connector_call_doors::*;
// The message reaction door (OF-181), likewise.
pub(crate) use super::reaction_doors::*;
// The core write doors (OF-181), likewise.
pub(crate) use super::core_write_doors::*;
// The default lens's door, which holds its card's frame (OF-181), likewise.
pub(crate) use super::ui_action_routes::vault_lenses_default;

/// `vault.packs.put`: the owner installs a pack folder, or replaces the one
/// installed under its name, under the proof `/v1/owner` takes from the
/// request. The put is the consent for the pack's hooks.
pub(crate) async fn vault_packs_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.put")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::put_pack_as_owner(server.vault(), &owner, input)
    })
    .await
    .map_err(|_| internal("vault.packs.put"))?
}

/// `vault.artifacts.review_slides`: reviews an artifact's head through the
/// host's decide() ladder as the bound actor, from the host's starting dial
/// and bands, and holds the proposal for Keep or Discard. The ladder runs on
/// a blocking thread, one call per unit.
pub(crate) async fn vault_artifacts_review_slides(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::blob_artifact::SlideReviewSubmit,
) -> MemoryResult<oneiron::blob_artifact::SlideReviewOutcome> {
    let (actor, class) = slide_reviewer(auth)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        let memory = crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality());
        let host = server.decision_host();
        memory.artifacts_review_slides_through(
            &input,
            &crate::decision_artifact::HostUnitDecider::new(
                &server,
                class,
                "vault.artifacts.review_slides",
            ),
            host.dial(oneiron::llm::decision::DecisionRung::Big),
            &host.bands(),
        )
    })
    .await
    .map_err(|_| internal("vault.artifacts.review_slides"))?
}

/// The principal a slide review binds its proposal to.
fn slide_reviewer(auth: &CoreAuth) -> MemoryResult<(EntityId, EdgeActorClass)> {
    super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a slide review binds its proposal to an authenticated principal",
            &["Present a slip paired from a link created with --principal-ref."],
        )
    })
}

/// `vault.artifacts.body.deck.preview`: the asked slides of a deck's head,
/// drawn by this host's review renderer on a blocking thread, for a
/// credential that reads the artifact.
pub(crate) async fn vault_artifacts_body_deck_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::office_body::DeckPreviewRequest,
) -> MemoryResult<oneiron::office_body::DeckPreview> {
    let (actor, class) = super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a deck preview reads as the credential's own principal",
            &["Present a slip paired with a principal ref and an actor class."],
        )
    })?;
    if let Ok(artifact) = EntityId::from_hex(&input.artifact_ref)
        && !auth.can_read_entity(&server.vault, &artifact)?
    {
        return Err(oneiron::Error::EntityNotFound.into());
    }
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality())
            .artifacts_body_deck_preview(
                &input,
                crate::slide_render::host_renderer().map(|renderer| {
                    renderer as &dyn oneiron::edit_roundtrip::slides_review::SlideRenderer
                }),
            )
    })
    .await
    .map_err(|_| internal("vault.artifacts.body.deck.preview"))?
}

/// `vault.authority.audit`: one page of the dated AUTHORITY_LOG audit, the
/// owner's view under the proof `/v1/owner` takes from the request.
pub(crate) async fn vault_authority_audit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::receipt::AuthorityAuditQuery,
) -> MemoryResult<oneiron::receipt::AuthorityAuditPage> {
    let owner = owner_proof(auth, server, "vault.authority.audit")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        server
            .vault()
            .authority_audit(&owner, &input)
            .map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal("vault.authority.audit"))?
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

/// One media call's answer, from its seat's ladder. A banked voice
/// withdrawn or re-recorded while it rendered is not handed back.
async fn answered(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    let (request, binding) = admit(server, auth, operation, input)?;
    let response = server
        .ai
        .model_runtime()
        .media()
        .run(request)
        .await
        .map_err(|error| failure(operation, &error))?;
    if binding.is_some_and(|binding| !binding.is_current(&server.vault)) {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the voice was withdrawn or its clone replaced while it rendered",
            &["Provision the voice again, then repeat the call."],
        ));
    }
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

/// `ai.speech`: speech audio out of text, in the voice the call names.
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
    let (request, _) = admit(server, auth, AiOperation::Video, input)?;
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
/// its clip on every poll until `ai.video.cancel` deletes it.
pub(crate) async fn ai_video_poll(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoJob> {
    owner_grade(auth, VIDEO_JOB_OWNERS)?;
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
    owner_grade(auth, VIDEO_JOB_OWNERS)?;
    server
        .ai
        .model_runtime()
        .media()
        .cancel(&input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoCancelled { job: input.job })
}

/// `self.memory.diary.query`: the caller reads an agent's diary, stating a
/// reason the agent sees in its read log (`Memory::read_agent_diary`). The
/// caller's `diary.read` Grants decide what it gets. A person reads with
/// their authentication, so the vault owner's own credential carries the
/// proof `/v1/owner` takes from the request; any other caller passes none
/// and the gate decides: an agent or system reads as itself, and a person
/// without the proof is refused.
pub(crate) async fn self_memory_diary_query(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::DiaryQueryRequest,
) -> MemoryResult<oneiron::task_verb::sdk::DiaryQueryOutcome> {
    let owner = crate::api::owner_routes::owner(auth, server).ok();
    let (actor, class) = diary_reader(auth)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        let memory = crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality());
        oneiron::task_verb::sdk::diary_query_as(&memory, owner.as_ref(), input)
    })
    .await
    .map_err(|_| internal("self.memory.diary.query"))?
}

/// The principal a diary query reads as.
fn diary_reader(auth: &CoreAuth) -> MemoryResult<(EntityId, EdgeActorClass)> {
    super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "self.memory.diary.query reads as the credential's own principal",
            &["Present a slip paired with a principal ref and an actor class."],
        )
    })
}

/// `ai.verdict`: the caller's own typed question through the host's
/// decision ladder, asked for the caller: the slip's principal, or the
/// vault's own owner for an owner-grade credential that names none. Its
/// evidence is read under the caller's own scoped read
/// ([`crate::decision_verdict::run_verdict`]); a screenshot the calling
/// code run's browser holds comes from that browser.
pub(crate) async fn ai_verdict(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVerdictRequest,
) -> MemoryResult<AiVerdict> {
    let (principal, class) = asking(auth, server)?;
    let held = crate::decision_verdict::HeldImage::in_task(input.image.as_deref());
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        let reader = crate::api::credential_memory(&server.vault, Some(&auth), principal, class)
            .at(auth.locality());
        // An image is pulled through the caller's own lane before any model
        // reads it, unless it is the run's own held screenshot.
        let lane = match (&input.image, &held) {
            (Some(_), None) => Some(
                crate::api::scoped_read_for_core_auth(&server.vault, &auth).map_err(|_| {
                    MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "ai.verdict reads an image under the caller's scoped read",
                        &["Present a credential that can read the image."],
                    )
                })?,
            ),
            _ => None,
        };
        crate::decision_verdict::run_verdict(
            &server,
            principal,
            class,
            &reader,
            lane.as_ref(),
            held,
            &input,
        )
    })
    .await
    .map_err(|_| internal("ai.verdict"))?
}

/// `vault.hooks.replay`: the owner replays a hook over past facts or its
/// saved verb runs, under the proof `/v1/owner` takes from the request, on
/// the hook sandbox serve runs its hooks on. A dry run: nothing lands. A fact
/// no run pinned previews a generative hook's verdicts on serve's own ladder.
pub(crate) async fn vault_hooks_replay(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HooksReplayRequest,
) -> MemoryResult<Vec<HookReplayRow>> {
    let owner = owner_proof(auth, server, "vault.hooks.replay")?;
    let Some(runtime) = server.hook_runtime.get().cloned() else {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "no hook sandbox runs on this server",
            &["Serve with fact hooks on (no --no-hooks), on a build with the code sandbox."],
        ));
    };
    let verdict = replay_verdict(server);
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::replay_hooks_as_owner(
            server.vault(),
            &owner,
            runtime.as_ref(),
            verdict,
            &input,
        )
    })
    .await
    .map_err(|_| internal("vault.hooks.replay"))?
}

/// The verdict host a replay's preview asks: the one the fact-hook runner
/// asks.
#[cfg(feature = "code-sandbox-wasmtime")]
fn replay_verdict(server: &Arc<SyncServer>) -> Option<Arc<dyn HookVerdict>> {
    Some(Arc::new(crate::hook_verdict::ServerHookVerdict::new(
        server,
    )))
}

/// No hook sandbox runs on this build, so no replay reaches a verdict.
#[cfg(not(feature = "code-sandbox-wasmtime"))]
fn replay_verdict(_server: &Arc<SyncServer>) -> Option<Arc<dyn HookVerdict>> {
    None
}

/// Whom a host-door question is asked for: the slip's principal, or the
/// vault's own owner for an owner-grade credential that names none, as a
/// chat turn's writer is.
fn asking(auth: &CoreAuth, server: &SyncServer) -> MemoryResult<(EntityId, EdgeActorClass)> {
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "ai.verdict is asked for an authenticated principal",
            &["Present a slip that names its principal, or the owner's own credential."],
        )
    };
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| refused())?,
        None if auth.is_owner_grade() => server
            .vault
            .ensure_embedded_owner_actor()
            .map_err(|_| refused())?,
        None => return Err(refused()),
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    Ok((actor, class))
}

/// The refusal of an `ai.*` media call from a credential short of the owner's.
const MEDIA_OWNERS: &str = "ai.* media calls are the owner's";
/// The refusal of a video job's poll or cancel from one short of it.
const VIDEO_JOB_OWNERS: &str = "video jobs are the owner's";

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

/// The authority check host-door row `verb`'s own door runs first: the
/// owner's proof, a person's proof, a bound principal or an owner-grade
/// credential. The facade runs it before the row's pre chain, so a hook
/// never fires on a call the door refuses; the door runs it again for the
/// proof it acts under. A row whose door has no such check passes.
pub(super) fn door_admits(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
    match verb {
        "vault.packs.put"
        | "vault.authority.audit"
        | "vault.hooks.replay"
        | "vault.lenses.activate"
        | "vault.lenses.deactivate"
        | "vault.packs.setup.prepare"
        | "vault.packs.setup.get"
        | "vault.packs.setup.answer"
        | "vault.packs.setup.verify"
        | "vault.authority.handoff_alarms"
        | "vault.authority.handoff_alarms.acknowledge"
        | "vault.legal_holds.place"
        | "vault.legal_holds.widen"
        | "vault.legal_holds.list"
        | "vault.legal_holds.log"
        | "vault.legal_holds.lift_and_erase"
        | "vault.settings.learning"
        | "vault.settings.learning.put"
        | "vault.settings.learning.clear"
        | "vault.widen_proposals"
        | "vault.widen_proposals.approve"
        | "vault.widen_proposals.decline"
        | "vault.settings.wake_policy.set" => owner_proof(auth, server, verb).map(drop),
        "vault.shared.propose_delete"
        | "vault.shared.propose_transfer"
        | "vault.shared.propose_remove_owner"
        | "vault.shared.execute"
        | "vault.shared.receipt"
        | "vault.shared.outcomes"
        | "vault.members.add"
        | "vault.members.change"
        | "vault.members.remove"
        | "vault.members.leave"
        | "vault.members.invitations"
        | "vault.members.accept"
        | "vault.members.decline"
        | "vault.members.withdraw_invitation"
        | "vault.members.invitation_slip"
        | "vault.shared.object"
        | "vault.shared.withdraw_objection"
        | "vault.shared.started"
        | "vault.shared.matured"
        | "vault.shared.erase_ask"
        | "vault.shared.erase_asks"
        | "vault.shared.close_erase_ask"
        | "vault.records.erase_preview"
        | "vault.records.erase_confirm" => {
            super::shared_act_doors::person(server, auth, verb).map(drop)
        }
        "vault.artifacts.review_slides" => slide_reviewer(auth).map(drop),
        "self.memory.diary.query" => diary_reader(auth).map(drop),
        "vault.decisions.asks.answer" | "vault.decisions.asks.climb" | "self.decisions.asks" => {
            super::decision_ask_doors::holder(auth, verb).map(drop)
        }
        "ai.verdict" => asking(auth, server).map(drop),
        "ai.image" | "ai.speech" | "ai.transcribe" | "ai.embed" | "ai.video" => {
            owner_grade(auth, MEDIA_OWNERS)
        }
        "ai.video.poll" | "ai.video.cancel" => owner_grade(auth, VIDEO_JOB_OWNERS),
        _ => Ok(()),
    }
}

pub(super) fn internal(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{verb} did not finish on this server"),
        &["Report this SDK host-door failure."],
    )
}

/// The owner's call of `operation`, admitted against the vault's inference
/// policy for the model it names, ready for its seat's ladder, with the
/// banked voice it renders in, if any (bound as `/v1/ai/speech` binds it).
fn admit(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<(MediaRequest, Option<BankVoiceBinding>)> {
    owner_grade(auth, MEDIA_OWNERS)?;
    let media = server.ai.model_runtime().media();
    let Some((seat, _)) = media.seat(operation) else {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!("no [models.media.{}] seat serves", operation.as_str()),
            &["Configure the operation's media seat on this server."],
        ));
    };
    let mut model = match input.model {
        Some(model) => {
            ModelId::new(model).map_err(|_| MemoryError::bad_request("model is not a model id"))?
        }
        None => seat,
    };
    let unserved = |model: &ModelId| {
        MemoryError::bad_request(format!(
            "{model} serves no {} call here",
            operation.as_str()
        ))
    };
    if media.locality(operation, &model).is_none() {
        return Err(unserved(&model));
    }
    let (voice, binding) =
        bind_voice(server, operation, &mut model, input.voice).map_err(voice_refused)?;
    let Some(locality) = media.locality(operation, &model) else {
        return Err(unserved(&model));
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
        voice,
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
    Ok((request, binding))
}

/// A refused voice, under the facade's codes: a banked voice no rung holds
/// is the bank's state (`INVALID_STATE`), any other refusal `BAD_REQUEST`.
fn voice_refused(refused: VoiceRefusal) -> MemoryError {
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

/// The vault owner's proof for an owner's host door, from the request, as
/// `/v1/owner` takes it.
fn owner_proof(
    auth: &CoreAuth,
    server: &SyncServer,
    verb: &str,
) -> MemoryResult<oneiron::consent::AuthenticatedOwner> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })
}

/// `vault.lenses.activate`: the owner selects a proposed lens revision for
/// its pack slot, under the proof `/v1/owner` takes from the request. The
/// owner's confirmation is the consent; an agent can only propose.
pub(crate) async fn vault_lenses_activate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensActivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    let owner = owner_proof(auth, server, "vault.lenses.activate")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || server.vault().activate_lens(&owner, input))
        .await
        .map_err(|_| internal("vault.lenses.activate"))?
}

/// `vault.lenses.deactivate`: the owner clears a pack slot's selected lens,
/// under the same proof. The pack, its skill and the proposal stay.
pub(crate) async fn vault_lenses_deactivate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensDeactivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    let owner = owner_proof(auth, server, "vault.lenses.deactivate")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || server.vault().deactivate_lens(&owner, input))
        .await
        .map_err(|_| internal("vault.lenses.deactivate"))?
}

/// `vault.packs.setup.prepare`: the owner opens, or resumes, a pack's guided
/// setup (OF-378), under the proof `/v1/owner` takes from the request.
/// Opening grants nothing.
pub(crate) async fn vault_packs_setup_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.setup.prepare")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::prepare_pack_setup_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.packs.setup.prepare"))?
}

/// `vault.packs.setup.get`: a pack's guided setup as it stands, under the
/// same proof.
pub(crate) async fn vault_packs_setup_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.setup.get")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::pack_setup_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.packs.setup.get"))?
}

/// `vault.packs.setup.answer`: one answer or card action, under the same
/// proof. The verb never answers `allow` (the owner's review stays at
/// `/v1/owner/packs/setup/answer`), and a store action answers with the
/// owner secrets door; a credential value never passes here.
pub(crate) async fn vault_packs_setup_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupAnswerRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.setup.answer")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        let checks = HostConnectionChecks::new(&server)?;
        oneiron::task_verb::sdk::answer_pack_setup_as_owner(server.vault(), &owner, &input, &checks)
    })
    .await
    .map_err(|_| internal("vault.packs.setup.answer"))?
}

/// `vault.packs.setup.verify`: checks one connection with the engine's fixed
/// read-only provider call for its declared check, under the same proof.
pub(crate) async fn vault_packs_setup_verify(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupVerifyRequest,
) -> MemoryResult<PackSetupReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.setup.verify")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        let checks = HostConnectionChecks::new(&server)?;
        oneiron::task_verb::sdk::verify_pack_setup_as_owner(server.vault(), &owner, &input, &checks)
    })
    .await
    .map_err(|_| internal("vault.packs.setup.verify"))?
}
