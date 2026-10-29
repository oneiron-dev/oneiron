//! The host doors' shared vocabulary: listings, refusals, proofs, the calling origin and askers.
//! `Listed`, `credential_listing`, `owner_proof` and `refused` are its call surface.
//! The facade's `owner_binding` and `FacadeApiError` define the proofs and errors used here.

use std::sync::Arc;

use oneiron::llm::media::{AiOperation, MediaReplayKey, MediaRequest};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult,
    ProducerRows,
};
use oneiron::task_verb::sdk::AiAnswer;
use oneiron::{EdgeActorClass, EntityId, FatalLlmError, LlmError, RetryableLlmError};

use crate::api::facade::facade_actor;
use crate::auth::CoreAuth;
use crate::models::RungVoices;
use crate::server::SyncServer;

pub(in crate::api::facade) mod owner_action;
pub(in crate::api::facade) mod owner_listing;

/// The principal a slide review binds its proposal to.
pub(super) fn slide_reviewer(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    crate::api::facade::owner_binding::facade_caller_or(server, auth, || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a slide review binds its proposal to an authenticated principal",
            &["Present a slip paired from a link created with --principal-ref."],
        )
    })
}

/// The principal an artifact ask binds its proposal to.
pub(super) fn artifact_asker(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    crate::api::facade::owner_binding::facade_caller_or(server, auth, || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "an artifact ask binds its proposal to an authenticated principal",
            &["Present a slip paired from a link created with --principal-ref."],
        )
    })
}

/// One media call's answer, from its seat's ladder: on `run` when its caller
/// admitted it on a line of its own, which bills that run's payer, else on
/// the media meter as the owner's call ([`answered`]), sourced from
/// `sources`, the rows the call is read from (FIX 11311). A banked voice
/// withdrawn or re-recorded while it rendered, on the rung that answered, is
/// not handed back; nor is a call that found the voice withdrawn everywhere
/// while it waited (FIX 1746). An owner's call known by `replay` answers a
/// repeat from its first answer, unpaid (FIX 2962); a run's call, on its
/// own line, is never replayed.
pub(super) async fn rendered(
    server: &SyncServer,
    operation: AiOperation,
    request: MediaRequest,
    voices: Option<RungVoices>,
    run: Option<&RunAdmission>,
    sources: Option<Vec<EntityId>>,
    replay: Option<MediaReplayKey>,
) -> MemoryResult<AiAnswer> {
    let media = server.ai.model_runtime().media();
    let hint = media.retry_hint(&request, voices.as_ref());
    let answer = match run {
        Some(run) => media.run_admitted(run, request, voices.as_ref()).await,
        None => {
            media
                .run_replayed(request, voices.as_ref(), None, sources, None, replay)
                .await
        }
    };
    let withdrawn = || {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the voice was withdrawn or its clone replaced while it rendered",
            &["Provision the voice again, then repeat the call."],
        )
    };
    match answer {
        Ok(_)
            if voices
                .as_ref()
                .is_some_and(|voices| !voices.answered_current()) =>
        {
            Err(withdrawn())
        }
        Err(_) if voices.as_ref().is_some_and(RungVoices::withdrawn) => Err(withdrawn()),
        Ok(response) => Ok(response.into()),
        Err(error) if error.is_provider_unavailable() => {
            Err(unavailable(operation, &error, hint.seconds()))
        }
        Err(error @ LlmError::BudgetDenied(_)) if run.is_some() => {
            let mut refusal = failure(operation, &error);
            refusal.suggestions = vec![RUN_LINE_SPENT.to_owned()];
            Err(refusal)
        }
        Err(error) => Err(failure(operation, &error)),
    }
}

/// What a run's media call refused for its spent line suggests: it spends
/// the run's own line, not the media meter.
pub(super) const RUN_LINE_SPENT: &str = "The run's spend line is spent.";

/// A media call no offer answered (FIX 3194): `MODEL_UNAVAILABLE`, with the
/// seconds until the first offer that could serve it is back as
/// `retry_after` and in its suggestion. Nothing keeps the call; its caller
/// sends it again.
pub(super) fn unavailable(
    operation: AiOperation,
    error: &LlmError,
    retry_after: u64,
) -> MemoryError {
    let mut refusal = failure(operation, error);
    refusal.suggestions = vec![format!(
        "Retry in {retry_after} s, or name another row ai.options lists."
    )];
    refusal.retry_after = Some(retry_after);
    refusal
}

/// The principal a diary query reads as.
pub(super) fn diary_reader(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    crate::api::facade::owner_binding::facade_caller_or(server, auth, || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "self.memory.diary.query reads as the credential's own principal",
            &["Present a slip paired with a principal ref and an actor class."],
        )
    })
}

/// Whom a host-door question is asked for: the slip's principal, or the
/// owner a self-hosted root or the dev mode acts as, as a chat turn's writer
/// is; a hosted operator's root asks for no one (FIX 2222).
pub(super) fn asking(
    auth: &CoreAuth,
    server: &SyncServer,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "ai.verdict is asked for an authenticated principal",
            &["Present a slip that names its principal, or the owner's own credential."],
        )
    };
    if let Some(action) = crate::api::host_action::host_action_of(server.vault(), auth) {
        let actor = action.map_err(MemoryError::from)?.actor();
        return Ok((actor.entity_ref(), actor.actor_class()));
    }
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| refused())?,
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
pub(super) const MEDIA_OWNERS: &str = "ai.* media calls are the owner's";

/// The refusal of a video job's poll or cancel from one short of it.
pub(super) const VIDEO_JOB_OWNERS: &str = "video jobs are the owner's";

pub(super) fn owner_grade(auth: &CoreAuth, message: &str) -> MemoryResult<()> {
    if auth.is_owner_grade() {
        return Ok(());
    }
    Err(MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        message,
        &["Present a verified, unattenuated owner credential."],
    ))
}

pub(in crate::api::facade) fn internal(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{verb} did not finish on this server"),
        &["Report this SDK host-door failure."],
    )
}

/// A listing host door's answer (`host_door_lists`), beside the rows its
/// reads derived it from, as a plain row's answer lists them (DEC-0005):
/// the rows its caller or its answer names by ref aside. A refusal keeps
/// its typed error, with the rows read before it.
pub(crate) type Listed<T> = (MemoryResult<T>, Vec<EntityId>);

/// [`Listed`] for a door one of whose paths lists none: `None` beside that
/// path's answer ([`ListedRows`]).
pub(crate) type MaybeListed<T> = (MemoryResult<T>, Option<Vec<EntityId>>);

/// The rows a listing door answers beside its result, as every served door
/// releases it by them: a list, or `None` for a call one of whose paths
/// lists none, never an empty list standing in for it.
pub(crate) trait ListedRows {
    /// The rows, `None` when they are unknown.
    fn rows(self) -> Option<Vec<EntityId>>;
}

impl ListedRows for Vec<EntityId> {
    fn rows(self) -> Option<Vec<EntityId>> {
        Some(self)
    }
}

impl ListedRows for Option<Vec<EntityId>> {
    fn rows(self) -> Option<Vec<EntityId>> {
        self
    }
}

/// A refusal before any read: it lists no row.
pub(in crate::api::facade) fn refused<T>(refusal: MemoryError) -> Listed<T> {
    (Err(refusal), Vec::new())
}

/// The rows hex ids name; a value that is no id names none.
pub(in crate::api::facade) fn hex_rows<S: AsRef<str>>(
    ids: impl IntoIterator<Item = S>,
) -> Vec<EntityId> {
    ids.into_iter()
        .filter_map(|hex| EntityId::from_hex(hex.as_ref()).ok())
        .collect()
}

/// `answer` beside the rows `named` reads off it, for a door whose answer
/// derives from no row but those it names (`host_door_lists`). A refusal
/// lists none.
pub(in crate::api::facade) fn naming<T>(
    answer: MemoryResult<T>,
    named: impl FnOnce(&T) -> Vec<EntityId>,
) -> Listed<T> {
    let rows = answer.as_ref().map_or_else(|_| Vec::new(), named);
    (answer, rows)
}

/// `act` off the runtime with a fresh collector, which its handles list
/// into, and beside its answer the rows they listed. A worker that does not
/// finish answers [`internal`] and lists none.
pub(in crate::api::facade) async fn off_runtime_listing<T: Send + 'static>(
    verb: &'static str,
    act: impl FnOnce(&ProducerRows) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    tokio::task::spawn_blocking(move || {
        let producers = ProducerRows::default();
        let answer = act(&producers);
        (answer, producers.take())
    })
    .await
    .unwrap_or_else(|_| refused(internal(verb)))
}

tokio::task_local! {
    /// The host origin of the code run calling a credential-backed door
    /// (Docs #3016): [`credential_listing`]'s fresh handle keeps it, so a
    /// generated program's call never reads as a person's.
    static CALLING_ORIGIN: oneiron::memory::HostWriteOrigin;
}

/// Runs `call` as the code run `origin` binds: every handle
/// [`credential_listing`] builds inside it carries that origin.
pub(crate) async fn with_calling_origin<F: std::future::Future>(
    origin: oneiron::memory::HostWriteOrigin,
    call: F,
) -> F::Output {
    CALLING_ORIGIN.scope(origin, call).await
}

/// `read` off the runtime on the credential's own handle as `caller`, at
/// its locality ([`crate::api::credential_memory`]), listing every row its
/// reads derive the answer from: the one collector the credential-backed
/// host doors share. A calling code run's host origin rides onto the handle.
pub(in crate::api::facade) async fn credential_listing<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    (actor, class): (EntityId, EdgeActorClass),
    verb: &'static str,
    read: impl FnOnce(&SyncServer, &CoreAuth, Memory<'_>) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let (server, auth) = (Arc::clone(server), auth.clone());
    let origin = CALLING_ORIGIN.try_with(Clone::clone).ok();
    off_runtime_listing(verb, move |producers| {
        let memory = crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality())
            .listing_producers(producers);
        let memory = match origin {
            Some(origin) => memory.with_host_origin(origin),
            None => memory,
        };
        read(&*server, &auth, memory)
    })
    .await
}

/// The rows a door reads beside its handle's own reads, as its caller names
/// them: a whole id, or an image handle (`<asset>@<hash>`) by its asset.
/// A short ref is the socket's to resolve, as every named ref is.
pub(in crate::api::facade) fn read_beside<S: AsRef<str>>(
    named: impl IntoIterator<Item = S>,
) -> Vec<EntityId> {
    named
        .into_iter()
        .filter_map(|text| oneiron::memory::ImageHandle::parse(text.as_ref()).ok())
        .map(|handle| handle.asset)
        .collect()
}

/// A media call's refusal, under the facade's codes: a spent line or window
/// is `BUDGET_SPENT`, a model that did not answer `MODEL_UNAVAILABLE`, and
/// a call its provider refused as written `BAD_REQUEST`.
pub(super) fn failure(operation: AiOperation, error: &LlmError) -> MemoryError {
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
pub(in crate::api::facade) fn owner_proof(
    auth: &CoreAuth,
    server: &SyncServer,
    verb: &str,
) -> MemoryResult<oneiron::consent::AuthenticatedOwner> {
    crate::api::facade::owner_binding::facade_owner(server, auth, verb)
}
