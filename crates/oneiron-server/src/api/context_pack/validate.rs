//! A context pack's request checks, run before its verb hooks (FIX 1435).
//! [`validate_context_pack`] checks a request and returns the
//! [`ValidatedContextPack`] that `execute_context_pack` runs.

use super::super::{
    core_engine_error, non_empty_query, parse_entity_id_param, scoped_read_for_core_auth,
    validate_core_query_seeds,
};
use super::builder_controls::{ContextPackRanking, ContextPackTimeWindow};
use super::controls::{ContextPackQueryAffect, CoreContextPackRequest};
use super::input_worker::{
    ResolvedContextInputs, resolve_context_inputs, resolve_context_inputs_here, transferred,
};
use super::interlocutor::RoomAudience;
use super::media_query::DecodedMediaQuery;
use super::narrow_to_core_audience;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::claim::OwnedScopedRead;
use oneiron::reaction::{MAX_REACTION_SIGNAL_PAGE, ReactionSignalPaging};

/// A context pack request that passed every request check, with what the
/// checks resolved (FIX 1435). It owns its reader, so it can wait across the
/// verb hooks. Nothing was spent, disclosed, embedded, built, observed or
/// recorded for it.
pub(crate) struct ValidatedContextPack {
    /// The caller's own read, narrowed to the request's audience.
    pub(super) read: OwnedScopedRead,
    pub(super) req: CoreContextPackRequest,
    pub(super) optional_memory: Option<oneiron::agent_def::OptionalMemory>,
    pub(super) room_id: Option<oneiron::EntityId>,
    pub(super) room: Option<RoomAudience>,
    pub(super) interlocutors: Option<oneiron::InterlocutorSet>,
    pub(super) media: Option<DecodedMediaQuery>,
    pub(super) skill_reliability: Option<oneiron::skill_reliability::SkillReliabilityQuery>,
    pub(super) candidate_limit: usize,
    pub(super) query_affect: Option<oneiron::Vad>,
    pub(super) ranking: ContextPackRanking,
    pub(super) time: ContextPackTimeWindow,
    pub(super) signals: Option<ContextPackSignalRequest>,
}

/// The reaction-signal feed a request asks for, checked (FIX 1435). Its
/// deadline starts only when the feed is read.
pub(super) struct ContextPackSignalRequest {
    pub(super) person: oneiron::EntityId,
    pub(super) since: u64,
    pub(super) room: Option<oneiron::EntityId>,
    pub(super) deadline_ms: Option<u64>,
    pub(super) paging: ReactionSignalPaging,
}

/// The request checks of context pack `req` for `auth` (FIX 1435). The
/// reader, room and contacts resolve on the request's admitted
/// context-input worker. The other checks then run here. Each check is
/// free; the first to fail is the answer.
pub(crate) async fn validate_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    req: CoreContextPackRequest,
) -> Result<ValidatedContextPack, ApiError> {
    check_signals_deadline(&req)?;
    // Every ref the request names resolves under the caller's own read: a
    // room or contact it cannot read is one that does not exist. A room's
    // members read its roster by membership, as their room turns do.
    let scoped_read = scoped_read_for_core_auth(&server.vault, auth)?;
    let inputs = resolve_context_inputs(server, auth, scoped_read, req).await?;
    validated_inputs(server, auth, inputs)
}

/// [`validate_context_pack`] on the calling thread, for a verb hook's
/// rewritten request (FIX 1435). The hook chain's own blocking thread runs
/// it, under the caller's own credential, with the caller's route controls.
pub(crate) fn validate_rewritten_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    req: CoreContextPackRequest,
) -> Result<ValidatedContextPack, ApiError> {
    check_signals_deadline(&req)?;
    let scoped_read = scoped_read_for_core_auth(&server.vault, auth)?;
    let inputs = resolve_context_inputs_here(server, auth, scoped_read, req)?;
    validated_inputs(server, auth, inputs)
}

/// The signal deadline `req` names, checked before its reader is admitted.
fn check_signals_deadline(req: &CoreContextPackRequest) -> Result<(), ApiError> {
    oneiron::memory::caps::check_deadline_ms(req.signals_deadline_ms)
        .map_err(|error| ApiError::bad_request(error.to_string(), Some("signals_deadline_ms")))?;
    if req.signals_deadline_ms.is_some() && req.signals_since.is_none() {
        return Err(ApiError::bad_request(
            "signals_since is required for reaction signals",
            Some("signals_since"),
        ));
    }
    Ok(())
}

/// The checks after `inputs`' reader, room and contacts resolved, in the
/// order the pipeline ran them. The reader returns narrowed to the
/// request's audience: the same state moved, not rebuilt.
fn validated_inputs(
    server: &SyncServer,
    auth: &CoreAuth,
    inputs: ResolvedContextInputs,
) -> Result<ValidatedContextPack, ApiError> {
    let ResolvedContextInputs {
        read,
        req,
        optional_memory,
        room_id,
        room_members,
        room,
        interlocutors,
    } = inputs;
    let scoped_read = read
        .into_borrowed(&server.vault)
        .map_err(|_| ApiError::internal_server_error("context-pack reader return failed"))?;
    let query = non_empty_query(req.query.as_deref());
    // A media query seeds the pack on its own; a vector beside it is still
    // checked.
    validate_core_query_seeds(
        query.or(req.media.as_ref().map(|_| "media")),
        req.query_vector.as_deref(),
    )?;
    let media = req
        .media
        .as_ref()
        .map(|media| media.decode(server.config.limits.retrieval_query_bytes))
        .transpose()?;
    let skill_reliability = req.skill_reliability_query(&server.vault)?;
    let scoped_read = narrow_to_core_audience(
        &server.vault,
        auth,
        scoped_read,
        room_members.as_deref(),
        room.as_ref(),
        interlocutors.as_ref(),
    )?;
    // The caller's own filter binds the pack's reader once its audience is
    // set, before any candidate is read (FIX 3977).
    let request = req
        .filter
        .as_ref()
        .map(oneiron::memory::ReadFilterInput::to_filter);
    let scoped_read = scoped_read.with_read_filter(request.as_ref());
    let candidate_limit = scoped_read
        .search_candidate_limit(req.limit)
        .map_err(|error| {
            tracing::error!(kind = ?error.kind(), "core context-pack scoped read setup failed");
            core_engine_error("core context-pack scoped read setup failed", error)
        })?;
    if let Some(model) = req.executor_model.as_deref() {
        oneiron::skill_reliability::validate_executor(model)
            .map_err(|error| core_engine_error("invalid context-pack executor model", error))?;
    }
    let query_affect = req
        .query_affect
        .map(ContextPackQueryAffect::vad)
        .transpose()?;
    let ranking = ContextPackRanking::checked(req.policy.as_ref())?;
    let time = ContextPackTimeWindow::checked(req.time.as_ref())?;
    let signals = ContextPackSignalRequest::checked(auth, &req, room_id)?;
    Ok(ValidatedContextPack {
        read: transferred(server, scoped_read)?,
        req,
        optional_memory,
        room_id,
        room,
        interlocutors,
        media,
        skill_reliability,
        candidate_limit,
        query_affect,
        ranking,
        time,
        signals,
    })
}

impl ContextPackSignalRequest {
    /// The feed `req` asks for, for `auth`, in room `room` if it names one:
    /// `None` when it names no `signals_since`. Each signal member needs
    /// `signals_since`. The person defaults to the caller, and only an
    /// owner-grade caller reads another person's feed. The page size and
    /// cursor are checked as the feed pages them.
    fn checked(
        auth: &CoreAuth,
        req: &CoreContextPackRequest,
        room: Option<oneiron::EntityId>,
    ) -> Result<Option<Self>, ApiError> {
        let Some(since) = req.signals_since else {
            if req.signals_after.is_some()
                || req.signals_limit.is_some()
                || req.signals_person.is_some()
                || req.signals_deadline_ms.is_some()
            {
                return Err(ApiError::bad_request(
                    "signals_since is required for reaction signals",
                    Some("signals_since"),
                ));
            }
            return Ok(None);
        };
        let person = req
            .signals_person
            .as_deref()
            .or_else(|| auth.principal_ref())
            .ok_or_else(|| {
                ApiError::bad_request("signals_person is required", Some("signals_person"))
            })?;
        if !auth.is_owner_grade() && auth.principal_ref() != Some(person) {
            return Err(ApiError::forbidden_scope("signals_person"));
        }
        let person = parse_entity_id_param(person, "signals_person")?;
        let paging = ReactionSignalPaging::checked(
            req.signals_after.as_deref(),
            req.signals_limit.unwrap_or(MAX_REACTION_SIGNAL_PAGE),
        )
        .map_err(|e| core_engine_error("reaction signal page failed", e))?;
        Ok(Some(Self {
            person,
            since,
            room,
            deadline_ms: req.signals_deadline_ms,
            paging,
        }))
    }
}
