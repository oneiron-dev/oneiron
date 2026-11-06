//! An MCP connection's own `describe(self)` (FIX 17594): the self brief of
//! the agent a registered connector credential stands for, read over that
//! connection alone, by the self-brief renderer the credentialed path uses
//! ([`super::describe_self_for_auth`]).
//!
//! It reads the connection's own session observations under its tagged MCP
//! key, never a Core `(principal, session)` key or a session the request
//! body names. The agent's grants, class ceilings and principal resolve as
//! the credentialed path's do. Its credential ceiling is the verified
//! slip's, beside the read key the connector reads under and the
//! connector's registered bounds; its communication ceiling is the slip's
//! comm reach; its pins are the ones its keyframe carries now, by the MCP
//! board's own rules; its scratchpad is the live pad of the session the
//! authenticated request binds. A connection is bound to no dispatch attempt
//! and to no replay run, so its run and parent ceilings, its run's comm
//! reach, its replay bindings and its budget are left out of the brief and
//! named on its one unavailable line.
//!
//! The connection's setup installs that brief in the server's custody under
//! the agent and the connection's stream id, and its page one hands the
//! client the brief's turn-one prefix (FIX 17594 D4, Engine call MCP A).
//! Once that page went out, describe(self) is the delivered brief's tail:
//! the state the connection resolves now is installed again at the brief's
//! epoch and rendered through that custody, the prefix untouched. Before
//! then, and with no installation, the brief is resolved now and rendered
//! whole. The one resolution here, [`connection_brief_reads`] and
//! [`connection_brief_state`], serves the describe and the setup alike.
//!
//! A code-mode durable run on the connection (FIX 17594 D5) has its own
//! brief, resolved by the same preparation with the run's own facts beside
//! the connection's: its replay run is its trusted durable run id
//! (`mcp_code_run_id`), its budget the code-mode line of that run where the
//! host holds one, and it is bound to no dispatch attempt, so it holds no run
//! ceiling. The run's host installs that brief under the agent and the run
//! ([`code_mode_brief_key`]) and keeps it with the durable run. A
//! describe(self) the run's own code makes answers that brief, never the
//! connection's, and never a run a body `session_id` names.

use oneiron::context_board::{BriefConnectorCeiling, People, SelfBriefState, SessionReadSet};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::task_verb::sdk::DescribeRequest;

use super::run_self::{BriefHostFacts, read_people, resolved_state, scratchpad_family};
use crate::api::mcp_gateway::{
    McpCallContext, McpGatewayError, code_mode_line, mcp_api_error, mcp_brief_pins,
    mcp_engine_error, mcp_facade_error, mcp_scoped_read, mcp_session_reads,
};
use crate::error::ApiError;
use crate::mcp::McpResolvedActor;
use crate::server::SyncServer;
use crate::server::self_brief_custody::BriefKey;

/// What one connection's self brief is laid out from: the connection's own
/// session reads and the PEOPLE its credential reads.
pub(crate) struct ConnectionBriefReads {
    pub(crate) reads: SessionReadSet,
    pub(crate) people: People,
}

/// Whether `actor`'s connection has a self brief: an agent's, on a
/// credential no record list narrows. Any other connection's describe(self)
/// is refused, and its setup carries none.
pub(crate) fn connection_has_brief(actor: &McpResolvedActor) -> bool {
    actor.actor_class == oneiron::EdgeActorClass::Agent && actor.has_unrestricted_record_scope()
}

/// The key a connection's self brief is installed under: the agent its
/// credential stands for and the connection's own stream id.
pub(crate) fn connection_brief_key(actor: &McpResolvedActor) -> BriefKey {
    (actor.actor_ref, actor.stream_connection.0.clone())
}

/// The key a code-mode durable run's self brief is installed under: the
/// agent the run's credential stands for and the run, by the trusted id
/// `mcp_code_run_id` derived (FIX 17594 D5), never the stream id or a
/// session label.
pub(crate) fn code_mode_brief_key(actor: &McpResolvedActor, run_id: oneiron::EntityId) -> BriefKey {
    (actor.actor_ref, format!("code-mode:{}", run_id.to_hex()))
}

/// The connection's own session reads, under its tagged MCP key, and the
/// PEOPLE its credential reads.
///
/// # Errors
///
/// The credential holds no scoped read, or PEOPLE did not read.
pub(crate) async fn connection_brief_reads(
    server: &SyncServer,
    actor: &McpCallContext,
) -> Result<ConnectionBriefReads, McpGatewayError> {
    let reads = mcp_session_reads(server, actor).await;
    let read = mcp_scoped_read(&server.vault, actor)?;
    let people = read_people(server, &read).map_err(mcp_facade_error)?;
    Ok(ConnectionBriefReads { reads, people })
}

/// The connection's brief state as it resolves now, over its session
/// `reads`: the agent's grants, class ceilings and principal, and the facts
/// the connection holds (the module doc names them). For a code-mode durable
/// run on the connection, `replay_run` is the run's trusted id and `line` the
/// run's code-mode line where the host holds one (FIX 17594 D5); the
/// connection's own brief passes neither.
///
/// # Errors
///
/// The request holds no verified auth, the credential holds no scoped read,
/// or the state did not resolve.
pub(crate) fn connection_brief_state(
    server: &SyncServer,
    actor: &McpCallContext,
    reads: &SessionReadSet,
    replay_run: Option<oneiron::EntityId>,
    line: Option<&RunAdmission>,
) -> Result<SelfBriefState, McpGatewayError> {
    let auth = actor
        .auth
        .as_ref()
        .ok_or_else(|| mcp_api_error(ApiError::unauthorized()))?;
    let read = mcp_scoped_read(&server.vault, actor)?;
    let connector = BriefConnectorCeiling {
        world_ref: actor.scope.world_ref,
        facet_ref: actor.scope.facet_ref,
        facets: actor.scope.facets.clone(),
        bound_verbs: actor
            .bound_verbs
            .as_ref()
            .map(|verbs| verbs.iter().copied().map(str::to_owned).collect()),
    };
    let host = BriefHostFacts {
        run_ceiling: None,
        replay_run,
        credential_ceiling: auth.verified_slip().map(|proof| {
            oneiron::context_board::brief_credential_ceiling(
                proof,
                read.actor_key(),
                Some(connector),
            )
        }),
        communication_credential_ceiling: auth
            .verified_slip()
            .map(oneiron::authority::VerifiedSlip::comm),
        // The session the authenticated request binds (`x-oneiron-session`),
        // read as the connector's board reads its SCRATCHPAD; a request that
        // binds none has no session to look in.
        scratchpad: actor.off_record_session.as_deref().and_then(|session| {
            let memory = crate::api::mcp_credential_memory(
                &server.vault,
                actor.auth.as_ref(),
                actor.actor_ref,
                actor.actor_class,
            )
            .at(actor.locality());
            scratchpad_family(&memory, session)
        }),
        pins: mcp_brief_pins(server, actor),
    };
    resolved_state(server, actor.write_actor(), line, reads, &host).map_err(mcp_facade_error)
}

/// Answers a registered connector's `describe(self)` for the agent it
/// stands for, over the connection `actor` resolved: the stream connection,
/// the connector scope, the bound verbs and the verified auth its
/// registration admitted. The brief is rendered whole, so a record-narrowed
/// credential is refused, as on the credentialed path. Once the
/// connection's setup delivered its brief, the answer is that brief's tail
/// (FIX 17594 D4). A call the code of a code-mode durable run makes names
/// that run (`run`, the trusted id its dispatch carries): its answer is the
/// run's own brief, through the run's installed custody once delivered (FIX
/// 17594 D5). Beside the card come the rows it is derived from
/// ([`oneiron::context_board::SelfBrief::sources`]), the PEOPLE roster it
/// read among them (DEC-0005). The wire value is the credentialed path's
/// `TaskDescription::SelfCard`.
pub(crate) async fn describe_self_for_mcp(
    server: &SyncServer,
    actor: &McpCallContext,
    run: Option<oneiron::EntityId>,
    body: &serde_json::Value,
) -> Result<(serde_json::Value, Vec<oneiron::EntityId>), McpGatewayError> {
    let auth = actor
        .auth
        .as_ref()
        .ok_or_else(|| mcp_api_error(ApiError::unauthorized()))?;
    auth.require_unrestricted_record_scope()
        .map_err(mcp_api_error)?;
    let request: DescribeRequest = serde_json::from_value(body.clone()).map_err(|_| {
        mcp_api_error(ApiError::bad_request(
            "invalid describe(self) input",
            Some("self"),
        ))
    })?;
    // describe(self) names the connection's own brief and nothing else (FIX
    // 3256). A `session_id` the body names is not read: the connection's own
    // observations are the session.
    request.validate().map_err(mcp_facade_error)?;
    if !request.self_target || actor.actor_class != oneiron::EdgeActorClass::Agent {
        return Err(mcp_api_error(ApiError::bad_request(
            "describe(self) requires an agent run",
            Some("self"),
        )));
    }
    let ConnectionBriefReads { reads, people } = connection_brief_reads(server, actor).await?;
    let (key, state) = match run {
        Some(run_id) => {
            let line = code_mode_line(server, run_id);
            let state = connection_brief_state(server, actor, &reads, Some(run_id), line.as_ref())?;
            (code_mode_brief_key(actor, run_id), state)
        }
        None => (
            connection_brief_key(actor),
            connection_brief_state(server, actor, &reads, None, None)?,
        ),
    };
    let (tail, sources) = installed_tail(server, &key, state, &reads, &people).await?;
    let value = serde_json::to_value(oneiron::task_verb::TaskDescription::SelfCard { tail })
        .map_err(|_| {
            mcp_api_error(ApiError::internal_server_error(
                "self brief encoding failed",
            ))
        })?;
    Ok((value, sources))
}

/// A mid-run `describe(self)` of the brief installed under `key`, as `state`
/// stands now, and the rows it is derived from. With a delivered prefix,
/// `state` is installed again at the brief's epoch and its tail rendered
/// through that custody, the cached prefix untouched; else `state` is
/// rendered whole.
async fn installed_tail(
    server: &SyncServer,
    key: &BriefKey,
    state: SelfBriefState,
    reads: &SessionReadSet,
    people: &People,
) -> Result<(String, Vec<oneiron::EntityId>), McpGatewayError> {
    let failed = |error: oneiron::Error| mcp_engine_error("self brief failed", error);
    let missing = || {
        mcp_api_error(ApiError::internal_server_error(
            "self brief tail is missing",
        ))
    };
    let mut briefs = server.self_brief_sessions.lock().await;
    if briefs.acknowledged(key).is_some() {
        briefs.restate(key, state).map_err(failed)?;
        let (card, sources) = briefs
            .tail_listing(key, &server.vault, reads, Some(people))
            .transpose()
            .map_err(failed)?
            .ok_or_else(missing)?;
        return Ok((card.tail.ok_or_else(missing)?, sources));
    }
    drop(briefs);
    let brief = state
        .describe(&server.vault, reads, Some(people))
        .map_err(failed)?;
    let sources = brief.sources(&server.vault, Some(people)).map_err(failed)?;
    Ok((brief.render(), sources))
}
