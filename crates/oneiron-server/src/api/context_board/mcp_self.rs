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

use oneiron::context_board::BriefConnectorCeiling;
use oneiron::task_verb::sdk::DescribeRequest;

use super::run_self::{BriefHostFacts, read_people, resolved_state, scratchpad_family};
use crate::api::mcp_gateway::{
    McpCallContext, McpGatewayError, mcp_api_error, mcp_brief_pins, mcp_engine_error,
    mcp_facade_error, mcp_scoped_read, mcp_session_reads,
};
use crate::error::ApiError;
use crate::server::SyncServer;

/// Answers a registered connector's `describe(self)` for the agent it
/// stands for, over the connection `actor` resolved: the stream connection,
/// the connector scope, the bound verbs and the verified auth its
/// registration admitted. The brief is rendered whole, so a record-narrowed
/// credential is refused, as on the credentialed path. Beside the card come
/// the rows it is derived from
/// ([`oneiron::context_board::SelfBrief::sources`]), the PEOPLE roster it
/// read among them (DEC-0005). The wire value is the credentialed path's
/// `TaskDescription::SelfCard`.
pub(crate) async fn describe_self_for_mcp(
    server: &SyncServer,
    actor: &McpCallContext,
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
    let reads = mcp_session_reads(server, actor).await;
    let read = mcp_scoped_read(&server.vault, actor)?;
    let people = read_people(server, &read).map_err(mcp_facade_error)?;
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
    let state = resolved_state(server, actor.write_actor(), None, &reads, &host)
        .map_err(mcp_facade_error)?;
    let brief = state
        .describe(&server.vault, &reads, Some(&people))
        .map_err(|error| mcp_engine_error("self brief failed", error))?;
    let sources = brief
        .sources(&server.vault, Some(&people))
        .map_err(|error| mcp_engine_error("self brief failed", error))?;
    let value = serde_json::to_value(oneiron::task_verb::TaskDescription::SelfCard {
        tail: brief.render(),
    })
    .map_err(|_| {
        mcp_api_error(ApiError::internal_server_error(
            "self brief encoding failed",
        ))
    })?;
    Ok((value, sources))
}
