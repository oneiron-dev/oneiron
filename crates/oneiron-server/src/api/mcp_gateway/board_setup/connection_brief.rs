//! An MCP connection's self brief as its setup delivers it (FIX 17594
//! delivery slice D4, Engine call MCP A): page one of `setup_oneiron`
//! carries the brief's turn-one prefix beside the keyframe, grammar and
//! instructions, and the client places it before its first model turn.
//!
//! Each page one begins the connection's brief afresh: the connection's
//! brief state is resolved now ([`crate::api::connection_brief_state`]) and
//! installed in the server's custody under the agent and the connection's
//! stream id, as a new installation, and its turn one staged. The
//! installation is made under the MCP registry's lock, only while the
//! connection is attached, and the registry keeps it with the connection,
//! so a revoked, unregistered or pruned connection's brief is closed with
//! it (`server/housekeeping.rs`) and a late install finds the connection
//! gone and installs nothing. The staged prefix is acknowledged only once
//! page one's result was released; a staged candidate a newer installation
//! or a close replaced acknowledges nothing.
//!
//! A brief that does not resolve, install or prepare, or that may not leave
//! this device for the connection's destination, never fails the setup,
//! which ran before it carried a brief: the miss is logged, and page one
//! goes out with no brief and with every name inline, as before.

use super::*;
use crate::api::ConnectionBriefReads;
use crate::server::self_brief_custody::{BriefAcknowledgment, BriefCandidate, BriefPreparation};

/// Installs `actor`'s connection brief afresh and stages its turn one for
/// the setup page one about to go out; `None` when the connection has no
/// brief, is no longer attached, or its brief did not resolve, install or
/// prepare or may not leave this device (logged).
pub(super) async fn stage_connection_brief(
    server: &SyncServer,
    actor: &McpCallContext,
) -> Option<BriefCandidate> {
    if !crate::api::connection_has_brief(actor) {
        return None;
    }
    let connection = &actor.stream_connection;
    let resolved = async {
        let reads = crate::api::connection_brief_reads(server, actor).await?;
        let state = crate::api::connection_brief_state(server, actor, &reads.reads, None, None)?;
        Ok::<_, McpGatewayError>((reads, state))
    }
    .await;
    let (ConnectionBriefReads { reads, people }, state) = match resolved {
        Ok(resolved) => resolved,
        Err(error) => {
            tracing::warn!(
                kind = error.kind,
                "a connection's self brief did not resolve; its setup carries none"
            );
            drop_connection_brief(server, connection).await;
            return None;
        }
    };
    // The roster is laid out under the `people` share of the layout the
    // keyframe beside it shows, which that page activates.
    let people_budget_tok = match mcp_brief_people_budget(server, actor.actor_ref, true) {
        Ok(budget) => budget,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a connection's self brief layout did not read; its setup carries none"
            );
            drop_connection_brief(server, connection).await;
            return None;
        }
    };
    let key = crate::api::connection_brief_key(actor);
    let briefs = {
        // Under the registry's lock, as the connection's teardown runs: a
        // connection already gone gets no installation.
        let mut registry = server.mcp_registry.lock().await;
        if !registry.connection_attached(connection) {
            return None;
        }
        let mut briefs = server.self_brief_sessions.lock().await;
        match briefs.install_fresh(key.clone(), state) {
            Ok(owner) => registry.hold_self_brief(connection, (key.clone(), owner)),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a connection's self brief did not install; its setup carries none"
                );
                if let Some((held, owner)) = registry.release_self_brief(connection) {
                    briefs.close(&held, owner);
                }
                return None;
            }
        }
        briefs
    };
    // The installation just made: the custody lock is held from it on.
    let candidate = match briefs.prepare(
        &key,
        &server.vault,
        &reads,
        Some(&people),
        people_budget_tok,
    ) {
        Ok(Some(BriefPreparation::Staged { candidate, .. })) => candidate,
        // A fresh installation has turn one to stage.
        Ok(Some(BriefPreparation::Emitted { .. }) | None) => return None,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a connection's self brief did not prepare; its setup carries none"
            );
            return None;
        }
    };
    drop(briefs);
    // Page one leaves as it did before it carried a brief: a brief derived
    // from a row this device keeps from the connection's destination stays
    // off it, and the page goes out without it (DEC-0005).
    match crate::device_local::withholds_retained(
        &server.vault,
        actor.destination(),
        candidate.sources(),
        candidate.prefix().as_bytes(),
    ) {
        Ok(false) => Some(candidate),
        Ok(true) => {
            tracing::warn!(
                "a connection's self brief may not leave this device; its setup carries none"
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a connection's self brief release check failed; its setup carries none"
            );
            None
        }
    }
}

/// Acknowledges `candidate`, the brief a setup page one carried, once that
/// page's result was released. A stale candidate changes nothing, and is
/// logged.
pub(super) async fn acknowledge_connection_brief(server: &SyncServer, candidate: BriefCandidate) {
    let boundary = candidate.boundary();
    let acknowledged = server
        .self_brief_sessions
        .lock()
        .await
        .acknowledge(candidate);
    if acknowledged == BriefAcknowledgment::Stale {
        tracing::warn!(
            ?boundary,
            "a connection's delivered self brief was stale; its custody did not move"
        );
    }
}

/// Closes the brief `connection` holds, for a setup page one that carries
/// none: the connection's boards then name every person inline, as the page
/// does.
async fn drop_connection_brief(
    server: &SyncServer,
    connection: &oneiron::context_board::StreamConnectionId,
) {
    let mut registry = server.mcp_registry.lock().await;
    if let Some((key, owner)) = registry.release_self_brief(connection) {
        server.self_brief_sessions.lock().await.close(&key, owner);
    }
}
