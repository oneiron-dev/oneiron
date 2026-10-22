//! Tool execution dispatch across actors.

pub(crate) use self::auth::*;
pub(crate) use self::execute::*;
pub(crate) use self::gates::*;
use super::{
    MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError, actions, execute_mcp_execute_code,
    execute_mcp_generated_verb, execute_mcp_read_result, execute_mcp_setup, mcp_actor_class_wire,
    mcp_engine_error, owner_call,
};
use crate::mcp::McpActorMetadata;
use crate::mcp::McpConnectorActorResolutionError;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpSurfaceMode;
use crate::mcp::McpToolValidationError;
use crate::mcp::McpValidatedToolArgs;
use crate::server::SyncServer;
use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap};
use oneiron::federation::{ScopeAxis, ScopeId};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;

mod auth;
mod execute;
mod gates;

impl McpCallContext {
    /// This call, on a connection that proved `peer` (mesh PR2b): its reads
    /// and every release, final, after an await, replayed or an error, judge
    /// that machine. An unproved peer leaves an unknown destination.
    pub(crate) fn toward(mut self, peer: oneiron::authority::PeerMachine) -> Self {
        self.actor.auth = self.actor.auth.take().map(|auth| auth.toward(peer));
        self
    }
}

/// What one call does to the vault, as its credential check sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum McpCallEffect {
    Reads,
    /// A write bound to its actor that lands at the actor's ceiling: under
    /// `proposed` it waits for review.
    Proposes,
    /// A write that takes effect at once.
    Commits,
}

impl McpCallEffect {
    /// A generated verb's effect. `vault.claims.upsert` proposes a new claim, or a
    /// replacement that supersedes its head only once approved; one that names
    /// its `id` rewrites that claim in place, so the old value leaves at once.
    /// A booking page publication acts at once too, with or without an `id`:
    /// the page's public address moves to the new claim as it is written, so
    /// a revision still awaiting review takes the live page offline.
    /// The input is read the way dispatch reads it, as a typed `ClaimInput`
    /// in whatever form serde takes (a positional array too); a spec that
    /// does not decode is refused at dispatch and writes nothing.
    fn of(
        tool: crate::mcp::McpGeneratedVerbTool,
        arguments: &crate::mcp::McpVerbArguments,
    ) -> Self {
        let acts_at_once = || {
            tool.name == oneiron::task_verb::sdk::AgentVerb::VaultClaimsUpsert.as_str()
                && arguments.spec.clone().is_some_and(|spec| {
                    serde_json::from_value::<oneiron::memory::ClaimInput>(spec).is_ok_and(|input| {
                        input.id.is_some()
                            || input.predicate == oneiron::booking::BOOKING_PUBLIC_PAGE_PREDICATE
                    })
                })
        };
        if !tool.writes() {
            Self::Reads
        } else if tool.proposes() && !acts_at_once() {
            Self::Proposes
        } else {
            Self::Commits
        }
    }
}

/// How much of the credential's record bounds one call can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum McpRecordBounds {
    /// A list filtered row by row: every bound applies per row.
    Filtered,
    /// A write whose records are born at the connector's world and facet.
    Born,
    /// Anything else: no projection, so no record bound at all.
    Unrestricted,
}
