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

    /// What one call a code run serves itself does, named for every effect
    /// and read by default for none. A run row's effect is judged by its
    /// generated rows (`RunVerb::effect`, `RunVerb::writes`). A verb-table
    /// call is judged by its own row at the door's call (`mcp_verb_gate`).
    /// The run's recorded output, its descriptor round trip and its speech
    /// are the run's own record: the native host keeps each run on canonical
    /// storage, where its speech lands in the run's own derived conversation
    /// (ONE-1686), never a room. Every other effect writes at once. No call
    /// here waits for review, so none proposes.
    fn of_run_call(call: oneiron::code_run::RunCall) -> Self {
        use oneiron::code_run::{RunCall, SelfEffect as Effect};
        let effect = match call {
            RunCall::RecordedOutput => return Self::Reads,
            RunCall::Bridge(effect) => effect,
        };
        match effect {
            Effect::ConnectorAnswer
            | Effect::WorldPrivacySet
            | Effect::MemorySearch
            | Effect::MemoryPutClaim
            | Effect::MemorySupersedeClaim
            | Effect::MemoryPutEdge
            | Effect::Fold
            | Effect::ConsultResult
            | Effect::TasksRefuse
            | Effect::ReportBlocked
            | Effect::AgentsSpawn
            | Effect::WorkflowDispatch
            | Effect::RepoSnapshotsGet
            | Effect::RepoSnapshotsRead
            | Effect::RepoSymbolsDefinitions
            | Effect::RepoViewsGet
            | Effect::RepoViewsRead
            | Effect::RepoMergeQueueObserve
            | Effect::RepoSnapshotsIngest
            | Effect::RepoWorkOpen
            | Effect::RepoSymbolsDeclare
            | Effect::RepoSymbolsRenew
            | Effect::RepoSymbolsRelease
            | Effect::RepoProposalSubmit
            | Effect::RepoMergeQueueEnqueue
            | Effect::RepoCheckoutBind
            | Effect::RepoExport
            | Effect::Leader
            | Effect::LeaderSplit
            | Effect::SkillsCall
            | Effect::Team
            | Effect::ReaderSpawn
            | Effect::TasksWaitSet
            | Effect::Summarize => Self::of_run_rows(effect),
            Effect::AgentVerb
            | Effect::Context
            | Effect::InferenceDefaultsRead
            | Effect::Speak
            | Effect::Think
            | Effect::Express => Self::Reads,
            Effect::TasksAsk
            | Effect::TasksWait
            | Effect::MemoryWriteFixture
            | Effect::Ask
            | Effect::DestructiveFixture
            | Effect::OutboundFixture
            | Effect::TaskDelegate
            | Effect::AgentsPut
            | Effect::InferenceDefaultsReplace
            | Effect::WakePolicyWrite
            | Effect::ReaderReport => Self::Commits,
        }
    }

    /// A run row effect's: it reads only while every generated row with it
    /// reads, so `self.folds` commits as `self.fold` does. An effect no row
    /// names commits.
    fn of_run_rows(effect: oneiron::code_run::SelfEffect) -> Self {
        let mut rows = oneiron::task_verb::sdk::RunVerb::ALL
            .iter()
            .filter(|verb| verb.effect() == effect)
            .peekable();
        if rows.peek().is_some() && rows.all(|verb| !verb.writes()) {
            Self::Reads
        } else {
            Self::Commits
        }
    }

    /// A row a run's door serves itself, not through a tool: its generated
    /// scope. A guest's act, an admission job's filing and an off-record
    /// room write take effect at once, and a room write has no Proposed
    /// lifecycle, so a writing row commits.
    fn of_host_verb(verb: oneiron::task_verb::sdk::AgentVerb) -> Self {
        if verb.writes() {
            Self::Commits
        } else {
            Self::Reads
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
