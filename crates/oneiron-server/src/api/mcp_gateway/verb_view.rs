//! The MCP discovery source: one credential-filtered verb-tree view per call (3b-2b PR 2, D3).
//!
//! [`mcp_discovery_view`] admits, for one resolved connector credential, the ROUTE of every
//! generated code-mode row the parity test enumerates
//! (`oneiron::verbs::code_mode_verb_names`), then projects the shipped catalogue through the
//! admitted set. A row is admitted exactly when the checks its live call meets pass without
//! input: PR 1's static checks for that route, the credential gates with default (empty)
//! arguments, and the owner / owner-delegate preflight where the row has one. Anything that
//! needs input or a per-call entitlement (task refs, subscriptions, self/vault/handle reads,
//! propose-vs-commit inputs, lane keys, Grants, Settings, record ACLs, hooks, permits) stays on
//! the actual call; a route that cannot be proven without input is hidden, never guessed.
//!
//! Route table (one row, one route; every check must pass):
//!
//! - Agent row, browser or `vault.runs.read_result`: caller-code author check, host admission
//!   (exact binding + unscoped execution) and desktop refusal, then hidden: the run guest
//!   (seat, pack, press) and the result window (run-ref input, derived run) need a run the
//!   signature does not carry, so no binding proves their custody.
//! - Agent row on the ToolFirst surface: caller-code author check; the argument-dependent
//!   hides below; scoped admission with default arguments (exact binding; unscoped execution
//!   for memory-method and requires-unscoped rows); the verb gate (lane record scope for
//!   lane-scope host doors; liveness, record bounds and effect grant); then the owner preflight
//!   where the row has one.
//! - Agent row on neither route (scoped-child rows): hidden; no code-mode door serves them.
//! - Run row: exact-row binding (a shared effect's other rows bind nothing), the `execute`
//!   entry's unscoped execution, the caller-code author check, then the run-call gate (world
//!   privacy refusal, live session, effect grant).
//!
//! The view omits required TASK addresses, subscriptions and `describe`'s
//! target selection; their route admission needs a real input. It also omits
//! narrowed registrations' image handles and whole-read routes without a
//! scope witness. A proposes row's static tier follows the nameable proposal
//! route; an input that commits still needs Write at the actual call.
//!
//! An off-record or room binding gets no rows: this source does not carry
//! the matching storage door. A Run row must be on the generated ordinary
//! storage surface, take no writer-checked power, and have the credential's
//! read lane. Live run, repo, child and other unproven surfaces are hidden.
//!
//! Dormant: PR 3 (typed run host) is the first production caller.

#![cfg_attr(
    not(test),
    allow(dead_code, reason = "dormant until 3b-2b PR 3 binds the run host door")
)]

use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::code_run::RunCall;
use oneiron::task_verb::sdk::{AgentVerb, RunVerb};
use oneiron::verbs::code_mode_verb_names;
use oneiron::verbs::tree::{AdmittedRows, DiscoveryView, NoteKindAudience, VerbTree};

use super::actor_dispatch::{mcp_run_call_gate, mcp_verb_gate};
use super::admission::{mcp_admit_host_verb, mcp_admit_run_verb, mcp_admit_scoped_verb};
use super::static_admission::{StaticCaller, StaticCheck, static_admission};
use super::tasks_response::RunAuthor;
use super::{McpCallContext, McpGatewayError};
use crate::mcp::{McpEndpointTool, McpRegisteredSurface, McpSurfaceMode, McpVerbArguments};
use crate::server::SyncServer;

/// The MCP discovery view for one credential under one run author: every generated code-mode
/// row whose route this credential can use, projected through one freshly built shipped
/// catalogue with this vault's view options. There is no shared tree cache on the server, so
/// the catalogue is built where the view is built.
///
/// `NoteKindAudience` is `Owner` exactly when the resolved caller is the vault owner in person:
/// an unbound, vault-wide Human registration whose credential passes the owner door (binding
/// ruling: grade alone is not identity, so agents and narrowed registrations are `NonOwner`
/// even with an unattenuated top slip).
pub(crate) fn mcp_discovery_view(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    author: RunAuthor,
) -> Result<DiscoveryView, McpGatewayError> {
    // This source has no room/anonymous storage door from which to prove routes.
    if actor.room_turn.is_some() || actor.off_record_session.is_some() {
        return Ok(DiscoveryView::empty());
    }
    let unavailable = || {
        McpGatewayError::new(
            -32603,
            "verb_view_unavailable",
            "Verb discovery is unavailable.",
        )
    };
    let tree = VerbTree::shipped().map_err(|_| unavailable())?;
    let options = server
        .vault()
        .verb_view_options()
        .map_err(|_| unavailable())?;
    let kinds = if owner_audience(server.as_ref(), actor) {
        NoteKindAudience::Owner
    } else {
        NoteKindAudience::NonOwner
    };
    // The ordinary route resolves on ToolFirst, as the code-mode door's own verb call does.
    let surface = server
        .mcp_surface(McpSurfaceMode::ToolFirst)
        .map_err(|_| unavailable())?;
    let caller = StaticCaller::connector(actor).authored(author);
    let mut rows = Vec::new();
    for name in code_mode_verb_names() {
        // Run names take precedence, as in the parity test: a Run row meets the run route even
        // where an Agent row shares its name.
        if RunVerb::from_name(name).is_some() {
            if run_row_admitted(server, actor, caller, name) {
                rows.push(name);
            }
        } else if let Some(verb) = AgentVerb::from_name(name) {
            if agent_row_admitted(server, actor, caller, surface, verb) {
                rows.push(name);
            }
        }
    }
    let admitted: AdmittedRows = rows.into_iter().collect();
    Ok(tree.discovery_view(admitted, options, kinds))
}

/// Whether generated Agent row `verb`'s route admits `actor` under `author`: its binding, scope,
/// author, desktop and credential gates with default (empty) arguments, then the owner preflight
/// where the row has one. Host-custody rows hide after their static checks (no run in
/// signature); argument-dependent rows hide per [`scoped_inputs_unproven`]; a row with no
/// ToolFirst tool outside the host route is hidden.
fn agent_row_admitted(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    caller: StaticCaller<'_>,
    surface: &McpRegisteredSurface,
    verb: AgentVerb,
) -> bool {
    if static_admission(caller, StaticCheck::CallerCodeAgentRow(verb)).is_err() {
        return false;
    }
    let name = verb.as_str();
    if verb.is_browser() || verb == AgentVerb::VaultRunsReadResult {
        if mcp_admit_host_verb(actor, verb).is_err() {
            return false;
        }
        if static_admission(StaticCaller::row_only(), StaticCheck::DesktopRow(verb)).is_err() {
            return false;
        }
        // No run guest or result proof: the signature carries no run, so the guest half of a
        // browser/desktop row and the run-ref half of a result read stay unproven for every
        // binding, whatever the credential gates would say.
        return false;
    }
    let Some(McpEndpointTool::Verb(tool)) = surface.resolve(name) else {
        return false;
    };
    if scoped_inputs_unproven(verb, actor, caller) {
        return false;
    }
    let arguments = McpVerbArguments::default();
    if mcp_admit_scoped_verb(server, tool, &arguments, actor).is_err() {
        return false;
    }
    if mcp_verb_gate(server, tool, &arguments, actor).is_err() {
        return false;
    }
    let Some(auth) = actor.auth.as_ref() else {
        return false;
    };
    crate::api::facade::view_owner_route_admits(server.as_ref(), auth, name)
}

/// Whether the door needs an input to prove the route. A required TASK
/// reference and `describe` use addressed-entity or target-selected gates.
/// Subscriptions need their requested categories; a narrowed registration
/// also needs the `ai.ask_image` spec's addressed asset and a witness for
/// any required whole-read target.
fn scoped_inputs_unproven(
    verb: AgentVerb,
    actor: &McpCallContext,
    caller: StaticCaller<'_>,
) -> bool {
    let required = verb.required_fields();
    // The route gate itself reads an addressed TASK, even for vault-wide registrations.
    // An empty argument cannot witness that read; do not look for a readable TASK.
    if required.contains(&"task_ref") || verb == AgentVerb::Describe {
        return true;
    }
    let addressed = ["self", "vault", "handle"]
        .into_iter()
        .any(|field| required.contains(&field));
    if addressed
        && (actor.scope.is_narrow()
            || static_admission(caller, StaticCheck::UnrestrictedRecordScope).is_err())
    {
        return true;
    }
    if required.contains(&"scopes") {
        return true;
    }
    verb.as_str() == "ai.ask_image" && actor.scope.is_narrow()
}

/// Whether generated Run row `name`'s route admits `actor` under `author`: its exact-row
/// binding, the `execute` entry's scope, the author veto, and the run-call gate. A shared
/// effect's other rows bind nothing here: only the exact row's own binding counts.
fn run_row_admitted(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    caller: StaticCaller<'_>,
    name: &str,
) -> bool {
    let Some(verb) = RunVerb::from_name(name) else {
        return false;
    };
    if mcp_admit_run_verb(actor, verb).is_err() {
        return false;
    }
    if static_admission(caller, StaticCheck::UnscopedExecution).is_err() {
        return false;
    }
    let call = RunCall::Bridge(verb.effect());
    if static_admission(caller, StaticCheck::CallerCodeRunCall(call)).is_err() {
        return false;
    }
    if mcp_run_call_gate(server, actor, call).is_err() {
        return false;
    }
    // Only ordinary-storage rows have a generated run route that this source
    // can prove without a bound live run or an input-selected entitlement.
    RunVerb::MEMORY_RUN.contains(&verb)
        && verb.power().is_none()
        && super::mcp_scoped_read(server.vault(), &actor.actor).is_ok()
}

/// Whether the resolved caller is the vault owner in person for NOTE-kind discovery: an
/// unbound, vault-wide Human registration whose credential passes the owner door (owner grade
/// plus live owner identity; managed and host-action owners through their own proofs). Grade
/// alone is not identity: any holder's unattenuated top-scope slip is owner-grade, so agents
/// and narrowed registrations are excluded even when their slip is.
fn owner_audience(server: &SyncServer, actor: &McpCallContext) -> bool {
    if actor.bound_verbs.is_some() || actor.scope.is_narrow() {
        return false;
    }
    if actor.actor_class != EdgeActorClass::Human {
        return false;
    }
    let Some(auth) = actor.auth.as_ref() else {
        return false;
    };
    crate::api::owner_routes::owner(auth, server).is_ok()
}
