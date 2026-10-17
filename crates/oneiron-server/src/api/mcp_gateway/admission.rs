//! Scoped-call admission and actor resolution.

use super::board_setup::mcp_scope_admits_row;
use super::{
    McpCallContext, McpGatewayError, McpToolCallParams, mcp_actor_result, mcp_api_error,
    mcp_engine_error, mcp_scoped_read, mcp_tool_validation_error,
};
use crate::api::parse_entity_id_param;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpSurfaceMode;
use crate::mcp::McpValidatedToolArgs;
use crate::server::SyncServer;
use std::sync::Arc;

/// The IMMUTABLE connector ceiling, applied BEFORE any executor runs.
///
/// Four intersections happen here and nowhere else (ONE-1704 M3):
///
/// 1. the registered bound-verb ceiling against the tool this call named;
/// 2. the registered world/facet against every entity the call ADDRESSES,
///    through the engine's own scoped-read admission plus the target's own
///    `world` key and `FacetOf` edges;
/// 3. the registered subscription ceiling against a STREAM routing request;
/// 4. the registered world/facet against every call whose EXECUTION carries no
///    scope of its own.
///
/// The fourth is the ONE-1704 B3 close: this admission no longer answers `Ok`
/// for every non-verb call. `execute_code` builds an actor-wide gated write, so
/// it cannot be narrowed downstream; under a world- OR facet-narrowed
/// credential it is refused here, fail-closed, with the two axes enforced
/// independently, and so is every verb row marked `unrestricted`. The one
/// scoped-positive write is `tasks.create`: the TASK it mints is born in the
/// connector's own world and facet (ARCH-0067 §5), so its writer reads it and
/// a credential narrowed elsewhere does not.
///
/// A caller echo can only ever narrow. Nothing a caller sends creates
/// authority, and a refusal here happens before dispatch, not after.
pub(crate) fn mcp_admit_scoped_call(
    server: &Arc<SyncServer>,
    args: &McpValidatedToolArgs,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    let tool_name = mcp_called_tool_name(args);
    mcp_admit_bound_tool(actor, tool_name)?;
    let verb = match args {
        // Setup reads a board that is ALREADY narrowed to this credential's
        // ceiling row by row (`mcp_scoped_tasks_section`), so it is the one
        // call a narrowed credential may make unchanged.
        McpValidatedToolArgs::Setup(_) => return Ok(()),
        // Unreachable from either registered wire surface (B1/B2), and refused
        // here too rather than admitted by omission.
        McpValidatedToolArgs::ExecuteCode(_) => {
            return mcp_admit_unscoped_execution(actor, crate::mcp::MCP_EXECUTE_CODE_TOOL, "name");
        }
        // It reads only what execute_code ran, so it is admitted as that is.
        McpValidatedToolArgs::ReadResult(_) => {
            return mcp_admit_unscoped_execution(actor, crate::mcp::MCP_READ_RESULT_TOOL, "name");
        }
        // The wrapper never routes around the connector's allow-list: the
        // verb it runs is admitted by name too. An action runs under the
        // credential's own slip and read key, so no world or facet a
        // registration narrows to rides it: a narrowed connector is refused,
        // as for execute_code.
        McpValidatedToolArgs::InvokeAction(action) => {
            mcp_admit_bound_tool(actor, &action.verb).map_err(|error| error.with_field("verb"))?;
            return mcp_admit_unscoped_execution(actor, crate::mcp::MCP_INVOKE_ACTION_TOOL, "name");
        }
        McpValidatedToolArgs::Verb(verb) => verb,
    };
    mcp_admit_verb_scope(server, verb.tool, &verb.payload.arguments, actor)
}

/// Whether this credential may start a code run here: a bound code host,
/// and everything an `execute_code` call meets before its program is read.
/// `/mcp` lists `execute_code` to every credential alike, so the listing
/// cannot say this; `initialize` does, and the stdio bridge picks its
/// endpoint by it.
pub(crate) fn mcp_execute_code_admitted(server: &Arc<SyncServer>, actor: &McpCallContext) -> bool {
    let tool = crate::mcp::MCP_EXECUTE_CODE_TOOL;
    server.code_execution_host().is_some()
        && mcp_admit_bound_tool(actor, tool).is_ok()
        && mcp_admit_unscoped_execution(actor, tool, "name").is_ok()
        && super::actor_dispatch::mcp_execute_code_gate(server, actor).is_ok()
}

/// One generated verb call, whichever door it arrived at: a `tools/call` or a
/// code-mode call at the verb's full path. Both meet exactly this admission.
pub(crate) fn mcp_admit_scoped_verb(
    server: &Arc<SyncServer>,
    tool: crate::mcp::McpGeneratedVerbTool,
    arguments: &crate::mcp::McpVerbArguments,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    mcp_admit_bound_tool(actor, tool.name)?;
    mcp_admit_verb_scope(server, tool, arguments, actor)
}

/// A verb a bound host operation runs on its own behalf: a browser batch's
/// routine decisions are `ai.verdict` calls. The batch's own binding carries
/// it, so only the verb's scope is admitted here, never a tool binding.
pub(crate) fn mcp_admit_step_verb(
    server: &Arc<SyncServer>,
    tool: crate::mcp::McpGeneratedVerbTool,
    arguments: &crate::mcp::McpVerbArguments,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    mcp_admit_verb_scope(server, tool, arguments, actor)
}

/// One verb-table row a code run serves itself (`vault.search`,
/// `vault.claims.put`, …). No tool carries it, so the bound-verb ceiling names it by
/// its row name. Its world/facet axis is the run's: `execute_code` admits no
/// narrowed credential.
pub(crate) fn mcp_admit_run_verb(
    actor: &McpCallContext,
    verb: oneiron::task_verb::sdk::RunVerb,
) -> Result<(), McpGatewayError> {
    mcp_admit_bound_tool(actor, verb.as_str())
}

/// One verb-table row only code mode serves, through a resource the host
/// binds to the run (`self.browser.*`). No tool carries it, so the
/// bound-verb ceiling names it by its row name, and it acts outside the
/// vault's world/facet axes, so a narrowed credential is refused.
pub(crate) fn mcp_admit_host_verb(
    actor: &McpCallContext,
    verb: oneiron::task_verb::sdk::AgentVerb,
) -> Result<(), McpGatewayError> {
    mcp_admit_bound_tool(actor, verb.as_str())?;
    mcp_admit_unscoped_execution(actor, verb.as_str(), "name")
}

fn mcp_admit_bound_tool(actor: &McpCallContext, tool_name: &str) -> Result<(), McpGatewayError> {
    if actor.admits_tool(tool_name) {
        return Ok(());
    }
    Err(McpGatewayError::new(
        -32020,
        "mcp_verb_not_bound",
        format!("{tool_name} is not bound to this connector credential"),
    )
    .with_field("name"))
}

fn mcp_admit_verb_scope(
    server: &Arc<SyncServer>,
    tool: crate::mcp::McpGeneratedVerbTool,
    arguments: &crate::mcp::McpVerbArguments,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    if tool.memory_method().is_some() {
        // Actor-scoped reads do NOT by themselves carry a connector's narrower
        // ceiling. Never confuse the principal's grants with this credential.
        mcp_admit_unscoped_execution(actor, tool.name, "arguments.request")?;
    }
    if arguments.self_target == Some(true) {
        // `describe(self)` renders the host-installed run brief whole: it has
        // no world/facet projection, so a narrowed connector cannot read it.
        mcp_admit_unscoped_execution(actor, tool.name, "arguments.self")?;
    }
    if arguments.vault == Some(true) {
        // `describe(vault)` joins the whole vault's send paths: a narrowed
        // connector cannot read it.
        mcp_admit_unscoped_execution(actor, tool.name, "arguments.vault")?;
    }
    if arguments.handle.is_some() {
        // `describe(handle)` answers the highway's status of a handle, which
        // carries no world/facet projection: a narrowed connector cannot
        // read it.
        mcp_admit_unscoped_execution(actor, tool.name, "arguments.handle")?;
    }
    if let Some(scopes) = arguments.scopes.as_ref() {
        mcp_admit_subscription_scopes(actor, scopes)?;
    }
    if let Some(task_ref) = arguments.task_ref.as_deref() {
        let id = parse_entity_id_param(task_ref, "arguments.task_ref").map_err(mcp_api_error)?;
        mcp_admit_scoped_entity(server, actor, &id, "arguments.task_ref")?;
    }
    if tool.requires_unscoped() {
        mcp_admit_unscoped_execution(actor, tool.name, "arguments.spec")?;
    }
    Ok(())
}

/// Refuses one call whose EXECUTION cannot carry this credential's scope.
///
/// Vault-wide credentials are unaffected — an actor-wide execution is exactly
/// their ceiling. A world- or facet-narrowed credential is refused, and the two
/// axes are independent: a world-only credential and a facet-only credential
/// each reach this on their own, neither inferred from the other.
fn mcp_admit_unscoped_execution(
    actor: &McpCallContext,
    tool_name: &str,
    field: &'static str,
) -> Result<(), McpGatewayError> {
    let scope = &actor.scope;
    let facets = !matches!(scope.facets, oneiron::federation::ScopeAxis::All);
    let axis = match (scope.world_ref.is_some(), facets) {
        (false, false) => return Ok(()),
        (true, false) => "world",
        (false, true) => "facet",
        (true, true) => "world and facet",
    };
    Err(McpGatewayError::new(
        -32020,
        "mcp_scope_refused",
        format!(
            "{tool_name} executes outside this credential's {axis} ceiling and is refused: this \
             release carries no scope through that execution"
        ),
    )
    .with_field(field))
}

/// The registered tool name one validated call resolved to.
fn mcp_called_tool_name(args: &McpValidatedToolArgs) -> &'static str {
    match args {
        McpValidatedToolArgs::Setup(_) => crate::mcp::MCP_SETUP_TOOL,
        McpValidatedToolArgs::ExecuteCode(_) => crate::mcp::MCP_EXECUTE_CODE_TOOL,
        McpValidatedToolArgs::ReadResult(_) => crate::mcp::MCP_READ_RESULT_TOOL,
        McpValidatedToolArgs::InvokeAction(_) => crate::mcp::MCP_INVOKE_ACTION_TOOL,
        McpValidatedToolArgs::Verb(verb) => verb.tool.name,
    }
}

/// Intersects a caller's requested STREAM categories with the ceiling this
/// credential was ATTACHED under.
fn mcp_admit_subscription_scopes(
    actor: &McpCallContext,
    requested: &[oneiron::context_board::SubscriptionScope],
) -> Result<(), McpGatewayError> {
    let asked = requested
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let admitted = actor.admitted_subscriptions(&asked);
    if admitted == asked {
        return Ok(());
    }
    Err(McpGatewayError::new(
        -32020,
        "mcp_scope_refused",
        "a requested subscription category is outside this credential's scope ceiling",
    )
    .with_field("arguments.scopes"))
}

/// Admits ONE caller-addressed entity against the registered world/facet.
///
/// Every axis is read from the store, not from the request: the actor-scoped
/// read lane decides readability, the target claim's own `world` key decides
/// world membership, and its `FacetOf` edges decide facet membership.
fn mcp_admit_scoped_entity(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    id: &oneiron::EntityId,
    field: &'static str,
) -> Result<(), McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    let readable = mcp_credential_reads(&server.vault, actor, id)
        .map_err(|error| mcp_engine_error("mcp scope admission read failed", error))?;
    if !readable || !mcp_scope_covers_entity(&scoped_read, &actor.scope, id)? {
        return Err(McpGatewayError::new(
            -32020,
            "mcp_scope_refused",
            "the addressed entity is outside this credential's world/facet scope",
        )
        .with_field(field));
    }
    Ok(())
}

/// The readability half of MCP admission: the same predicate the HTTP task
/// routes ask. A connector without a credential reads nothing here; its call
/// was already refused by [`mcp_scoped_read`].
pub(super) fn mcp_credential_reads(
    vault: &oneiron::Vault,
    actor: &McpResolvedActor,
    id: &oneiron::EntityId,
) -> oneiron::Result<bool> {
    actor
        .auth
        .as_ref()
        .map_or(Ok(false), |auth| auth.can_read_entity(vault, id))
}

/// True when the registered world/facet ceiling covers this entity.
///
/// A vault-wide credential covers everything. A facet-scoped credential covers
/// only rows inside one of its facets, by the engine's one facet rule
/// (`Vault::row_in_facets`), which every read lane applies too.
///
/// ONE-1704 B5: the world axis applies to EVERY addressed row rather than to
/// CLAIMs alone. A CLAIM is covered exactly when its own `world` key is this
/// credential's world. A TASK carries no `world` key, so it is projected
/// through the engine's record-scope stamp instead (`mcp_task_in_world`):
/// the board's TASK rows, a call addressing a TASK and the STREAM events about
/// one all take that one projection (ARCH-0067 §5). Any other row that carries
/// no `world` key cannot be PROVEN in this credential's world and is refused.
/// Prerelease law: the admission is narrowed outright, with no compatibility
/// carve-out for the rows the old CLAIM-only check let through.
pub(super) fn mcp_scope_covers_entity(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    scope: &crate::mcp::McpConnectorScope,
    id: &oneiron::EntityId,
) -> Result<bool, McpGatewayError> {
    if !scope.is_narrow() {
        return Ok(true);
    }
    let entity_type = scoped_read
        .vault()
        .get_entity_type(id)
        .map_err(|error| mcp_engine_error("mcp scope type read failed", error))?;
    if entity_type == Some(oneiron::registry::ENTITY_TYPE_TASK) {
        if !mcp_task_in_world(scoped_read.vault(), scope, id)? {
            return Ok(false);
        }
    } else if let Some(world_ref) = scope.world_ref {
        if entity_type != Some(oneiron::registry::ENTITY_TYPE_CLAIM) {
            return Ok(false);
        }
        let claim = scoped_read
            .vault()
            .get_claim(id)
            .map_err(|error| mcp_engine_error("mcp scope world read failed", error))?;
        let Some(claim) = claim else {
            return Ok(false);
        };
        if claim.world != Some(world_ref) {
            return Ok(false);
        }
    }
    // The one facet rule every read lane applies (owner ruling FACET-READ).
    // This is membership evidence, not returned graph data: a facet's
    // separate read-type ceiling must not erase proof of a row's scope.
    // Payload projection still uses the receipted ScopedRead door.
    scoped_read
        .vault()
        .row_in_facets(id, &scope.facets)
        .map_err(|error| mcp_engine_error("mcp scope facet read failed", error))
}

/// A TASK is inside a narrowed world when the world the engine stamped it
/// with at birth is that world; its facets are judged by the one facet rule.
/// A TASK is born in its writer's world and facet: a narrowed connector's
/// inside that connector's ceiling, a vault-wide writer's in base reality
/// under the TASK's own substrate facet. So a credential narrowed to base
/// reality reads the vault-wide writers' TASKs, and one narrowed to another
/// world or to a facet reads those written inside it. A TASK with no stamp
/// (an opaque replicated row) is outside every narrowed ceiling.
fn mcp_task_in_world(
    vault: &oneiron::Vault,
    scope: &crate::mcp::McpConnectorScope,
    id: &oneiron::EntityId,
) -> Result<bool, McpGatewayError> {
    use oneiron::federation::{Scope, ScopeAxis, ScopeId};
    let Some(position) = vault
        .record_scope(id)
        .map_err(|error| mcp_engine_error("mcp scope record read failed", error))?
    else {
        return Ok(false);
    };
    let Some(ceiling) = scope.world_ref else {
        return Ok(true);
    };
    // The registration's world and the TASK's birth position, each as a
    // world-only Scope, in the one Scope order.
    let stamped = Scope {
        worlds: position.worlds,
        ..Scope::top()
    };
    let registered = Scope {
        worlds: ScopeAxis::Some([ScopeId(ceiling)].into()),
        ..Scope::top()
    };
    Ok(!stamped.worlds.is_bottom() && stamped.is_narrowing_of(&registered))
}

/// Narrows the TASKS rows to the credential's registered world/facet and its
/// verified slip, then renders what is left. A TASK one of `pins` names that
/// the scope admitted but the render cap left off is still shown.
///
/// The narrowing runs BEFORE the render cap, so the window and its overflow
/// footer count only rows this credential may see. The returned count is the
/// scope omission: rows proven inside the credential's world and facet that
/// another of its bounds withholds. A row in a world or facet the credential
/// cannot read, or one that cannot prove where it sits, adds to no count
/// (ARCH-0067 §5, DEC-0005). Each row it admits is listed in `served`.
pub(super) fn mcp_scoped_tasks_section(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
    rows: oneiron::context_board::TasksSectionRows,
    pins: &[oneiron::context_board::HookPin],
    served: &mut Vec<oneiron::EntityId>,
) -> Result<(oneiron::context_board::TasksSection, usize), McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    let mut omitted = 0_usize;
    let mut admits = |row_id: &str| -> Result<bool, McpGatewayError> {
        if mcp_scope_admits_row(&server.vault, actor, &scoped_read, row_id)? {
            served.extend(oneiron::EntityId::from_hex(row_id).ok());
            return Ok(true);
        }
        if mcp_row_position_inside(&server.vault, actor, &scoped_read, row_id)? {
            omitted += 1;
        }
        Ok(false)
    };
    let mut intents = Vec::with_capacity(rows.intents.len());
    for intent in rows.intents {
        if admits(&intent.id)? {
            intents.push(intent);
        }
    }
    let mut bare_jobs = Vec::with_capacity(rows.bare_jobs.len());
    for job in rows.bare_jobs {
        if admits(&job.id)? {
            bare_jobs.push(job);
        }
    }
    let rows = oneiron::context_board::TasksSectionRows {
        intents,
        bare_jobs,
        source_exhausted: rows.source_exhausted,
    };
    let mut section = rows.render();
    // A hook-pinned TASK the scope admitted but the render cap left off is
    // shown, as on the HTTP board (OF-579).
    section.pin_hook_tasks(&rows.intents, pins);
    Ok((section, omitted))
}

/// Whether the TASK this board id names sits, by its birth stamp, inside both
/// the registered world/facet ceiling and the verified slip's worlds and
/// facets: only such a withheld row may be counted. A credential that
/// narrows neither excludes no TASK. Any other row cannot prove it, so it is
/// not counted.
fn mcp_row_position_inside(
    vault: &oneiron::Vault,
    actor: &McpResolvedActor,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    row_id: &str,
) -> Result<bool, McpGatewayError> {
    let Ok(id) = oneiron::EntityId::from_hex(row_id) else {
        return Ok(false);
    };
    let kind = vault
        .get_entity_type(&id)
        .map_err(|error| mcp_engine_error("mcp board row type read failed", error))?;
    if kind != Some(oneiron::registry::ENTITY_TYPE_TASK)
        || !mcp_scope_covers_entity(scoped_read, &actor.scope, &id)?
    {
        return Ok(false);
    }
    let granted = actor
        .auth
        .as_ref()
        .and_then(|auth| auth.verified_slip())
        .map(oneiron::authority::VerifiedSlip::scope);
    let whole = |axis: &oneiron::federation::ScopeAxis<_>| {
        matches!(axis, oneiron::federation::ScopeAxis::All)
    };
    if !actor.scope.is_narrow()
        && granted.is_none_or(|granted| whole(&granted.worlds) && whole(&granted.facets))
    {
        return Ok(true);
    }
    let Some(position) = vault
        .record_scope(&id)
        .map_err(|error| mcp_engine_error("mcp board row scope read failed", error))?
    else {
        return Ok(false);
    };
    // Positional: the row's world/facet stamp against the slip's world/facet
    // projection, never the slip's other bounds.
    let projection = |worlds, facets| oneiron::federation::Scope {
        worlds,
        facets,
        ..oneiron::federation::Scope::top()
    };
    let stamped = projection(position.worlds, position.facets);
    Ok(granted.is_none_or(|granted| {
        stamped.is_narrowing_of(&projection(granted.worlds.clone(), granted.facets.clone()))
    }))
}

/// Resolves one `tools/call` name against THIS endpoint's registration.
///
/// The registered surface is the WHOLE callable surface (ONE-1704 M1). There is
/// no second resolution step: a tool the other endpoint registered, and every
/// retired `oneiron.*` plain-verb name, is `unknown_tool` here even though its
/// argument catalog still exists in this process. Nothing falls back, so no
/// unadvertised name can reach an executor or bypass the result envelope.
pub(super) fn mcp_validated_call_args(
    server: &SyncServer,
    mode: McpSurfaceMode,
    params: McpToolCallParams,
    raw_arguments: Option<&str>,
    actor: &McpResolvedActor,
) -> Result<McpValidatedToolArgs, McpGatewayError> {
    let Some(tool) = server.mcp_surface(mode).resolve(&params.name) else {
        if params.name == crate::mcp::MCP_EXECUTE_CODE_TOOL {
            return Err(mcp_code_host_unbound());
        }
        // A canonical verb under the wrong root is refused with its
        // correction; it is never resolved to the verb it means.
        if let Some(refusal) = oneiron::task_verb::sdk::wrong_root(&params.name) {
            return Err(super::mcp_facade_error(refusal));
        }
        return Err(McpGatewayError::new(
            -32602,
            "unknown_tool",
            format!(
                "{name} is not registered on the {mode} Oneiron MCP endpoint",
                name = params.name,
                mode = mode.as_str(),
            ),
        )
        .with_field("name"));
    };
    // The wire's own bytes when this call arrived over HTTP; the routed
    // `Value` only when it did not (ONE-1704 repair).
    let arguments = raw_arguments.map_or_else(
        || crate::mcp::McpToolArguments::from(params.arguments),
        crate::mcp::McpToolArguments::from_raw_json,
    );
    // WHO is the credential's: a call that names no actor is the caller the
    // credential resolved to (ARCH-0028 #surface).
    crate::mcp::validate_mcp_endpoint_tool_args_as(tool, arguments, &mcp_actor_result(actor))
        .map_err(mcp_tool_validation_error)
}

/// Refuse an unavailable interpreter before decoding arguments or creating a run.
pub(super) fn mcp_code_host_unbound() -> McpGatewayError {
    McpGatewayError::new(
        -32020,
        crate::mcp::MCP_CODE_HOST_UNBOUND_CODE,
        format!(
            "{tool} has no verified production runtime on this server; no run was created",
            tool = crate::mcp::MCP_EXECUTE_CODE_TOOL,
        ),
    )
    .with_field("name")
}
