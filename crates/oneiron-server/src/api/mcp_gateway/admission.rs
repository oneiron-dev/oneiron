//! Scoped-call admission and actor resolution.

use super::{
    McpCallContext, McpGatewayError, McpToolCallParams, mcp_api_error, mcp_engine_error,
    mcp_scoped_read, mcp_tool_validation_error,
};
use crate::api::parse_entity_id_param;
use crate::mcp::McpSurfaceMode;
use crate::mcp::McpValidatedToolArgs;
use crate::server::SyncServer;
use oneiron::EdgeKind;
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
/// for every non-verb call. `execute_code` builds an actor-wide gated write and
/// `tasks.create` writes through the actor-wide memory facade, so neither can
/// be narrowed downstream; under a world- OR facet-narrowed credential both are
/// refused here, fail-closed, with the two axes enforced independently. There is
/// no scoped-positive service for narrowed credentials in this release, and a
/// refusal is the truthful shape of that.
///
/// A caller echo can only ever narrow. Nothing a caller sends creates
/// authority, and a refusal here happens before dispatch, not after.
pub(crate) fn mcp_admit_scoped_call(
    server: &Arc<SyncServer>,
    args: &McpValidatedToolArgs,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    let tool_name = mcp_called_tool_name(args);
    if !actor.admits_tool(tool_name) {
        return Err(McpGatewayError::new(
            -32020,
            "mcp_verb_not_bound",
            format!("{tool_name} is not bound to this connector credential"),
        )
        .with_field("name"));
    }
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
        McpValidatedToolArgs::Verb(verb) => verb,
        // The retired plain-verb adapters carry no scope projection either, so
        // a narrowed credential is refused on them by the same rule. After M1
        // no wire name resolves onto them at all.
        _ => return mcp_admit_unscoped_execution(actor, tool_name, "name"),
    };
    if let Some(scopes) = verb.payload.arguments.scopes.as_ref() {
        mcp_admit_subscription_scopes(actor, scopes)?;
    }
    if let Some(task_ref) = verb.payload.arguments.task_ref.as_deref() {
        let id = parse_entity_id_param(task_ref, "arguments.task_ref").map_err(mcp_api_error)?;
        mcp_admit_scoped_entity(server, actor, &id, "arguments.task_ref")?;
    }
    if matches!(verb.tool.binding, crate::mcp::McpVerbBinding::TasksCreate) {
        mcp_admit_unscoped_execution(actor, verb.tool.name, "arguments.spec")?;
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
    let axis = match (scope.world_ref.is_some(), scope.facet_ref.is_some()) {
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
        McpValidatedToolArgs::Verb(verb) => verb.tool.name,
        // Unreachable from the wire after M1: no unlisted name resolves.
        _ => "",
    }
}

/// Intersects a caller's requested STREAM categories with the ceiling this
/// credential was ATTACHED under.
fn mcp_admit_subscription_scopes(
    actor: &McpCallContext,
    requested: &[crate::mcp::McpSubscriptionScope],
) -> Result<(), McpGatewayError> {
    let asked = requested
        .iter()
        .copied()
        .map(crate::mcp::McpSubscriptionScope::engine)
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
    let readable = scoped_read
        .is_entity_readable(id)
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

/// True when the registered world/facet ceiling covers this entity.
///
/// A vault-wide credential covers everything. A facet-scoped credential covers
/// only rows that actually carry the `FacetOf` edge to that facet.
///
/// ONE-1704 B5: the world axis is now symmetric with that facet axis, and it
/// applies to EVERY addressed row rather than to CLAIMs alone. Only a CLAIM
/// carries a `world` key, so a task/entity row that carries none cannot be
/// PROVEN in this credential's world and is refused; a CLAIM is covered exactly
/// when its own `world` key is this credential's world. No world projection is
/// invented for non-claim rows here — a projection is engine scope, and until
/// one exists the fail-closed answer is the only true one. Prerelease law: the
/// admission is narrowed outright, with no compatibility carve-out for the rows
/// the old CLAIM-only check let through.
pub(super) fn mcp_scope_covers_entity(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    scope: &crate::mcp::McpConnectorScope,
    id: &oneiron::EntityId,
) -> Result<bool, McpGatewayError> {
    if let Some(world_ref) = scope.world_ref {
        let entity_type = scoped_read
            .vault()
            .get_entity_type(id)
            .map_err(|error| mcp_engine_error("mcp scope type read failed", error))?;
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
    if let Some(facet_ref) = scope.facet_ref {
        let edges = scoped_read
            .edges_out(id)
            .map_err(|error| mcp_engine_error("mcp scope facet read failed", error))?
            .unwrap_or_default();
        let carries_facet = edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::FacetOf && edge.target == facet_ref);
        if !carries_facet {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Resolves one `tools/call` name against THIS endpoint's registration.
///
/// The registered surface is the WHOLE callable surface (ONE-1704 M1). There is
/// no second resolution step: a tool the other endpoint registered, and every
/// retired `oneiron.*` plain-verb name, is `unknown_tool` here even though its
/// argument catalog still exists in this process. Nothing falls back, so no
/// unadvertised name can reach an executor or bypass the result envelope.
pub(super) fn mcp_validated_call_args(
    mode: McpSurfaceMode,
    params: McpToolCallParams,
    raw_arguments: Option<&str>,
) -> Result<McpValidatedToolArgs, McpGatewayError> {
    let Some(tool) = crate::mcp::registered_surface(mode).resolve(&params.name) else {
        if params.name == crate::mcp::MCP_EXECUTE_CODE_TOOL {
            return Err(mcp_execute_code_unavailable());
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
    crate::mcp::validate_mcp_endpoint_tool_args(tool, arguments).map_err(mcp_tool_validation_error)
}

/// The ONE stable typed refusal a direct `execute_code` call receives
/// (ONE-1704 B2).
///
/// It is raised at the single name-resolution chokepoint both routes share, so
/// it lands BEFORE arguments decode, before admission, and before any executor:
/// no run is created, no durable run handle is minted, no `Waiting` is
/// published, and no `resume` block or `terminal:false` advancement claim can
/// reach the wire, under full or narrowed credentials on either endpoint.
///
/// This is the FINAL release posture, not a placeholder for a host that is
/// about to appear: `execute_code` is not shipped in this release, and the
/// refusal says exactly that instead of the generic `unknown_tool` a retired
/// name would otherwise get.
pub(super) fn mcp_execute_code_unavailable() -> McpGatewayError {
    McpGatewayError::new(
        -32020,
        crate::mcp::MCP_EXECUTE_CODE_UNAVAILABLE_CODE,
        format!(
            "{tool} is not shipped in this release: it is registered on no endpoint and no run \
             was created",
            tool = crate::mcp::MCP_EXECUTE_CODE_TOOL,
        ),
    )
    .with_field("name")
}
