//! Tool execution dispatch across actors.

use super::{
    MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError, execute_mcp_execute_code,
    execute_mcp_generated_verb, execute_mcp_read_result, execute_mcp_setup, mcp_actor_class_wire,
};
use crate::mcp::McpActorMetadata;
use crate::mcp::McpConnectorActorResolutionError;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpSurfaceMode;
use crate::mcp::McpToolValidationError;
use crate::mcp::McpValidatedToolArgs;
use crate::server::SyncServer;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use oneiron::federation::{ScopeAxis, ScopeId};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;

/// The caller a registered MCP credential names, with its verified auth at
/// `locality`, where the request's connection sits.
pub(crate) async fn resolve_mcp_gateway_actor(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    locality: oneiron::claim::CallerLocality,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let credential = mcp_connector_credential(headers)?;
    // A paired record expires when its slip does, and a slip's lifetime runs
    // on the vault's authority clock. Judge it on that clock, as the vault
    // judges the slip: the wall clock runs ahead of it by all the time the
    // vault was closed, enough in time to expire a credential minted today.
    let now = server
        .vault
        .capability_slip_now()
        .map_err(|error| McpGatewayError::new(-32603, "engine_error", error.to_string()))?;
    let mut registry = server.mcp_registry.lock().await;
    let ceiling_exists = |actor_class: &str, actor_ref: &str| {
        server
            .vault
            .gate_actor_ceiling_exists(actor_class, actor_ref)
            .unwrap_or(false)
    };
    // The registry is memory: it learns a credential when one is redeemed over
    // HTTP. A live paired slip it has not seen gets its record now, by the
    // same rule, once the slip verifies — so a restart or a credential minted
    // on the stopped vault does not lock an agent out.
    let mut actor = match registry.resolve(&credential, now, ceiling_exists) {
        Err(McpConnectorActorResolutionError::UnknownCredential)
            if crate::api::pairing::register_live_paired_mcp(
                &mut registry,
                &credential,
                headers,
                server,
            ) =>
        {
            registry.resolve(&credential, now, ceiling_exists)
        }
        resolved => resolved,
    }
    .map_err(mcp_actor_resolution_error)?;
    drop(registry);
    // The connector header selects a registered instrument, not another
    // principal. Verify that exact instrument with its holder proof; never
    // borrow an unrelated Authorization header's owner privileges.
    let mut proof_headers = headers.clone();
    proof_headers.insert(
        AUTHORIZATION,
        format!("Bearer {credential}")
            .parse()
            .map_err(|_| mcp_proof_error())?,
    );
    let auth = crate::auth::CoreAuth::from_headers(
        &proof_headers,
        &server.config,
        server.vault().as_ref(),
    )
    .map_err(|_| mcp_proof_error())?;
    let proof = auth.verified_slip().ok_or_else(mcp_proof_error)?;
    // Only the actual configured root may act through its host-registered
    // actor. Every client is bound to the paired holder and verified class.
    if !(auth.principal_ref().is_none() && auth.is_owner_grade())
        && (auth.principal_ref() != Some(actor.gate_actor_ref.as_str())
            || auth.actor_class() != Some(actor.gate_actor_class))
    {
        return Err(mcp_proof_error());
    }
    if auth.org_ref().is_some() || !auth.has_scope(crate::auth::CoreScope::Read) {
        return Err(mcp_proof_error());
    }
    // The registry holds all or one world, and all or a set of facets. Refuse
    // a wider registration instead of silently projecting away verifier bounds.
    // A facet bound the owner's own credential carries binds nothing (owner
    // ruling FACET-READ), so it refuses no facet set.
    let axis = |id: Option<oneiron::EntityId>| {
        id.map_or(ScopeAxis::All, |id| {
            ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(id)]))
        })
    };
    let facets_owner_exempt = || {
        server
            .vault
            .credential_facets_owner_exempt(proof)
            .unwrap_or(false)
    };
    if !axis(actor.scope.world_ref).is_narrowing_of(&proof.scope().worlds)
        || (!actor.scope.facets.is_narrowing_of(&proof.scope().facets) && !facets_owner_exempt())
    {
        return Err(mcp_proof_error());
    }
    actor.auth = Some(auth.at(locality));
    // Where this request's writes land, judged once from the session it
    // names (owner ruling FACET-READ).
    let session = crate::api::write_facet::request_session(headers).map_err(|()| {
        McpGatewayError::new(-32602, "tool_args_invalid", "invalid session header")
    })?;
    let landing = crate::api::write_facet::landing_facet(
        &server.vault,
        session,
        &actor.scope.facets,
        actor.scope.facet_ref,
    );
    Ok(McpCallContext {
        actor,
        mode,
        request_id: request_id.to_owned(),
        landing,
    })
}

/// A write whose session names a facet the connector does not read, or a
/// session that does not read, is refused before anything is written, alike.
fn mcp_landing_refusal(_: crate::api::write_facet::LandingRefused) -> McpGatewayError {
    McpGatewayError::new(
        -32020,
        "mcp_scope_refused",
        "the session this request names does not place this connector's writes",
    )
}

fn mcp_proof_error() -> McpGatewayError {
    McpGatewayError::new(
        -32001,
        "mcp_auth_required",
        "the registered connector requires its live paired holder proof",
    )
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

/// The verb a call needs on this door: Read; for a write, Write — or Propose
/// when the write waits for review: it proposes and the actor's live ceiling
/// is `proposed`. So a propose-only credential (ARCH-0028: write capability
/// at `proposed`) drafts here and nowhere else, and nothing it does here takes
/// effect without review: acknowledging a task, claiming a room turn, speech,
/// a key-value write, an ask, a wait or an answer all need Write, as every
/// unbound door does.
fn mcp_call_scope(
    server: &SyncServer,
    actor: &McpResolvedActor,
    auth: &crate::auth::CoreAuth,
    effect: McpCallEffect,
) -> crate::auth::CoreScope {
    use crate::auth::CoreScope;
    match effect {
        McpCallEffect::Reads => CoreScope::Read,
        McpCallEffect::Proposes
            if !auth.has_scope(CoreScope::Write)
                && server
                    .vault
                    .gate_actor_ceiling_is_proposed(actor.gate_actor_class, &actor.gate_actor_ref)
                    .unwrap_or(false) =>
        {
            CoreScope::Propose
        }
        McpCallEffect::Proposes | McpCallEffect::Commits => CoreScope::Write,
    }
}

pub(crate) fn mcp_connector_credential(headers: &HeaderMap) -> Result<String, McpGatewayError> {
    if let Some(value) = headers
        .get(MCP_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(value.to_owned());
    }

    let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "missing MCP connector credential",
        ));
    };
    let value = value.trim_start();
    let Some((scheme, credential)) = value.split_once(char::is_whitespace) else {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "Authorization must use Bearer credentials",
        )
        .with_field("authorization"));
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "Authorization must use Bearer credentials",
        )
        .with_field("authorization"));
    }
    let credential = credential.trim();
    if credential.is_empty() {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "MCP connector credential must not be empty",
        )
        .with_field("authorization"));
    }
    Ok(credential.to_owned())
}

pub(crate) fn mcp_actor_resolution_error(
    error: McpConnectorActorResolutionError,
) -> McpGatewayError {
    let kind = match error {
        McpConnectorActorResolutionError::UnknownCredential => "mcp_credential_unknown",
        McpConnectorActorResolutionError::ExpiredCredential => "mcp_credential_expired",
        McpConnectorActorResolutionError::RevokedCredential => "mcp_credential_revoked",
        McpConnectorActorResolutionError::MissingActorCeiling => "mcp_actor_ceiling_missing",
    };
    McpGatewayError::new(-32001, kind, error.to_string())
}

pub(crate) fn mcp_params<T: DeserializeOwned>(
    params: Option<Value>,
    field: &'static str,
) -> Result<T, McpGatewayError> {
    let params = params.ok_or_else(|| {
        McpGatewayError::new(-32602, "invalid_params", "params are required").with_field(field)
    })?;
    serde_json::from_value(params).map_err(|error| {
        McpGatewayError::new(-32602, "invalid_params", error.to_string()).with_field(field)
    })
}

pub(crate) fn mcp_tool_validation_error(error: McpToolValidationError) -> McpGatewayError {
    match error {
        McpToolValidationError::Decode { tool, message } => McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            format!("{tool} arguments could not be decoded: {message}"),
        ),
        McpToolValidationError::Field {
            tool,
            field,
            message,
        } => McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            format!("{tool}.{field}: {message}"),
        )
        .with_field(field),
    }
}

pub(crate) fn ensure_mcp_actor_matches(
    args: &McpValidatedToolArgs,
    resolved: &McpResolvedActor,
) -> Result<(), McpGatewayError> {
    let actor = mcp_validated_actor(args);
    if actor.actor_ref != resolved.actor_ref.to_hex() {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor_ref must match the authenticated connector actor",
        )
        .with_field("actor.actor_ref"));
    }
    if mcp_actor_class_wire(actor.actor_class) != resolved.gate_actor_class {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor_class must match the authenticated connector actor class",
        )
        .with_field("actor.actor_class"));
    }
    if actor.gate_actor_ref != resolved.gate_actor_ref {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool gate_actor_ref must match the authenticated connector actor",
        )
        .with_field("actor.gate_actor_ref"));
    }
    if mcp_actor_class_wire(actor.gate_actor_class) != resolved.gate_actor_class {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool gate_actor_class must match the authenticated connector actor class",
        )
        .with_field("actor.gate_actor_class"));
    }
    let scope = &resolved.scope;
    if actor.scope.world_ref.as_deref()
        != scope
            .world_ref
            .as_ref()
            .map(oneiron::EntityId::to_hex)
            .as_deref()
    {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor.scope.world_ref must match the authenticated connector scope",
        )
        .with_field("actor.scope.world_ref"));
    }
    if actor.scope.facet_ref.as_deref()
        != scope
            .facet_ref
            .as_ref()
            .map(oneiron::EntityId::to_hex)
            .as_deref()
    {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor.scope.facet_ref must match the authenticated connector scope",
        )
        .with_field("actor.scope.facet_ref"));
    }
    Ok(())
}

pub(crate) fn mcp_validated_actor(args: &McpValidatedToolArgs) -> &McpActorMetadata {
    match args {
        McpValidatedToolArgs::Setup(args) => &args.actor,
        McpValidatedToolArgs::ExecuteCode(args) => &args.actor,
        McpValidatedToolArgs::ReadResult(args) => &args.actor,
        McpValidatedToolArgs::Verb(args) => &args.payload.actor,
    }
}

/// Dispatches one VALIDATED endpoint tool call: setup, execute_code, or one
/// generated verb (ONE-1704). Nothing resolves a retired `oneiron.*` name.
pub(crate) async fn execute_mcp_tool(
    server: &Arc<SyncServer>,
    args: McpValidatedToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    match &args {
        McpValidatedToolArgs::Verb(verb) => {
            mcp_verb_gate(server, verb.tool, &verb.payload.arguments, actor)?;
        }
        // Setup renders filtered board rows; execute_code persists its run
        // at once, whatever the program does.
        McpValidatedToolArgs::Setup(_) => {
            mcp_credential_gate(
                server,
                actor,
                McpRecordBounds::Filtered,
                McpCallEffect::Reads,
            )?;
        }
        // A result read takes the credential its run was admitted on.
        McpValidatedToolArgs::ExecuteCode(_) | McpValidatedToolArgs::ReadResult(_) => {
            mcp_execute_code_gate(server, actor)?;
        }
    }
    match args {
        McpValidatedToolArgs::Setup(args) => execute_mcp_setup(server, *args, actor).await,
        McpValidatedToolArgs::ExecuteCode(args) => {
            execute_mcp_execute_code(server, *args, actor).await
        }
        McpValidatedToolArgs::ReadResult(args) => {
            execute_mcp_read_result(server, *args, actor).await
        }
        McpValidatedToolArgs::Verb(args) => execute_mcp_generated_verb(server, *args, actor).await,
    }
}

/// `execute_code`'s credential gate: a run commits at once, so it needs the
/// whole record scope and Write.
pub(super) fn mcp_execute_code_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    mcp_credential_gate(
        server,
        actor,
        McpRecordBounds::Unrestricted,
        McpCallEffect::Commits,
    )
}

/// One generated verb's credential gate, whichever door the call arrived at.
///
/// Board/task lists are explicitly filtered row by row. Task detail/write
/// facades have no recursive proof projection, so they require an unrestricted
/// record scope instead of dropping caveats. A filtered read that names one
/// task reads that task's card, which is task detail too. `describe(self)`
/// renders the whole run brief, not filtered rows, so it takes the same guard.
/// A `born` write (`tasks.create`) from a narrowed connector carries its world
/// and facet into the records it mints, so only those two axes may be
/// narrowed, and it needs a Write grant. From a vault-wide connector it is
/// unrestricted, as before.
pub(crate) fn mcp_verb_gate(
    server: &Arc<SyncServer>,
    tool: crate::mcp::McpGeneratedVerbTool,
    arguments: &crate::mcp::McpVerbArguments,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    let bounds = if tool.filtered_read()
        && arguments.task_ref.is_none()
        && arguments.self_target != Some(true)
    {
        McpRecordBounds::Filtered
    } else if tool.born_in_scope() && actor.scope.is_narrow() {
        McpRecordBounds::Born
    } else {
        McpRecordBounds::Unrestricted
    };
    mcp_credential_gate(server, actor, bounds, McpCallEffect::of(tool, arguments))
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

/// The connector credential is live, inside the record bounds the call can
/// carry, and holds the verb for what the call does.
fn mcp_credential_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    bounds: McpRecordBounds,
    effect: McpCallEffect,
) -> Result<(), McpGatewayError> {
    let auth = actor.auth.as_ref().ok_or_else(mcp_proof_error)?;
    if !auth.credential_is_live(server.vault().as_ref()) {
        return Err(mcp_proof_error());
    }
    let axis = |id: Option<oneiron::EntityId>| {
        id.map_or(ScopeAxis::All, |id| {
            ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(id)]))
        })
    };
    let carried = match bounds {
        McpRecordBounds::Filtered => Ok(()),
        McpRecordBounds::Born => {
            let landing = actor.landing.map_err(mcp_landing_refusal)?;
            auth.require_record_scope_carried(axis(actor.scope.world_ref), axis(landing))
        }
        McpRecordBounds::Unrestricted => auth.require_unrestricted_record_scope(),
    };
    carried.map_err(|_| {
        McpGatewayError::new(
            -32020,
            "mcp_scope_unprojectable",
            "this facade cannot project the credential's record bounds",
        )
    })?;
    match bounds {
        // The world and facet it carries were judged just above. The birth
        // takes Write: a Propose-only grant would rest on a ceiling read
        // outside the transaction that commits the TASK.
        McpRecordBounds::Born => auth.require_granted(crate::auth::CoreScope::Write),
        McpRecordBounds::Filtered | McpRecordBounds::Unrestricted => {
            auth.require(mcp_call_scope(server, actor, auth, effect))
        }
    }
    .map_err(|_| mcp_proof_error())
}
