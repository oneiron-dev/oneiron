//! Who an MCP call acts as: its actor, resolved from its credential, proof headers and placement.
//! `resolve_mcp_gateway_actor` and `ensure_mcp_actor_matches` are its call surface.
//! `crate::mcp` defines `McpResolvedActor` and the resolution errors forwarded here.

use super::*;

/// The session and the room turn a request names in its headers.
pub(in crate::api::mcp_gateway) fn mcp_request_placement(
    headers: &HeaderMap,
) -> Result<(Option<oneiron::EntityId>, Option<oneiron::EntityId>), McpGatewayError> {
    let session = crate::api::write_facet::request_session(headers).map_err(|()| {
        McpGatewayError::new(-32602, "tool_args_invalid", "invalid session header")
    })?;
    let room_turn = headers
        .get(crate::api::facade::ROOM_TURN_HEADER)
        .map(|room| {
            room.to_str()
                .ok()
                .and_then(|room| oneiron::EntityId::from_hex(room.trim()).ok())
                .ok_or_else(|| {
                    McpGatewayError::new(-32602, "tool_args_invalid", "invalid room turn header")
                })
        })
        .transpose()?;
    Ok((session, room_turn))
}

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
    let proof_headers = mcp_proof_headers(headers)?;
    let auth = crate::auth::CoreAuth::from_headers(
        &proof_headers,
        &server.config,
        server.vault().as_ref(),
    )
    .map_err(|_| mcp_proof_error())?
    .at(locality);
    let (session, room_turn) = mcp_request_placement(headers)?;
    // A narrower caller's own holder proof, for the home an opened device
    // asks (FIX 2905): the one this request was admitted on.
    let forwarded = (!auth.is_owner_grade())
        .then(|| auth.forwarded_caller_proof(&proof_headers))
        .flatten();
    let mut context = registered_actor(
        server,
        &credential,
        auth,
        mode,
        request_id,
        session,
        room_turn,
    )
    .await?;
    context.forwarded = forwarded;
    Ok(context)
}

/// The same connector resolution after the facade or MCP door verified the
/// caller's holder proof. The token is the bound request's, never an input.
/// A managed vault's attested owner, with no invocation slip, is his own
/// call, as on `/mcp` (FIX 5400).
pub(crate) async fn resolve_mcp_actor_for_auth(
    server: &Arc<SyncServer>,
    auth: &crate::auth::CoreAuth,
    session: Option<oneiron::EntityId>,
) -> Result<McpCallContext, McpGatewayError> {
    if let Some(owner) = super::owner_call::attested_owner_call(server, auth, session) {
        return owner;
    }
    let credential = auth
        .invocation_slip()
        .ok_or_else(mcp_proof_error)?
        .credential_token()
        .map_err(|_| mcp_proof_error())?;
    registered_actor(
        server,
        &credential,
        auth.clone(),
        McpSurfaceMode::Primary,
        "memory-proxy",
        session,
        None,
    )
    .await
}

pub(super) async fn registered_actor(
    server: &Arc<SyncServer>,
    credential: &str,
    auth: crate::auth::CoreAuth,
    mode: McpSurfaceMode,
    request_id: &str,
    session: Option<oneiron::EntityId>,
    room_turn: Option<oneiron::EntityId>,
) -> Result<McpCallContext, McpGatewayError> {
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
    let mut actor = match registry.resolve(credential, now, ceiling_exists) {
        Err(McpConnectorActorResolutionError::UnknownCredential)
            if crate::api::pairing::register_live_paired_mcp(
                &mut registry,
                credential,
                &auth,
                server,
            ) =>
        {
            registry.resolve(credential, now, ceiling_exists)
        }
        resolved => resolved,
    }
    .map_err(mcp_actor_resolution_error)?;
    drop(registry);
    mcp_proof_admits(server, &actor, &auth)?;
    let session_ref = session.map(|session| session.to_hex());
    actor.auth = Some(auth.in_off_record_session(session_ref.as_deref()));
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
        invocation: None,
        hook_ask: None,
        off_record_session: session_ref,
        room_turn,
        drain: None,
        forwarded: None,
    })
}

/// `headers` with the credential the connector header selected as their
/// bearer. The header selects a registered instrument, not another
/// principal: an unrelated Authorization header is replaced, so its owner
/// privileges are never borrowed. A call's proof is verified on these, and
/// an action's rows run on them.
pub(in crate::api::mcp_gateway) fn mcp_proof_headers(
    headers: &HeaderMap,
) -> Result<HeaderMap, McpGatewayError> {
    let credential = mcp_connector_credential(headers)?;
    let mut proof_headers = headers.clone();
    proof_headers.insert(
        AUTHORIZATION,
        format!("Bearer {credential}")
            .parse()
            .map_err(|_| mcp_proof_error())?,
    );
    Ok(proof_headers)
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
        McpValidatedToolArgs::InvokeAction(args) => &args.actor,
        McpValidatedToolArgs::Verb(args) => &args.payload.actor,
    }
}
