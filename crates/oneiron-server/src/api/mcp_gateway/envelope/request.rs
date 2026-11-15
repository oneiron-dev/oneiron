//! One MCP JSON-RPC request: its id and its dispatch to the method it names.
//! `handle_mcp_request` is its call surface.
//! The envelope root defines `McpJsonRpcRequest` and `McpCallContext`, the records forwarded here.

use super::*;

/// The stable request id a result or refusal is keyed by.
pub(in crate::api::mcp_gateway) fn mcp_request_id(id: &Value) -> String {
    match id {
        Value::String(id) => id.clone(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}

pub(crate) async fn handle_mcp_request(
    mode: McpSurfaceMode,
    headers: &HeaderMap,
    locality: CallerLocality,
    connection: &Extensions,
    server: &Arc<SyncServer>,
    request: McpJsonRpcRequest,
    raw_arguments: Option<&str>,
    held: Option<super::blob_body::McpHeld>,
) -> Result<Value, McpGatewayError> {
    if request.jsonrpc != "2.0" {
        return Err(
            McpGatewayError::new(-32600, "invalid_request", "jsonrpc must be \"2.0\"")
                .with_field("jsonrpc"),
        );
    }
    let request_id = mcp_request_id(request.id.as_ref().unwrap_or(&Value::Null));
    // The machine this request's connection proved: the call reads, and
    // every release is judged, for it (mesh PR2b).
    let peer = crate::auth::proved_peer(headers, connection);

    match request.method.as_str() {
        // The static catalog answers before any caller is resolved, an
        // unauthenticated prober's included: it names no one, so it has no
        // one to resolve (canon ARCH-0028 "Discover catalog"; Engine RULING
        // L1-04 = B, 13 Nov 2026).
        "server/discover" => Ok(mcp_server_discover_result()),
        "initialize" => {
            let actor =
                resolve_handshake_caller(mode, &request_id, headers, connection, locality, server)
                    .await?
                    .toward(peer);
            // The generated-UI profile the client declares (FIX 7969),
            // answered back as negotiated (`null`: none this build reads).
            // This endpoint keeps no session: each call names its profile
            // again in `_meta.clientCapabilities`.
            let declared = super::super::client_surface::declared_surface(
                request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("capabilities")),
            );
            // It states the credential's scope, so it is released as every
            // result is (DEC-0005).
            // The vault this origin answers for (FIX 11695): its authority
            // id, so a hosted login confirms the vault it was told before it
            // records the credential. Null until the vault is rooted, or when
            // the fold does not compute; the handshake never fails for it.
            let vault_id = server
                .vault()
                .authority_vault_id()
                .ok()
                .flatten()
                .map(|id| crate::owner::vault_key::hex(&id));
            // The version the client asks for when this server speaks it,
            // else the newest (FIX 4902).
            let protocol_version = mcp_negotiated_version(
                request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("protocolVersion"))
                    .and_then(Value::as_str),
            );
            let result = json!({
                "protocolVersion": protocol_version,
                "serverInfo": {
                    "name": crate::mcp::MCP_SERVER_NAME,
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": mcp_server_capabilities(declared.as_ref()),
                "surfaceMode": mode.as_str(),
                "executeCodeAdmitted": matches!(mode, McpSurfaceMode::Primary)
                    && super::admission::mcp_execute_code_admitted(server, &actor),
                "instructions": "Oneiron MCP exposes foreign-client tools over the same read and write Gate as the REST core surface. Use tools/list for the tools THIS endpoint registered and tools/call to call one. A call runs as this credential's actor; it need not name one, and an actor block that names anyone else is refused.",
                "actor": mcp_actor_result(&actor),
                "vault_id": vault_id,
            });
            super::device_release::mcp_release_result(server, &actor, &[], false, result, false)
        }
        // Actor-free, but a caller is still REQUIRED, as for every method but
        // `server/discover`.
        "notifications/initialized" => {
            resolve_handshake_caller(mode, &request_id, headers, connection, locality, server)
                .await?;
            Ok(json!({}))
        }
        "oneiron/wakes" => {
            let actor =
                resolve_handshake_caller(mode, &request_id, headers, connection, locality, server)
                    .await?
                    .toward(peer);
            super::wakes::poll(server, &actor, request.params).await
        }
        // Deliberately actor-free: a listing that echoed the caller back would
        // not be byte-identical across credentials, and the whole point of an
        // immutable registration is that it is the same bytes for everyone.
        // A caller is still REQUIRED (its credential, or the owner a managed
        // vault's supervisor attested), just never reflected. A stale owner
        // sign-in's booking caller is listed the booking tools alone (FIX 5934).
        "tools/list" => {
            let actor =
                resolve_handshake_caller(mode, &request_id, headers, connection, locality, server)
                    .await?
                    .toward(peer);
            Ok(json!({
                "surfaceMode": mode.as_str(),
                "tools": super::booking_call::tools_listing(server, mode, &actor)?,
            }))
        }
        "tools/call" => {
            // The owner's clock repair whose caller its own writer judges,
            // before any caller here reads the clock (FIX 11190, FIX 11202).
            if let Some(caller) = super::clock_repair_call::deferred_caller(
                server,
                headers,
                connection,
                request.params.as_ref(),
            ) {
                return super::clock_repair_call::repair_call(
                    server,
                    mode,
                    request.params,
                    raw_arguments,
                    caller,
                )
                .await;
            }
            // A stale owner sign-in's booking tool call is his (FIX 5327).
            let actor = super::booking_call::resolve_tool_caller(
                mode,
                &request_id,
                headers,
                connection,
                locality,
                server,
                request.params.as_ref(),
            )
            .await?
            .toward(peer);
            // OF-538: what the call's receipt states of its request, taken
            // before the params are consumed.
            let tool = request
                .params
                .as_ref()
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            // A body whose content is held as a file states its params as
            // they arrived (FIX 22074).
            let request_digest = match &held {
                Some(held) => held.params_digest().to_owned(),
                None => oneiron::receipt::call_json_digest(
                    request.params.as_ref().unwrap_or(&Value::Null),
                ),
            };
            // OF-568: what the call reads, captured before it runs.
            let inputs =
                crate::api::call_receipt::action_inputs(server, &tool, request.params.as_ref());
            // OF-063: only a caller whose principal is verified in the
            // session keeps no record, judged on arrival and again before the
            // receipt is written. The configured root maps to the actor it
            // acts through (FIX 2271), the one its rows' surfaces bind.
            let principal = crate::api::call_receipt::mcp_session_principal(
                actor.auth.as_ref(),
                actor.actor_ref,
            );
            let anonymous =
                crate::api::call_receipt::in_anonymous_session(server, headers, principal)
                    || crate::api::call_receipt::room_notes::mcp_room_note_call(
                        server,
                        headers,
                        principal,
                        &tool,
                        request.params.as_ref(),
                    );
            // FIX 1085: the call counts once on the wire, under the caller
            // resolved above and the tool it names, before it is judged.
            super::wire::observe_tool_call(server, mode, &actor, &tool, anonymous);
            // OF-568 L4: the attempt whose live run the call holds, as the
            // hold witnessed it.
            let (called, attempt): (Result<Value, McpGatewayError>, _) =
                crate::api::call_receipt::attempt_witnessed(async {
                    let params: McpToolCallParams = mcp_params(request.params, "params")?;
                    let actor = McpCallContext {
                        invocation: params.invocation()?,
                        hook_ask: params.hook_ask()?,
                        client_surface: params.client_surface(),
                        signing_request_transport: Some(
                            oneiron::memory::SigningRequestTransport::new(
                                connection
                                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                                    // Embedded locality uses loopback:0, not a TCP peer.
                                    .filter(|peer| peer.0.port() != 0)
                                    .map(|peer| peer.0.ip()),
                                headers
                                    .get(axum::http::header::USER_AGENT)
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_owned),
                            ),
                        ),
                        ..actor.clone()
                    };
                    let mut args =
                        mcp_validated_call_args(server, mode, params, raw_arguments, &actor)?;
                    // The held content rides the call of the tool it arrived
                    // for, with that call's page argument digest (FIX 22074).
                    if let (Some(held), crate::mcp::McpValidatedToolArgs::Verb(call)) =
                        (held, &mut args)
                    {
                        call.held = held.content_for(call).map_err(|error| {
                            McpGatewayError::new(-32603, "engine_error", error.to_string())
                        })?;
                    }
                    ensure_mcp_actor_matches(&args, &actor)?;
                    mcp_admit_scoped_call(server, &args, &actor)?;
                    // A named verb call keeps its admission intent, as the
                    // facade's does, unless it sits off the record (FIX 4735).
                    let intent = super::super::admission_intent::McpIntent::of(
                        server, &args, &actor, anonymous,
                    );
                    // The tool fan-out, on the heap (FIX 12072).
                    let run = execute_mcp_tool(server, args, &actor, headers, connection);
                    Box::pin(super::super::admission_intent::observed(
                        server,
                        &actor,
                        intent,
                        run,
                        |result| result,
                    ))
                    .await
                })
                .await;
            // ONE-1704 M4: ONE chokepoint. Everything inside that block happened
            // AFTER the credential resolved, so every refusal it can produce —
            // decode, validation, actor mismatch, bound-verb or scope refusal,
            // scoped-grant refusal, board/task dispatch, projection, facade, or
            // engine failure — leaves with the effective scope attached. Only
            // failures before this point are legitimately scope-less. Each is
            // released as a result is, by the rows its words and its scope
            // name (DEC-0005).
            let called = called.map_err(|error| {
                super::device_release::mcp_release_error(
                    server,
                    &actor,
                    Some(&[]),
                    error.with_effective_scope(&actor),
                )
            });
            let anonymous = anonymous
                || crate::api::call_receipt::in_anonymous_session(server, headers, principal);
            mcp_call_receipt(
                server,
                &actor,
                tool,
                request_digest,
                inputs,
                attempt,
                anonymous,
                called,
            )
        }
        _ => Err(McpGatewayError::new(
            -32601,
            "method_not_found",
            format!("unsupported MCP method {}", request.method),
        )
        .with_field("method")),
    }
}

/// The capabilities this server declares: its tools, whose registration is
/// fixed, and generated UI, with the profile `declared` names as negotiated
/// (`None`: none declared, as `server/discover` answers every caller).
fn mcp_server_capabilities(
    declared: Option<&oneiron::lens::GeneratedUiSurfaceCapabilities>,
) -> Value {
    json!({
        "tools": { "listChanged": false },
        "experimental": {
            (super::super::client_surface::MCP_GENERATED_UI_CAPABILITY):
                super::super::client_surface::initialize_capability(declared),
        },
    })
}

/// `server/discover` (canon ARCH-0028 "Discover catalog"): the static,
/// account-neutral identity and capability summary, the same bytes for every
/// caller. It holds the server's name and build version, the protocol
/// versions it speaks, its capabilities and its endpoints. It holds nothing
/// of the vault, a caller, a scope, a world or a facet, and no live state:
/// retrieval health rides each result's envelope instead. It is the one
/// publicly cacheable result (mcp-rc:cache-refusal).
fn mcp_server_discover_result() -> Value {
    let endpoints: Vec<Value> = McpSurfaceMode::ALL
        .iter()
        .map(|mode| {
            json!({
                "path": mode.path(),
                "surfaceMode": mode.as_str(),
            })
        })
        .collect();
    json!({
        "serverInfo": {
            "name": crate::mcp::MCP_SERVER_NAME,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "protocolVersions": MCP_PROTOCOL_VERSIONS,
        "capabilities": mcp_server_capabilities(None),
        "endpoints": endpoints,
        "ttlMs": crate::mcp::MCP_DISCOVER_TTL_MS,
        "cacheScope": crate::mcp::MCP_DISCOVER_CACHE_SCOPE,
    })
}
