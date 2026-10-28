//! One MCP JSON-RPC request: its id and its dispatch to initialize, tools/list or tools/call.
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
        "initialize" => {
            let actor =
                resolve_handshake_caller(mode, &request_id, headers, connection, locality, server)
                    .await?
                    .toward(peer);
            // The generated-UI profile the client declares (FIX 7969),
            // answered back as negotiated. This endpoint keeps no session:
            // each call names its profile again in `_meta.clientCapabilities`.
            let declared = super::super::client_surface::declared_surface(
                request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("capabilities")),
                "params.capabilities",
                "invalid_params",
            )?;
            // It states the credential's scope, so it is released as every
            // result is (DEC-0005).
            let result = json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {
                    "name": crate::mcp::MCP_SERVER_NAME,
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": {
                    "tools": { "listChanged": false },
                    "experimental": {
                        (super::super::client_surface::MCP_GENERATED_UI_CAPABILITY):
                            super::super::client_surface::initialize_capability(declared.as_ref()),
                    },
                },
                "surfaceMode": mode.as_str(),
                "executeCodeAdmitted": matches!(mode, McpSurfaceMode::Primary)
                    && super::admission::mcp_execute_code_admitted(server, &actor),
                "instructions": "Oneiron MCP exposes foreign-client tools over the same read and write Gate as the REST core surface. Use tools/list for the tools THIS endpoint registered and tools/call to call one. A call runs as this credential's actor; it need not name one, and an actor block that names anyone else is refused.",
                "actor": mcp_actor_result(&actor),
            });
            super::device_release::mcp_release_result(server, &actor, &[], false, result)
        }
        // Actor-free, but a caller is still REQUIRED, as for every method.
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
            let request_digest =
                oneiron::receipt::call_json_digest(request.params.as_ref().unwrap_or(&Value::Null));
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
                        client_surface: params.client_surface()?,
                        ..actor.clone()
                    };
                    let args =
                        mcp_validated_call_args(server, mode, params, raw_arguments, &actor)?;
                    ensure_mcp_actor_matches(&args, &actor)?;
                    mcp_admit_scoped_call(server, &args, &actor)?;
                    execute_mcp_tool(server, args, &actor, headers, connection).await
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
