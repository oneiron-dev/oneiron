//! The MCP gateway's HTTP side: its routes, its connection stamp and each POST's JSON-RPC reply.
//! `mcp_gateway` and `mcp_tool_first_gateway` are its call surface.
//! The envelope root defines `McpCallContext` and `McpGatewayError`, the records forwarded here.

use super::*;

/// The PRIMARY endpoint: the truthful `setup_oneiron` catalog. `execute_code`
/// is not registered in this release; direct requests receive its typed
/// unavailable refusal at the shared name-resolution door. `connection` is
/// the request's own (its peer, the machine its binding proved): an action's
/// rows run under it.
pub(crate) async fn mcp_gateway(
    headers: HeaderMap,
    Locality(locality): Locality,
    State(server): State<Arc<SyncServer>>,
    connection: Extensions,
    body: Bytes,
) -> impl IntoResponse {
    // What a tool's answer holds (a deck preview's renderer) is kept until
    // the reply is encoded (FIX 8238).
    crate::api::answer_hold::until_encoded(mcp_endpoint(
        McpSurfaceMode::Primary,
        headers,
        locality,
        connection,
        server,
        body,
    ))
    .await
}

/// The TOOL-FIRST endpoint: one generated tool per exported verb row.
///
/// A separately registered host endpoint, not a mode switch: nothing on the
/// wire moves a connection between this router entry and the primary one.
pub(crate) async fn mcp_tool_first_gateway(
    headers: HeaderMap,
    Locality(locality): Locality,
    State(server): State<Arc<SyncServer>>,
    connection: Extensions,
    body: Bytes,
) -> impl IntoResponse {
    // What a tool's answer holds (a deck preview's renderer) is kept until
    // the reply is encoded (FIX 8238).
    crate::api::answer_hold::until_encoded(mcp_endpoint(
        McpSurfaceMode::ToolFirst,
        headers,
        locality,
        connection,
        server,
        body,
    ))
    .await
}

/// A reply no `tools/call` receipt covers is its connection's (FIX 811): a
/// parse or envelope error, an invocation claim's refusal, `initialize`,
/// `tools/list`, `oneiron/wakes`, an unknown method, and a `tools/call`
/// refused before its credential resolved. A refusal states the ref in
/// `error.data.receipt_ref`, as a refused call does; every such reply states
/// it in `x-oneiron-receipt-ref`. A result's body is left as it is, so
/// `tools/list` stays the same bytes for every credential.
pub(super) fn mcp_connection_stamp(
    server: &SyncServer,
    headers: &HeaderMap,
    method: &str,
    body: &[u8],
    answered: &mut Result<Value, McpGatewayError>,
) -> crate::api::call_receipt::CallStamp {
    let (outcome, result_digest) = match &*answered {
        Ok(result) => (
            oneiron::receipt::CallOutcome::Ok,
            Some(oneiron::receipt::call_json_digest(result)),
        ),
        Err(error) => (
            oneiron::receipt::CallOutcome::Refused {
                code: error.kind.to_owned(),
            },
            Some(oneiron::receipt::call_refusal_digest(
                error.kind,
                &error.message,
            )),
        ),
    };
    let anonymous = crate::api::call_receipt::in_anonymous_session(server, headers, None);
    let stamp = crate::api::call_receipt::record(
        server,
        anonymous,
        crate::api::call_receipt::connection_call(
            oneiron::receipt::CallTransport::Mcp,
            method.to_owned(),
            outcome,
            oneiron::receipt::call_bytes_digest(body),
            result_digest,
        ),
    );
    if let Err(error) = answered {
        // FIX 1085: it counts on the wire on its own, under no caller.
        super::wire::observe_envelope_error(server, method, error.kind);
        error.call_receipt = Some(Box::new(stamp.clone()));
    }
    stamp
}

/// One JSON-RPC reply: its result, or its error.
pub(super) fn mcp_envelope(id: Value, answered: Result<Value, McpGatewayError>) -> Value {
    match answered {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        Err(error) => mcp_error_response(id, error),
    }
}

/// The HTTP reply: a connection's receipt in `x-oneiron-receipt-ref`, or,
/// for a reply a `tools/call` receipt covers (or a replay of one), the mark
/// that its door answered it.
pub(super) fn mcp_http_reply(
    reply: Value,
    stamp: Option<&crate::api::call_receipt::CallStamp>,
) -> Response {
    let mut response = Json(reply).into_response();
    match stamp {
        Some(stamp) => stamp.stamp_header(&mut response),
        None => {
            response
                .extensions_mut()
                .insert(crate::api::call_receipt::DoorAnswered);
        }
    }
    response
}

/// An envelope refused before any method ran, as its connection's reply.
pub(super) fn mcp_connection_refusal(
    server: &SyncServer,
    headers: &HeaderMap,
    method: &str,
    body: &[u8],
    id: Value,
    error: McpGatewayError,
) -> Response {
    let mut refused = Err(error);
    let stamp = mcp_connection_stamp(server, headers, method, body, &mut refused);
    mcp_http_reply(mcp_envelope(id, refused), Some(&stamp))
}

pub(super) async fn mcp_endpoint(
    mode: McpSurfaceMode,
    headers: HeaderMap,
    locality: CallerLocality,
    connection: Extensions,
    server: Arc<SyncServer>,
    body: Bytes,
) -> Response {
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(raw) => raw,
        Err(error) => {
            return mcp_connection_refusal(
                &server,
                &headers,
                "mcp",
                &body,
                Value::Null,
                McpGatewayError::new(-32700, "parse_error", error.to_string()),
            );
        }
    };
    let id = raw.get("id").cloned().unwrap_or(Value::Null);
    let request = match serde_json::from_value::<McpJsonRpcRequest>(raw) {
        Ok(request) => request,
        Err(error) => {
            return mcp_connection_refusal(
                &server,
                &headers,
                "mcp",
                &body,
                id,
                McpGatewayError::new(-32600, "invalid_request", error.to_string()),
            );
        }
    };
    let id = request.id.clone().unwrap_or(id);

    // The envelope above is routed from a `Value`, which rounds a JSON number
    // through `f64`. Tool arguments are decoded against the ADVERTISED schema
    // instead, so their ORIGINAL spelling is read back out of the request bytes
    // and carried to that decoder unrounded (ONE-1704 repair).
    let raw_arguments = crate::mcp::mcp_raw_call_arguments(&body);
    // A `tools/call` that names its invocation claims it for the whole
    // request (OF-580): a second call naming it for the same call waits for
    // this one's reply and gets it, under its own id; one naming it for
    // another call is refused at once.
    // The owner's clock repair whose caller its own writer judges claims no
    // invocation: resolving the claim's owner reads the clock it repairs
    // (FIX 11202).
    let deferred_repair = super::clock_repair_call::deferred_caller(
        &server,
        &headers,
        &connection,
        request.params.as_ref(),
    )
    .is_some();
    let claim = match mcp_named_invocation(&request).filter(|_| !deferred_repair) {
        None => None,
        Some(invocation) => {
            // A held socket's owner is judged before anything is claimed or
            // replayed, and keys the claim (FIX 5128); a stale one's booking
            // tool call is his to claim (FIX 5327).
            let params = request.params.as_ref();
            let owner_of = || {
                super::booking_call::invocation_owner(mode, &headers, &connection, &server, params)
            };
            let owner = match owner_of() {
                Ok(owner) => owner,
                Err(error) => {
                    return mcp_connection_refusal(
                        &server,
                        &headers,
                        &request.method,
                        &body,
                        id,
                        error,
                    );
                }
            };
            let call = mcp_invocation_body(
                mode,
                locality,
                &headers,
                &owner,
                &request,
                raw_arguments.as_deref(),
            );
            match facade::claim_door_invocation(&server, invocation, call).await {
                DoorClaim::Run(claim) => Some(claim),
                DoorClaim::Answered(outcome) => {
                    // And again once the wait is over, before a reply is his.
                    if let Err(error) = owner_of() {
                        return mcp_connection_refusal(
                            &server,
                            &headers,
                            &request.method,
                            &body,
                            id,
                            error,
                        );
                    }
                    // The waiter is resolved again, on its own connection's
                    // machine: a credential no longer live gets the refusal
                    // it gets anywhere, and the kept answer is released for
                    // this waiter (FIX 7914).
                    let waiter = match super::booking_call::resolve_tool_caller(
                        mode,
                        &mcp_request_id(&id),
                        &headers,
                        &connection,
                        locality,
                        &server,
                        params,
                    )
                    .await
                    {
                        Ok(waiter)
                            if waiter
                                .auth
                                .as_ref()
                                .is_some_and(|auth| !auth.credential_is_live(server.vault())) =>
                        {
                            Err(super::super::actor_dispatch::mcp_proof_error())
                        }
                        Ok(waiter) => {
                            Ok(waiter.toward(crate::auth::proved_peer(&headers, &connection)))
                        }
                        Err(error) => Err(error),
                    };
                    let waiter = match waiter {
                        Ok(waiter) => waiter,
                        Err(error) => {
                            return mcp_connection_refusal(
                                &server,
                                &headers,
                                &request.method,
                                &body,
                                id,
                                error,
                            );
                        }
                    };
                    let mut reply =
                        super::super::claimed_release::replayed(&server, &waiter, outcome);
                    if let Some(reply) = reply.as_object_mut() {
                        reply.insert("id".to_owned(), id);
                    }
                    // The replay states the first call's receipt.
                    return mcp_http_reply(reply, None);
                }
                DoorClaim::InFlight => {
                    return mcp_connection_refusal(
                        &server,
                        &headers,
                        &request.method,
                        &body,
                        id,
                        McpGatewayError::new(
                            -32020,
                            facade::INVOCATION_IN_FLIGHT,
                            "another request is still running this invocation; retry with it once the first call returns",
                        ),
                    );
                }
                DoorClaim::Conflict => {
                    return mcp_connection_refusal(
                        &server,
                        &headers,
                        &request.method,
                        &body,
                        id,
                        McpGatewayError::new(
                            -32020,
                            facade::INVOCATION_CONFLICT,
                            "this invocation id names a different call",
                        ),
                    );
                }
            }
        }
    };
    let method = request.method.clone();
    let call = handle_mcp_request(
        mode,
        &headers,
        locality,
        &connection,
        &server,
        request,
        raw_arguments.as_deref(),
    );
    // A claimed call keeps the answer its release judged, for the calls
    // waiting on it (FIX 7914).
    let (mut result, judged) = if claim.is_some() {
        super::super::claimed_release::capturing(call).await
    } else {
        (call.await, None)
    };
    // A `tools/call` that reached its door carries its own receipt; every
    // other reply is the connection's (FIX 811).
    let covered = match &result {
        Ok(_) => method == "tools/call",
        Err(error) => error.call_receipt.is_some(),
    };
    let stamp =
        (!covered).then(|| mcp_connection_stamp(&server, &headers, &method, &body, &mut result));
    let reply = mcp_envelope(id, result);
    if let Some(claim) = claim {
        let mut saved = reply.clone();
        if let Some(saved) = saved.as_object_mut() {
            saved.remove("id");
        }
        let peer = crate::auth::proved_peer(&headers, &connection);
        let release = super::super::claimed_release::kept(peer, &saved, judged);
        claim.finish(InvocationOutcome {
            status: 200,
            body: saved,
            release,
        });
    }
    mcp_http_reply(reply, stamp.as_ref())
}

/// The invocation a `tools/call` names in `_meta`, when it names a valid
/// one; a malformed one is left to the call's own refusal.
pub(super) fn mcp_named_invocation(request: &McpJsonRpcRequest) -> Option<InvocationId> {
    if request.method != "tools/call" {
        return None;
    }
    request
        .params
        .as_ref()?
        .get("_meta")?
        .get(MCP_INVOCATION_META)?
        .as_str()
        .and_then(InvocationId::parse_hex)
}

/// The call a claimed MCP invocation names: the endpoint, the credential
/// headers and session the actor resolves from, the owner a managed vault's
/// supervisor attested for it or for the held socket it came on (empty for
/// none), where the caller sits, and the call itself.
pub(super) fn mcp_invocation_body(
    mode: McpSurfaceMode,
    locality: CallerLocality,
    headers: &HeaderMap,
    owner: &str,
    request: &McpJsonRpcRequest,
    raw_arguments: Option<&str>,
) -> [u8; 32] {
    let header = |name: &str| headers.get(name).map_or(&[][..], HeaderValue::as_bytes);
    let params =
        oneiron::receipt::call_json_digest(request.params.as_ref().unwrap_or(&Value::Null));
    facade::invocation_body(
        None,
        locality,
        &[
            b"mcp".as_slice(),
            mode.as_str().as_bytes(),
            header(MCP_CREDENTIAL_HEADER),
            header(AUTHORIZATION.as_str()),
            owner.as_bytes(),
            header(crate::api::write_facet::SESSION_HEADER),
            request.method.as_bytes(),
            params.as_bytes(),
            raw_arguments.unwrap_or_default().as_bytes(),
        ],
    )
}
