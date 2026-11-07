//! The MCP gateway's Streamable HTTP side: its routes, its connection stamp and each POST's reply.
//! `mcp_gateway`, `mcp_tool_first_gateway` and `mcp_method_not_allowed` are its call surface.
//! The envelope root defines `McpCallContext` and `McpGatewayError`, the records forwarded here.

use super::*;
use axum::http::StatusCode;
use axum::http::header::{ALLOW, ORIGIN};

/// The header a POST after `initialize` names its MCP protocol version in.
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// The methods an MCP endpoint serves, as its 405's `Allow` header states
/// them.
const MCP_ALLOWED_METHODS: &str = "POST";

/// The HTTP status a notification or response this server cannot accept
/// answers with. The transport asks for an HTTP error status and names 400
/// as one; which one is an engine call (CALLS, FIX 4902).
const MCP_REFUSED_MESSAGE_STATUS: StatusCode = StatusCode::BAD_REQUEST;

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
    // the reply is encoded (FIX 8238). The endpoint's future lives on the
    // heap, so the route's handler future holds a pointer through every
    // layer, not the whole dispatch (FIX 12072).
    crate::api::answer_hold::until_encoded(Box::pin(mcp_endpoint(
        McpSurfaceMode::Primary,
        headers,
        locality,
        connection,
        server,
        body,
    )))
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
    // the reply is encoded (FIX 8238); the endpoint's future on the heap
    // (FIX 12072).
    crate::api::answer_hold::until_encoded(Box::pin(mcp_endpoint(
        McpSurfaceMode::ToolFirst,
        headers,
        locality,
        connection,
        server,
        body,
    )))
    .await
}

/// `GET` and `DELETE` on an MCP endpoint: 405 Method Not Allowed, with
/// `Allow: POST`. An engine call (CALLS, FIX 4902): this server opens no
/// server-initiated SSE stream, which the transport lets a GET answer 405
/// for, and holds no session (it mints no `Mcp-Session-Id`), so a DELETE
/// has none to end. A present `Origin` this server does not admit is
/// refused first, as on a POST.
pub(crate) async fn mcp_method_not_allowed(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Response {
    if let Some(refused) = mcp_origin_refusal(&server, &headers, &[]) {
        return refused;
    }
    let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
    response
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static(MCP_ALLOWED_METHODS));
    response
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

/// An envelope refused before any method ran, as its connection's reply,
/// under the HTTP status the transport answers it with.
fn mcp_status_refusal(
    status: StatusCode,
    server: &SyncServer,
    headers: &HeaderMap,
    method: &str,
    body: &[u8],
    id: Value,
    error: McpGatewayError,
) -> Response {
    let mut response = mcp_connection_refusal(server, headers, method, body, id, error);
    *response.status_mut() = status;
    response
}

/// The refusal of a request whose `Origin` this server does not admit (MCP
/// Streamable HTTP: a present, invalid `Origin` answers 403 Forbidden,
/// against DNS rebinding; canon ARCH-0028 "Origin-validated"). An engine
/// call (CALLS, FIX 4902): an origin is admitted when `allowed_origins`
/// names it exactly, when it is this host's own public origin
/// (`oauth_resource_indicator`), or when its host is a loopback name or
/// address, which a rebinding page never carries. A request with no
/// `Origin`, as every client outside a browser sends, is not judged.
fn mcp_origin_refusal(server: &SyncServer, headers: &HeaderMap, body: &[u8]) -> Option<Response> {
    let origin = headers.get(ORIGIN)?;
    let listed = crate::web_client::parse_allowed_origins(&server.config.allowed_origins)
        .is_ok_and(|allowed| allowed.contains(origin));
    let own = crate::builtin_host::public_origin(server.config.oauth_resource_indicator.as_deref())
        .is_some_and(|own| origin.as_bytes() == own.as_bytes());
    if listed || own || origin.to_str().is_ok_and(loopback_origin) {
        return None;
    }
    let error = McpGatewayError::new(
        -32600,
        "origin_not_allowed",
        format!(
            "Origin {} is not one this server admits",
            String::from_utf8_lossy(origin.as_bytes())
        ),
    )
    .with_field("Origin");
    Some(mcp_status_refusal(
        StatusCode::FORBIDDEN,
        server,
        headers,
        "mcp",
        body,
        Value::Null,
        error,
    ))
}

/// Whether `origin` (`scheme://host[:port]`) names a loopback host:
/// `localhost`, `127.0.0.1` or `[::1]`.
fn loopback_origin(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https") {
        return false;
    }
    let host = match rest.strip_prefix('[') {
        Some(bracketed) => bracketed.split_once(']').map(|(host, _)| host),
        None => Some(rest.split(':').next().unwrap_or(rest)),
    };
    host.is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
    })
}

/// The refusal of a POST whose `MCP-Protocol-Version` header names a
/// version this server does not speak, which the transport answers with
/// 400. `None` when it names one of [`MCP_PROTOCOL_VERSIONS`], or names
/// none: the transport then assumes `2025-03-26`, which this server serves
/// as it serves every version it speaks.
fn mcp_protocol_header_refusal(headers: &HeaderMap) -> Option<McpGatewayError> {
    let named = headers.get(MCP_PROTOCOL_VERSION_HEADER)?;
    if named
        .to_str()
        .is_ok_and(|version| MCP_PROTOCOL_VERSIONS.contains(&version))
    {
        return None;
    }
    Some(
        McpGatewayError::new(
            -32600,
            "unsupported_protocol_version",
            format!(
                "MCP-Protocol-Version {} is not one this server speaks; it speaks {}",
                String::from_utf8_lossy(named.as_bytes()),
                MCP_PROTOCOL_VERSIONS.join(", ")
            ),
        )
        .with_field("MCP-Protocol-Version"),
    )
}

/// What MCP Streamable HTTP answers for a POSTed message before any request
/// runs: a version header this server does not speak is refused with 400
/// (`initialize` is not judged by it), and a notification or a response is
/// accepted with 202 or refused with an HTTP error status, never answered as
/// a request is. `None` for a request, which is answered as before.
async fn mcp_transport_answer(
    mode: McpSurfaceMode,
    headers: &HeaderMap,
    locality: CallerLocality,
    connection: &Extensions,
    server: &Arc<SyncServer>,
    body: &[u8],
    raw: &Value,
) -> Option<Response> {
    let method = raw.get("method").and_then(Value::as_str);
    if method != Some("initialize")
        && let Some(error) = mcp_protocol_header_refusal(headers)
    {
        return Some(mcp_status_refusal(
            StatusCode::BAD_REQUEST,
            server,
            headers,
            method.unwrap_or("mcp"),
            body,
            raw.get("id").cloned().unwrap_or(Value::Null),
            error,
        ));
    }
    if !mcp_is_notification_or_response(raw) {
        return None;
    }
    Some(mcp_accept_message(mode, headers, locality, connection, server, body, raw).await)
}

/// Whether a POSTed body is a JSON-RPC notification (a `method` and no `id`
/// member) or a response (an `id`, a `result` or an `error`, and no
/// `method`). Neither is answered as a request is. A request, a batch and
/// any other body are not.
fn mcp_is_notification_or_response(raw: &Value) -> bool {
    let Some(message) = raw.as_object() else {
        return false;
    };
    match message.get("method") {
        Some(Value::String(_)) => !message.contains_key("id"),
        Some(_) => false,
        None => {
            message.contains_key("id")
                && (message.contains_key("result") || message.contains_key("error"))
        }
    }
}

/// Whether this server accepts a notification of `method`. An engine call
/// (CALLS, FIX 4902): every `notifications/*` is accepted and ignored,
/// `initialized`, `cancelled`, `progress` and `roots/list_changed` among
/// them, since the endpoint holds no session, cancels no call it is
/// running, and asks for no roots. A message with no `id` that names any
/// other method is a request no reply can answer, so it is refused.
fn mcp_notification_accepted(method: &str) -> bool {
    method.starts_with("notifications/")
}

/// One POSTed notification or response (MCP Streamable HTTP): accepted, it
/// answers 202 Accepted with no body, under its connection's receipt; else
/// [`MCP_REFUSED_MESSAGE_STATUS`] with the JSON-RPC error and no id. Its
/// caller is required, as for every method, and is resolved as a
/// handshake's is.
async fn mcp_accept_message(
    mode: McpSurfaceMode,
    headers: &HeaderMap,
    locality: CallerLocality,
    connection: &Extensions,
    server: &Arc<SyncServer>,
    body: &[u8],
    raw: &Value,
) -> Response {
    let method = raw.get("method").and_then(Value::as_str);
    let label = method.unwrap_or("mcp");
    let refusal = if raw.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        Some(
            McpGatewayError::new(-32600, "invalid_request", "jsonrpc must be \"2.0\"")
                .with_field("jsonrpc"),
        )
    } else if let Some(method) = method
        && !mcp_notification_accepted(method)
    {
        Some(
            McpGatewayError::new(
                -32600,
                "invalid_request",
                format!(
                    "{method} is a request and needs an id; only a notifications/* method omits one"
                ),
            )
            .with_field("id"),
        )
    } else {
        None
    };
    let caller = match refusal {
        Some(error) => Err(error),
        None => resolve_handshake_caller(
            mode,
            &mcp_request_id(&Value::Null),
            headers,
            connection,
            locality,
            server,
        )
        .await
        .map(drop),
    };
    if let Err(error) = caller {
        return mcp_status_refusal(
            MCP_REFUSED_MESSAGE_STATUS,
            server,
            headers,
            label,
            body,
            Value::Null,
            error,
        );
    }
    let anonymous = crate::api::call_receipt::in_anonymous_session(server, headers, None);
    let stamp = crate::api::call_receipt::record(
        server,
        anonymous,
        crate::api::call_receipt::connection_call(
            oneiron::receipt::CallTransport::Mcp,
            label.to_owned(),
            oneiron::receipt::CallOutcome::Ok,
            oneiron::receipt::call_bytes_digest(body),
            None,
        ),
    );
    let mut response = StatusCode::ACCEPTED.into_response();
    stamp.stamp_header(&mut response);
    response
}

pub(super) async fn mcp_endpoint(
    mode: McpSurfaceMode,
    headers: HeaderMap,
    locality: CallerLocality,
    connection: Extensions,
    server: Arc<SyncServer>,
    body: Bytes,
) -> Response {
    // A present Origin this server does not admit is refused before the
    // body is read (FIX 4902).
    if let Some(refused) = mcp_origin_refusal(&server, &headers, &body) {
        return refused;
    }
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
    // The version header and a notification or response are answered
    // before any request runs (FIX 4902); that answer's future on the heap
    // (FIX 12072).
    if let Some(answered) = Box::pin(mcp_transport_answer(
        mode,
        &headers,
        locality,
        &connection,
        &server,
        &body,
        &raw,
    ))
    .await
    {
        return answered;
    }
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
            match facade::claim_door_invocation(
                &server,
                invocation,
                call,
                oneiron::EntityId::from_hex(&owner).ok(),
            )
            .await
            {
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
                DoorClaim::ReplyNotKept { committed_writes } => {
                    return mcp_connection_refusal(
                        &server,
                        &headers,
                        &request.method,
                        &body,
                        id,
                        McpGatewayError::new(
                            -32020,
                            crate::idempotency::REPLY_NOT_KEPT_STATE,
                            format!(
                                "the first request with this invocation committed {committed_writes} write(s) while it ran; its reply was not kept"
                            ),
                        ),
                    );
                }
                DoorClaim::Erased => {
                    return mcp_connection_refusal(
                        &server,
                        &headers,
                        &request.method,
                        &body,
                        id,
                        McpGatewayError::new(
                            -32020,
                            facade::INVOCATION_RESPONSE_ERASED,
                            "the first response with this invocation was erased",
                        ),
                    );
                }
                DoorClaim::StoreFailed => {
                    return mcp_connection_refusal(
                        &server,
                        &headers,
                        &request.method,
                        &body,
                        id,
                        McpGatewayError::new(
                            -32603,
                            facade::INVOCATION_STORE_FAILED,
                            "the invocation claim could not be stored",
                        ),
                    );
                }
            }
        }
    };
    let method = request.method.clone();
    // The method dispatch, `tools/call` and every verb under it, on the heap
    // (FIX 12072).
    let call = Box::pin(handle_mcp_request(
        mode,
        &headers,
        locality,
        &connection,
        &server,
        request,
        raw_arguments.as_deref(),
    ));
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
    let failed = result.is_err();
    let reply = mcp_envelope(id, result);
    if let Some(claim) = claim {
        let mut saved = reply.clone();
        if let Some(saved) = saved.as_object_mut() {
            saved.remove("id");
        }
        let peer = crate::auth::proved_peer(&headers, &connection);
        let release = super::super::claimed_release::kept(peer, &saved, judged);
        let outcome = InvocationOutcome {
            status: 200,
            body: saved,
            release,
        };
        if failed {
            claim.finish_failed(outcome);
        } else {
            claim.finish(outcome);
        }
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
