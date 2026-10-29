//! MCP on the app-tier socket: `oneiron mcp` holds one `/ws` connection and
//! sends every JSON-RPC message over it, instead of a POST per message
//! (ARCH-0044 "anything that loops holds a socket"; owner, 10-17).
//!
//! The upgrade names [`MCP_SUBPROTOCOL`] and presents the agent's slip with a
//! holder proof, which the binding door consumes as for any request. On a
//! managed vault an upgrade with no slip that its supervisor attested as the
//! vault owner's own opens his own socket instead (FIX 5128). No root
//! snapshot, presence or sync frame flows on this socket, so no owner-grade
//! credential is asked for: it answers the protocol hello, pings and
//! [`MCP_RPC_METHOD`] calls, and closes on anything else.
//!
//! Each call carries the client's JSON-RPC message as it wrote it, which of
//! the two MCP endpoints it is for, and a fresh holder proof for the socket's
//! own slip. It runs through the very `/mcp` or `/mcp/tool-first` route a POST
//! does, binding door included: the proof is verified and its nonce spent,
//! the credential is resolved and checked live, and the invocation is claimed
//! or replayed exactly as over HTTP. The HTTP status and body come back as the
//! call's one result. The owner's call carries no proof: it names whose
//! socket it came on, never the attestation that signed only the upgrade, and
//! is his own call only while the vault records him as its live owner.
//!
//! On a managed vault each call is admitted under the reap freeze as the
//! `POST` it becomes, and a receipt the socket writes outside a call (a
//! ping's, a protocol refusal's) is admitted alone. While the vault is frozen
//! a call is answered with the served pause, and a ping with the same pause
//! and no receipt. An idle socket holds nothing a reap waits for (FIX 5128).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::http::{Extensions, HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use serde_json::json;
use tower::ServiceExt;

use super::protocol_close;
use super::socket_stop::StoppingTransport;
use super::transport::{GuardedTransport, WS_MAX_WRITE_BUFFER_SIZE, WS_WRITE_BUFFER_SIZE};
use crate::auth::{CoreAuth, RevokedTokenJtis};
use crate::managed::{ManagedCarrierContext, ManagedOwnerSession};
use crate::protocol::{TAG_RPC, close_codes};
use crate::server::SyncServer;

/// The subprotocol an upgrade names to open this carrier. A server that
/// selects it answers MCP here; one that does not has no MCP carrier.
pub(crate) const MCP_SUBPROTOCOL: &str = "oneiron.mcp.v1";

/// The app RPC method that carries one MCP message.
pub(crate) const MCP_RPC_METHOD: &str = "mcp";

/// How many MCP calls one socket runs at once: `oneiron mcp`'s own limit. The
/// loop reads no further frame while this many are in flight.
const MAX_MCP_CALLS_IN_FLIGHT: usize = 8;

/// The largest HTTP answer one call carries back: under the app tier's packed
/// result ceiling, and above the bridge's own reply limit, which judges it.
const MAX_ANSWER_BYTES: usize = 24 * 1024 * 1024;

/// The upgrade headers each call's request repeats, so the routes judge where
/// the caller sits and where it came from as they did for the upgrade.
const CARRIED_HEADERS: [header::HeaderName; 2] = [header::HOST, header::ORIGIN];
const CARRIED_FORWARDING_HEADERS: [&str; 4] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
];

/// The header an MCP connector names its credential in. Beside an owner's
/// attestation it is that connector's call on `/mcp`, so it never opens the
/// owner's own socket.
const MCP_CREDENTIAL_HEADER: &str = "x-oneiron-mcp-credential";

/// The upgrade headers the owner's own socket also repeats on each call:
/// the room turn and the session his supervisor's attestation placed the
/// upgrade in. Never the invocation it named, which was the upgrade's own.
const OWNER_PLACING_HEADERS: [&str; 2] = ["x-oneiron-room-turn", "x-oneiron-session"];

/// Whether this upgrade asks for the MCP carrier.
pub(super) fn requested(ws: &WebSocketUpgrade) -> bool {
    ws.requested_protocols()
        .any(|protocol| protocol.as_bytes() == MCP_SUBPROTOCOL.as_bytes())
}

/// One call's params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpCall {
    /// `/mcp` or `/mcp/tool-first`.
    surface: String,
    /// The holder proof for this call, as the `x-oneiron-binding` header holds it.
    binding: String,
    /// The JSON-RPC message, byte for byte as the client wrote it.
    body: String,
}

/// One call's params on the owner's own socket (FIX 5128): the endpoint and
/// the message, as for [`McpCall`], and no holder proof, since no slip
/// stands behind him.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpOwnerCall {
    /// `/mcp` or `/mcp/tool-first`.
    surface: String,
    /// The JSON-RPC message, byte for byte as the client wrote it.
    body: String,
}

/// One call, as its socket's caller sends it.
enum Call {
    Slip(McpCall),
    Owner(McpOwnerCall),
}

impl Call {
    fn surface(&self) -> &str {
        match self {
            Self::Slip(call) => &call.surface,
            Self::Owner(call) => &call.surface,
        }
    }
}

/// Whom a socket's calls run as.
enum Credential {
    /// The slip its upgrade presented, and that slip as its upgrade
    /// verified it: each call names a fresh holder proof for it, and
    /// carries the verified slip for a deferred clock repair (FIX 11525).
    Slip {
        bearer: HeaderValue,
        verified: Option<oneiron::authority::VerifiedSlip>,
    },
    /// A managed vault's owner, whose upgrade his supervisor attested (FIX
    /// 5128).
    Owner(ManagedOwnerSession),
}

/// What every call's request carries from the upgrade: its credential, the
/// headers the routes read the caller's position from, its peer, and on a
/// managed vault the reap admission each call takes.
struct Caller {
    credential: Credential,
    headers: HeaderMap,
    tcp_peer: Option<ConnectInfo<SocketAddr>>,
    local_peer: Option<ConnectInfo<crate::managed::UnixPeer>>,
    managed: Option<ManagedCarrierContext>,
}

impl Caller {
    /// One `mcp` call's params, read as this socket's caller sends them.
    fn call(&self, params: serde_json::Value) -> Option<Call> {
        match self.credential {
            Credential::Slip { .. } => serde_json::from_value(params).ok().map(Call::Slip),
            Credential::Owner(_) => serde_json::from_value(params).ok().map(Call::Owner),
        }
    }

    fn request(&self, call: Call) -> Option<Request<Body>> {
        let (surface, body, binding) = match call {
            Call::Slip(call) => (call.surface, call.body, Some(call.binding)),
            Call::Owner(call) => (call.surface, call.body, None),
        };
        let mut request = Request::post(surface).body(Body::from(body)).ok()?;
        let headers = request.headers_mut();
        headers.extend(self.headers.clone());
        if let Credential::Slip { bearer, .. } = &self.credential {
            headers.insert(header::AUTHORIZATION, bearer.clone());
        }
        if let Some(binding) = binding {
            headers.insert("x-oneiron-binding", HeaderValue::from_str(&binding).ok()?);
        }
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let extensions = request.extensions_mut();
        if let Some(peer) = self.tcp_peer {
            extensions.insert(peer);
        }
        if let Some(peer) = self.local_peer.clone() {
            extensions.insert(peer);
        }
        // Whose socket it came on, never the attestation of the upgrade.
        if let Credential::Owner(session) = &self.credential {
            extensions.insert(*session);
        }
        // The slip a slip socket's upgrade verified (FIX 11525): a
        // deferred clock repair runs as it, judged in the repair's writer.
        if let Credential::Slip { verified: Some(verified), .. } = &self.credential {
            extensions.insert(crate::api::clock_ingress::McpSocketSlip::of(verified.clone()));
        }
        if let Some(managed) = &self.managed {
            managed.carry(&mut request);
        }
        Some(request)
    }
}

/// The two MCP routes, behind the same binding door and telemetry the API
/// mounts them behind.
fn mcp_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route(
            crate::cli::McpSurface::Primary.path(),
            post(crate::api::mcp_gateway),
        )
        .route(
            crate::cli::McpSurface::ToolFirst.path(),
            post(crate::api::mcp_tool_first_gateway),
        )
        .layer(axum::middleware::from_fn_with_state(
            server.clone(),
            crate::wire_telemetry::observe_http,
        ))
        .with_state(server.clone())
        .layer(axum::middleware::from_fn_with_state(
            server.clone(),
            crate::auth::admit_http_binding,
        ))
        .layer(axum::middleware::from_fn_with_state(
            server,
            crate::api::call_receipt::connection_receipt,
        ))
}

/// Opens the carrier for a slip the binding door just admitted, or, on a
/// managed vault, for the owner his supervisor attested on this upgrade with
/// no slip beside him (FIX 5128). Anything else is refused before the
/// upgrade: a slip that fails never falls back to the owner.
pub(super) fn upgrade(
    ws: WebSocketUpgrade,
    headers: &HeaderMap,
    extensions: &Extensions,
    server: Arc<SyncServer>,
) -> Result<Response, Response> {
    let unauthorized = || StatusCode::UNAUTHORIZED.into_response();
    // A managed vault admits each call under its reap freeze: an upgrade its
    // ingress handed no admission is refused, never served bare.
    let managed = if server.managed_issuer.is_some() {
        let context = extensions.get::<ManagedCarrierContext>().cloned();
        Some(context.ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())?)
    } else {
        None
    };
    let (credential, session_jti, owner) =
        match CoreAuth::for_attested_request(headers, extensions, "/ws", &server) {
            Some(Err(refused)) => return Err(refused.into_response()),
            // The owner, with no credential of anyone's beside him, as
            // `/mcp` takes him: his own socket, which stands while the vault
            // records him as its live owner.
            Some(Ok(auth))
                if !crate::auth::carries_caller_slip(headers)
                    && !headers.contains_key(MCP_CREDENTIAL_HEADER) =>
            {
                let session = ManagedOwnerSession::opened_by(&auth).ok_or_else(unauthorized)?;
                (Credential::Owner(session), None, Some(auth))
            }
            // A slip, beside an attestation of its own person or alone: the
            // slip's socket, as on any vault.
            Some(Ok(_)) | None => {
                let bearer = headers
                    .get(header::AUTHORIZATION)
                    .filter(|value| {
                        value
                            .to_str()
                            .is_ok_and(|value| value.trim_start().starts_with("Bearer v2.slip."))
                    })
                    .cloned()
                    .ok_or_else(unauthorized)?;
                let auth = CoreAuth::from_headers(headers, &server.config, server.vault().as_ref())
                    .map_err(|_| unauthorized())?;
                // The slip as its upgrade verified it (FIX 11525): every
                // call's request carries it for a deferred clock repair.
                // The upgrade is admitted as before whether or not it has one.
                let verified = auth.verified_slip().cloned();
                (
                    Credential::Slip { bearer, verified },
                    auth.jti().map(str::to_owned),
                    None,
                )
            }
        };
    let mut carried = HeaderMap::new();
    for name in CARRIED_HEADERS {
        if let Some(value) = headers.get(&name) {
            carried.insert(name, value.clone());
        }
    }
    for name in CARRIED_FORWARDING_HEADERS {
        if let Some(value) = headers.get(name) {
            carried.insert(name, value.clone());
        }
    }
    if owner.is_some() {
        for name in OWNER_PLACING_HEADERS {
            if let Some(value) = headers.get(name) {
                carried.insert(name, value.clone());
            }
        }
    }
    let caller = Caller {
        credential,
        headers: carried,
        tcp_peer: extensions.get::<ConnectInfo<SocketAddr>>().copied(),
        local_peer: extensions
            .get::<ConnectInfo<crate::managed::UnixPeer>>()
            .cloned(),
        managed,
    };
    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new MCP socket");
    // FIX 811: the socket's unattributed replies name the connection its
    // upgrade arrived on.
    let connection = crate::api::call_receipt::connection_id();
    // OF-237: on a request carrying an upgrade lifetime (an embedded
    // channel or mesh, or plain/managed serve through `upgrade_lifetime`)
    // the whole carrier, hello and calls included, lives under the
    // server's stop, which it answers itself, and the stop waits for it
    // and every call it admitted from before the upgrade registers;
    // without one it runs as before.
    let hold = crate::embedded::UpgradeHold::take(extensions);
    Ok(ws
        .protocols([MCP_SUBPROTOCOL])
        .max_frame_size(server.config.max_frame_size)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
        .on_upgrade(move |socket| {
            crate::embedded::UpgradeHold::run(hold, move |stop| {
                crate::api::call_receipt::on_connection(
                    connection,
                    serve(socket, stop, server, conn_id, (session_jti, owner), caller),
                )
            })
        })
        .into_response())
}

/// The carrier's loop. Every frame it writes goes through the guarded
/// transport, which re-consults the socket credential's revocation first (the
/// owner's live ownership, for his own socket), and every read does too; each
/// call is admitted again on its own proof, or as the owner again. On the
/// engine's `stop` (OF-237) the loop stops reading at its next wait and the
/// transport closes; the carrier ends once every call it admitted has.
async fn serve(
    socket: WebSocket,
    mut stop: crate::embedded::UpgradeStop,
    server: Arc<SyncServer>,
    conn_id: u32,
    (session_jti, owner): (Option<String>, Option<CoreAuth>),
    caller: Caller,
) {
    let transport = GuardedTransport::new(
        socket,
        Arc::clone(server.vault()) as Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti,
        conn_id,
    )
    .with_inbound_cap(server.config.max_frame_size)
    .with_live_owner(server.vault(), owner);
    // Its hello and sends give way to the engine's stop.
    let mut transport = StoppingTransport::new(transport, stop.clone());
    // On a managed vault every receipt and call below is admitted under the
    // reap freeze, each on its own (FIX 5128).
    let managed = caller.managed.clone();
    let admission = managed.as_ref();
    // FIX 3303: each refusal below is its connection's receipt, then the close.
    match protocol_close::hello(&mut transport, &server, conn_id, admission).await {
        Some(version) if version >= oneiron::sync::transport::APP_TIER_PROTOCOL_VERSION_VERSION => {
        }
        Some(_) => {
            protocol_close::refuse_hello_version(
                &mut transport,
                &server,
                close_codes::CLOSE_RPC_VERSION_MISMATCH,
                "app tier needs protocol 8",
                admission,
            )
            .await;
            return;
        }
        None => return,
    }
    let routes = mcp_routes(Arc::clone(&server));
    // Each call is admitted as the `POST` it becomes, outside its receipt
    // and binding doors.
    let routes = match admission {
        Some(managed) => managed.admit_requests(routes),
        None => routes,
    };
    let caller = Arc::new(caller);
    let mut calls = tokio::task::JoinSet::new();
    'serving: loop {
        let event = tokio::select! {
            biased;
            () = stop.turned() => break,
            Some(answered) = calls.join_next(), if !calls.is_empty() => Event::Answered(answered),
            inbound = transport.read_next(), if calls.len() < MAX_MCP_CALLS_IN_FLIGHT => {
                Event::Inbound(inbound)
            }
        };
        let data = match event {
            Event::Answered(Ok(Ok(frames))) => {
                for frame in frames {
                    if !transport.send_binary(frame).await {
                        break 'serving;
                    }
                }
                continue;
            }
            Event::Answered(_) => {
                tracing::warn!(conn_id, "MCP call ended without an answer — closing");
                break;
            }
            Event::Inbound(Some(Ok(WsMessage::Binary(data)))) => data,
            Event::Inbound(Some(Ok(
                WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Text(_),
            ))) => {
                continue;
            }
            Event::Inbound(Some(Ok(WsMessage::Close(_)))) => break,
            // A frame the WebSocket codec refused is a refusal, not a
            // disconnect: receipted, then closed (FIX 5311).
            Event::Inbound(Some(Err(error))) => {
                protocol_close::close_read_error(&server, &mut transport, &error, admission).await;
                break;
            }
            // A frame the transport refused is a refusal, not a disconnect.
            Event::Inbound(None) => {
                protocol_close::close_read_refusal(&server, &mut transport, admission).await;
                break;
            }
        };
        if data.len() > server.config.max_frame_size {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::FRAME_TOO_LARGE,
                "frame too large",
                admission,
            )
            .await;
            break;
        }
        // Only app RPCs: no sync message is served on this socket.
        let Some((&TAG_RPC, payload)) = data.split_first() else {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::UNKNOWN_TAG,
                "this socket carries MCP calls only",
                admission,
            )
            .await;
            break;
        };
        let Ok(request) = crate::livequery::decode_rpc(payload) else {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::DECODE_ERROR,
                "invalid app envelope",
                admission,
            )
            .await;
            break;
        };
        if request.method == "ping" {
            // FIX 811: a ping is the connection's reply, echoing its params.
            let id = request.request_id;
            let reply = || {
                let digest = oneiron::receipt::call_json_digest(&request.params);
                let stamp = crate::api::call_receipt::record_socket_reply(
                    &server,
                    request.method,
                    oneiron::receipt::CallOutcome::Ok,
                    digest.clone(),
                    Some(digest),
                );
                crate::livequery::stamped_ping_result(id, request.params, &stamp)
                    .map(|frame| vec![frame])
            };
            // On a managed vault its receipt is admitted under the reap
            // freeze; while frozen it is answered with the pause, as a call
            // is, and records nothing.
            let frames = match admission {
                None => reply(),
                Some(managed) => managed.admit_receipt(reply).unwrap_or_else(|paused| {
                    let pause = json!({
                        "status": paused.status().as_u16(),
                        "body": paused.body().to_string(),
                    });
                    crate::livequery::rpc_result(id, pause)
                }),
            };
            let Ok(frames) = frames else {
                break;
            };
            for frame in frames {
                if !transport.send_binary(frame).await {
                    break 'serving;
                }
            }
            continue;
        }
        let surfaces = [
            crate::cli::McpSurface::Primary.path(),
            crate::cli::McpSurface::ToolFirst.path(),
        ];
        let call = (request.method == MCP_RPC_METHOD)
            .then(|| caller.call(request.params))
            .flatten()
            .filter(|call| surfaces.contains(&call.surface()));
        let Some(call) = call else {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::DECODE_ERROR,
                "expected an mcp call",
                admission,
            )
            .await;
            break;
        };
        let id = request.request_id;
        let routes = routes.clone();
        let caller = Arc::clone(&caller);
        calls.spawn(crate::api::call_receipt::on_connection(
            crate::api::call_receipt::connection_id(),
            async move { answer(id, call, &routes, &caller).await },
        ));
    }
    // OF-237: the carrier closes, then every call it admitted runs to its
    // end; none is aborted. Only after them does its place in an embedded
    // engine's drain go, so no worker stops under one.
    drop(transport);
    while calls.join_next().await.is_some() {}
}

/// What woke the carrier's loop.
enum Event {
    Answered(Result<Result<Vec<Vec<u8>>, crate::protocol::ProtocolError>, tokio::task::JoinError>),
    Inbound(Option<Result<WsMessage, axum::Error>>),
}

/// One call, through the MCP routes, as its result frames.
async fn answer(
    id: u64,
    call: Call,
    routes: &Router,
    caller: &Caller,
) -> Result<Vec<Vec<u8>>, crate::protocol::ProtocolError> {
    let (status, body) = match caller.request(call) {
        // A proof no header can hold is no proof: the door's own refusal.
        None => (
            StatusCode::UNAUTHORIZED,
            json!({ "error": "the call's holder proof is not a header value" }).to_string(),
        ),
        Some(request) => {
            let response = match routes.clone().oneshot(request).await {
                Ok(response) => response,
                Err(never) => match never {},
            };
            let status = response.status();
            match axum::body::to_bytes(response.into_body(), MAX_ANSWER_BYTES).await {
                Ok(bytes) => (status, String::from_utf8_lossy(&bytes).into_owned()),
                Err(_) => (
                    StatusCode::INSUFFICIENT_STORAGE,
                    json!({ "error": format!("the answer is over {MAX_ANSWER_BYTES} bytes") })
                        .to_string(),
                ),
            }
        }
    };
    crate::livequery::rpc_result(id, json!({ "status": status.as_u16(), "body": body }))
}
