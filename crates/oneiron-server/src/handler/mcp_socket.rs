//! MCP on the app-tier socket: `oneiron mcp` holds one `/ws` connection and
//! sends every JSON-RPC message over it, instead of a POST per message
//! (ARCH-0044 "anything that loops holds a socket"; owner, 10-17).
//!
//! The upgrade names [`MCP_SUBPROTOCOL`] and presents the agent's slip with a
//! holder proof, which the binding door consumes as for any request. No root
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
//! call's one result.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{Extensions, HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use serde_json::json;
use tower::ServiceExt;

use super::hello::{HelloOutcome, await_protocol_hello};
use super::transport::{GuardedTransport, WS_MAX_WRITE_BUFFER_SIZE, WS_WRITE_BUFFER_SIZE};
use crate::auth::{CoreAuth, RevokedTokenJtis};
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

/// What every call's request carries from the upgrade: the slip, the headers
/// the routes read the caller's position from, and its peer.
struct Caller {
    bearer: HeaderValue,
    headers: HeaderMap,
    tcp_peer: Option<ConnectInfo<SocketAddr>>,
    local_peer: Option<ConnectInfo<crate::managed::UnixPeer>>,
}

impl Caller {
    fn request(&self, call: McpCall) -> Option<Request<Body>> {
        let mut request = Request::post(call.surface)
            .body(Body::from(call.body))
            .ok()?;
        let headers = request.headers_mut();
        headers.extend(self.headers.clone());
        headers.insert(header::AUTHORIZATION, self.bearer.clone());
        headers.insert(
            "x-oneiron-binding",
            HeaderValue::from_str(&call.binding).ok()?,
        );
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
            server,
            crate::auth::admit_http_binding,
        ))
}

/// Opens the carrier for a slip the binding door just admitted. Anything but
/// a holder-bound slip is refused before the upgrade.
pub(super) fn upgrade(
    ws: WebSocketUpgrade,
    headers: &HeaderMap,
    extensions: &Extensions,
    server: Arc<SyncServer>,
) -> Result<Response, StatusCode> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .filter(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.trim_start().starts_with("Bearer v2.slip."))
        })
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let auth = CoreAuth::from_headers(headers, &server.config, server.vault().as_ref())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session_jti = auth.jti().map(str::to_owned);
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
    let caller = Caller {
        bearer,
        headers: carried,
        tcp_peer: extensions.get::<ConnectInfo<SocketAddr>>().copied(),
        local_peer: extensions
            .get::<ConnectInfo<crate::managed::UnixPeer>>()
            .cloned(),
    };
    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new MCP socket");
    Ok(ws
        .protocols([MCP_SUBPROTOCOL])
        .max_frame_size(server.config.max_frame_size)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
        .on_upgrade(move |socket| serve(socket, server, conn_id, session_jti, caller))
        .into_response())
}

/// The carrier's loop. Every frame it writes goes through the guarded
/// transport, which re-consults the socket credential's revocation first, and
/// every read does too; each call is admitted again on its own proof.
async fn serve(
    socket: WebSocket,
    server: Arc<SyncServer>,
    conn_id: u32,
    session_jti: Option<String>,
    caller: Caller,
) {
    let mut transport = GuardedTransport::new(
        socket,
        Arc::clone(server.vault()) as Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti,
        conn_id,
    );
    match await_protocol_hello(&mut transport).await {
        HelloOutcome::Valid(version)
            if version >= oneiron::sync::transport::APP_TIER_PROTOCOL_VERSION_VERSION => {}
        HelloOutcome::Valid(_) => {
            close(
                &mut transport,
                close_codes::CLOSE_RPC_VERSION_MISMATCH,
                "app tier needs protocol 8",
            )
            .await;
            return;
        }
        HelloOutcome::Reject(reason) => {
            close(&mut transport, close_codes::VERSION_MISMATCH, reason).await;
            return;
        }
        HelloOutcome::Disconnected => return,
    }
    let routes = mcp_routes(Arc::clone(&server));
    let caller = Arc::new(caller);
    let mut calls = tokio::task::JoinSet::new();
    loop {
        let event = tokio::select! {
            biased;
            Some(answered) = calls.join_next(), if !calls.is_empty() => Event::Answered(answered),
            inbound = transport.read_next(), if calls.len() < MAX_MCP_CALLS_IN_FLIGHT => {
                Event::Inbound(inbound)
            }
        };
        let data = match event {
            Event::Answered(Ok(Ok(frames))) => {
                for frame in frames {
                    if !transport.send_binary(frame).await {
                        return;
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
            Event::Inbound(Some(Ok(WsMessage::Close(_)) | Err(_)) | None) => break,
        };
        if data.len() > server.config.max_frame_size {
            close(
                &mut transport,
                close_codes::FRAME_TOO_LARGE,
                "frame too large",
            )
            .await;
            break;
        }
        // Only app RPCs: no sync message is served on this socket.
        let Some((&TAG_RPC, payload)) = data.split_first() else {
            close(
                &mut transport,
                close_codes::UNKNOWN_TAG,
                "this socket carries MCP calls only",
            )
            .await;
            break;
        };
        let Ok(request) = crate::livequery::decode_rpc(payload) else {
            close(
                &mut transport,
                close_codes::DECODE_ERROR,
                "invalid app envelope",
            )
            .await;
            break;
        };
        if request.method == "ping" {
            let Ok(frame) = crate::livequery::ping_result(request.request_id, request.params)
            else {
                break;
            };
            if !transport.send_binary(frame).await {
                break;
            }
            continue;
        }
        let surfaces = [
            crate::cli::McpSurface::Primary.path(),
            crate::cli::McpSurface::ToolFirst.path(),
        ];
        let call = (request.method == MCP_RPC_METHOD)
            .then(|| serde_json::from_value::<McpCall>(request.params).ok())
            .flatten()
            .filter(|call| surfaces.contains(&call.surface.as_str()));
        let Some(call) = call else {
            close(
                &mut transport,
                close_codes::DECODE_ERROR,
                "expected an mcp call",
            )
            .await;
            break;
        };
        let id = request.request_id;
        let routes = routes.clone();
        let caller = Arc::clone(&caller);
        calls.spawn(async move { answer(id, call, &routes, &caller).await });
    }
}

/// What woke the carrier's loop.
enum Event {
    Answered(Result<Result<Vec<Vec<u8>>, crate::protocol::ProtocolError>, tokio::task::JoinError>),
    Inbound(Option<Result<WsMessage, axum::Error>>),
}

/// One call, through the MCP routes, as its result frames.
async fn answer(
    id: u64,
    call: McpCall,
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

async fn close(transport: &mut GuardedTransport<WebSocket>, code: u16, reason: &'static str) {
    transport
        .send_unguarded_close_frame(WsMessage::Close(Some(CloseFrame {
            code,
            reason: Utf8Bytes::from_static(reason),
        })))
        .await;
}
