//! The one connection `oneiron mcp` holds to its server (ARCH-0044 "anything
//! that loops holds a socket"; owner, 10-17).
//!
//! By default it is the app-tier socket: one `/ws` upgrade naming the MCP
//! subprotocol, then every message rides it as one app RPC, the wake poll's
//! included. A server that does not select that subprotocol, or refuses the
//! upgrade, has no MCP carrier, and the bridge holds one pooled HTTP client
//! instead for the rest of its life; so does `--transport http`.
//!
//! Neither changes what a request is. Each still carries the slip and a holder
//! proof signed for it alone, which the server's binding door verifies and
//! spends; each still runs through the server's `/mcp` or `/mcp/tool-first`
//! route, invocation claims and their replay included; and each still ends by
//! its own deadline, idle limit and byte limit, whatever else the connection
//! carries. A revoked slip is refused on its next request, and the server
//! drops a socket whose slip it finds revoked.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::timeout_at;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};

use crate::cli::{McpSurface, McpTransport};

/// How long opening the socket may take, inside the request's own deadline.
/// A server that cannot be reached in this time gets this request over HTTP,
/// and the next request tries the socket again.
const SOCKET_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How often an otherwise quiet socket is pinged, and how long it may stay
/// silent with nothing in flight before the bridge drops it and opens a fresh
/// one for the next request.
const SOCKET_PING_INTERVAL: Duration = Duration::from_secs(10);
const SOCKET_SILENCE_LIMIT: Duration = Duration::from_secs(25);

/// The largest frame the socket takes from the server: answers come in
/// 64 KiB chunks, so this bounds memory per frame, not the answer.
const SOCKET_MAX_INBOUND_FRAME: usize = 1024 * 1024;

/// What the server sent back for one request.
pub(super) struct Exchange {
    /// The HTTP status, when there was one.
    pub(super) status: Option<u16>,
    pub(super) body: Vec<u8>,
}

/// Why a request ended without a whole answer.
pub(super) enum Cut {
    /// No answer at all: the server could not be reached, or the exchange broke.
    Failed(String),
    /// The deadline passed before the answer was whole.
    Deadline,
    /// The answer started, then stalled for the idle limit.
    Idle,
    /// The answer grew past the reply limit.
    TooLarge,
}

/// The bounds on one request.
pub(super) struct Bounds {
    /// When the whole exchange must be over, answer included.
    pub(super) until: Instant,
    /// How long an answer that has started arriving may send nothing more.
    pub(super) idle: Duration,
    /// The largest answer body kept.
    pub(super) max_reply_bytes: usize,
}

/// The credential every request carries: the slip, and a signer that makes a
/// fresh holder proof for one request each time it is called.
pub(super) struct Credential<'a> {
    pub(super) bearer: &'a str,
    pub(super) sign: &'a dyn Fn() -> Result<String, String>,
}

/// The bridge's connection: the socket while the server offers it, else one
/// pooled HTTP client.
pub(super) struct Link {
    base: String,
    http: HttpLink,
    socket: Option<SocketLink>,
}

impl Link {
    pub(super) fn new(base: &str, transport: McpTransport) -> anyhow::Result<Self> {
        let runtime = Handle::try_current()?;
        let socket = match transport {
            McpTransport::Socket => Some(SocketLink::new(base, runtime.clone())?),
            McpTransport::Http => None,
        };
        Ok(Self {
            base: base.to_owned(),
            http: HttpLink::new(runtime)?,
            socket,
        })
    }

    /// The URL a request to `surface` names, for messages.
    pub(super) fn endpoint(&self, surface: McpSurface) -> String {
        format!("{}{}", self.base, surface.path())
    }

    /// One MCP message to `surface`, signed for this request alone, ending
    /// within `bounds`. Called from a plain thread, never from a runtime task.
    pub(super) fn exchange(
        &self,
        surface: McpSurface,
        credential: &Credential<'_>,
        body: Vec<u8>,
        bounds: &Bounds,
    ) -> Result<Exchange, Cut> {
        if let Some(socket) = &self.socket {
            match socket.exchange(surface, credential, &body, bounds) {
                Ok(exchange) => return Ok(exchange),
                Err(Carried::Cut(cut)) => return Err(cut),
                // Nothing reached the server: this request goes over HTTP.
                Err(Carried::Unsent) => {}
            }
        }
        let binding = (credential.sign)().map_err(Cut::Failed)?;
        self.http.post(
            &self.endpoint(surface),
            credential.bearer,
            &binding,
            body,
            bounds,
        )
    }
}

/// One pooled HTTP client for the bridge's life. Its connections stay open
/// between requests, so a remote vault costs one handshake, not one a call.
struct HttpLink {
    client: reqwest::Client,
    runtime: Handle,
}

impl HttpLink {
    fn new(runtime: Handle) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            // As `oneiron api`'s curl is told `--noproxy *`: a proxy the
            // environment names would be handed the bearer and its fresh proof.
            .no_proxy()
            // Nor does a redirect carry them to another origin; curl was given
            // no `--location`.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { client, runtime })
    }

    fn post(
        &self,
        url: &str,
        bearer: &str,
        binding: &str,
        body: Vec<u8>,
        bounds: &Bounds,
    ) -> Result<Exchange, Cut> {
        let request = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header("x-oneiron-binding", binding)
            .body(body);
        self.runtime.block_on(async move {
            let deadline = tokio::time::Instant::from_std(bounds.until);
            let mut response = match timeout_at(deadline, request.send()).await {
                Err(_) => return Err(Cut::Deadline),
                Ok(Err(error)) => {
                    return Err(Cut::Failed(format!("could not reach {url}: {error}")));
                }
                Ok(Ok(response)) => response,
            };
            let status = response.status().as_u16();
            if response.content_length().is_some_and(|length| {
                length > u64::try_from(bounds.max_reply_bytes).unwrap_or(u64::MAX)
            }) {
                return Err(Cut::TooLarge);
            }
            let mut body = Vec::new();
            loop {
                let stalls_at = tokio::time::Instant::now() + bounds.idle;
                match timeout_at(stalls_at.min(deadline), response.chunk()).await {
                    Err(_) if stalls_at < deadline => return Err(Cut::Idle),
                    Err(_) => return Err(Cut::Deadline),
                    Ok(Err(error)) => {
                        return Err(Cut::Failed(format!("{url}'s answer broke off: {error}")));
                    }
                    Ok(Ok(None)) => break,
                    Ok(Ok(Some(chunk))) => {
                        body.extend_from_slice(&chunk);
                        if body.len() > bounds.max_reply_bytes {
                            return Err(Cut::TooLarge);
                        }
                    }
                }
            }
            Ok(Exchange {
                status: Some(status),
                body,
            })
        })
    }
}

/// How a request the socket was asked to carry ended without an answer.
enum Carried {
    /// It never reached the socket, so another carrier may send it.
    Unsent,
    /// It was handed to the socket, so it may have run: it is not sent again.
    Cut(Cut),
}

/// The socket, opened on first use and again after it drops.
struct SocketLink {
    url: String,
    runtime: Handle,
    state: Mutex<SocketState>,
    /// Signalled when an open ends.
    opened: Condvar,
    next_id: AtomicU64,
}

#[derive(Default)]
struct SocketState {
    session: Option<Arc<Session>>,
    /// An open is under way.
    opening: bool,
    /// The server has no MCP carrier: every request goes over HTTP.
    declined: bool,
}

/// One open socket: requests reach its driver through here.
struct Session {
    outbound: mpsc::UnboundedSender<Outbound>,
}

/// One request handed to the driver, and where its answer's chunks go.
struct Outbound {
    id: u64,
    frame: Vec<u8>,
    chunks: mpsc::UnboundedSender<Inbound>,
}

/// What the driver tells one waiting request.
enum Inbound {
    Chunk {
        bytes: Vec<u8>,
        last: bool,
    },
    /// The socket ended after the request was handed over.
    Closed(String),
    /// The socket ended before the request was written.
    Unsent,
}

/// How an open ended.
enum Opened {
    Session(Arc<Session>),
    /// The server has no MCP carrier.
    Declined(String),
    /// It could not be opened this time.
    Failed,
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

impl SocketLink {
    fn new(base: &str, runtime: Handle) -> anyhow::Result<Self> {
        let url = match base.split_once("://") {
            Some(("https", rest)) => format!("wss://{rest}/ws"),
            Some(("http", rest)) => format!("ws://{rest}/ws"),
            _ => anyhow::bail!("base URL must be an http(s) origin: {base:?}"),
        };
        Ok(Self {
            url,
            runtime,
            state: Mutex::new(SocketState::default()),
            opened: Condvar::new(),
            next_id: AtomicU64::new(1),
        })
    }

    fn exchange(
        &self,
        surface: McpSurface,
        credential: &Credential<'_>,
        body: &[u8],
        bounds: &Bounds,
    ) -> Result<Exchange, Carried> {
        let Ok(body) = std::str::from_utf8(body) else {
            return Err(Carried::Unsent);
        };
        let Some(session) = self.session(credential, bounds.until) else {
            return Err(Carried::Unsent);
        };
        let binding = (credential.sign)().map_err(|error| Carried::Cut(Cut::Failed(error)))?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = request_frame(id, surface, &binding, body).map_err(Carried::Cut)?;
        let (chunks, mut answer) = mpsc::unbounded_channel();
        if session
            .outbound
            .send(Outbound { id, frame, chunks })
            .is_err()
        {
            return Err(Carried::Unsent);
        }
        self.runtime.block_on(async move {
            let deadline = tokio::time::Instant::from_std(bounds.until);
            let mut stalls_at: Option<tokio::time::Instant> = None;
            let mut packed = Vec::new();
            loop {
                let until = stalls_at.map_or(deadline, |stalls_at| stalls_at.min(deadline));
                match timeout_at(until, answer.recv()).await {
                    Err(_) if stalls_at.is_some_and(|stalls_at| stalls_at < deadline) => {
                        return Err(Carried::Cut(Cut::Idle));
                    }
                    Err(_) => return Err(Carried::Cut(Cut::Deadline)),
                    Ok(Some(Inbound::Unsent)) => return Err(Carried::Unsent),
                    Ok(Some(Inbound::Closed(why))) => return Err(Carried::Cut(Cut::Failed(why))),
                    Ok(None) => {
                        return Err(Carried::Cut(Cut::Failed(
                            "the MCP socket closed before the answer was whole".to_owned(),
                        )));
                    }
                    Ok(Some(Inbound::Chunk { bytes, last })) => {
                        packed.extend_from_slice(&bytes);
                        // The answer is packed with its status around it.
                        if packed.len() > bounds.max_reply_bytes.saturating_add(64) {
                            return Err(Carried::Cut(Cut::TooLarge));
                        }
                        if last {
                            break;
                        }
                        stalls_at = Some(tokio::time::Instant::now() + bounds.idle);
                    }
                }
            }
            let answer: SocketAnswer = rmp_serde::from_slice(&packed).map_err(|_| {
                Carried::Cut(Cut::Failed(
                    "the MCP socket's answer did not decode".to_owned(),
                ))
            })?;
            if answer.body.len() > bounds.max_reply_bytes {
                return Err(Carried::Cut(Cut::TooLarge));
            }
            Ok(Exchange {
                status: Some(answer.status),
                body: answer.body.into_bytes(),
            })
        })
    }

    /// The open socket, opening one when there is none. `None` sends this
    /// request over HTTP: the server has no MCP carrier, or the socket could
    /// not be opened by `until`. Requests that arrive during an open wait for
    /// it, each no longer than its own deadline.
    fn session(&self, credential: &Credential<'_>, until: Instant) -> Option<Arc<Session>> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if state.declined {
                return None;
            }
            if let Some(session) = &state.session
                && !session.outbound.is_closed()
            {
                return Some(Arc::clone(session));
            }
            if !state.opening {
                break;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            state = self
                .opened
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        state.opening = true;
        state.session = None;
        // No lock is held while the socket opens.
        drop(state);
        let opened = self.open(credential, until);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.opening = false;
        let session = match opened {
            Opened::Session(session) => {
                state.session = Some(Arc::clone(&session));
                Some(session)
            }
            Opened::Declined(why) => {
                state.declined = true;
                eprintln!("oneiron mcp: {why}; holding one pooled HTTP connection instead");
                None
            }
            Opened::Failed => None,
        };
        self.opened.notify_all();
        session
    }

    /// One upgrade, signed with its own fresh proof, then the protocol hello.
    fn open(&self, credential: &Credential<'_>, until: Instant) -> Opened {
        let Ok(binding) = (credential.sign)() else {
            return Opened::Failed;
        };
        let Ok(mut request) = self.url.as_str().into_client_request() else {
            return Opened::Failed;
        };
        let headers = request.headers_mut();
        for (name, value) in [
            ("authorization", format!("Bearer {}", credential.bearer)),
            ("x-oneiron-binding", binding),
            (
                "sec-websocket-protocol",
                crate::handler::MCP_SUBPROTOCOL.to_owned(),
            ),
        ] {
            let Ok(value) = value.parse() else {
                return Opened::Failed;
            };
            headers.insert(name, value);
        }
        let config = WebSocketConfig::default()
            .max_frame_size(Some(SOCKET_MAX_INBOUND_FRAME))
            .max_message_size(Some(SOCKET_MAX_INBOUND_FRAME));
        let runtime = self.runtime.clone();
        self.runtime.block_on(async move {
            let deadline = tokio::time::Instant::from_std(until)
                .min(tokio::time::Instant::now() + SOCKET_OPEN_TIMEOUT);
            let connect = tokio_tungstenite::connect_async_with_config(request, Some(config), true);
            let mut socket = match timeout_at(deadline, connect).await {
                Ok(Ok((socket, _))) => socket,
                Ok(Err(tungstenite::Error::Http(response)))
                    if response.status().is_client_error()
                        && !matches!(response.status().as_u16(), 408 | 429) =>
                {
                    return Opened::Declined(format!(
                        "the server refused the MCP socket (HTTP {})",
                        response.status().as_u16()
                    ));
                }
                Ok(Err(tungstenite::Error::Protocol(
                    tungstenite::error::ProtocolError::SecWebSocketSubProtocolError(_),
                ))) => {
                    return Opened::Declined("the server's socket carries no MCP".to_owned());
                }
                Ok(Err(_)) | Err(_) => return Opened::Failed,
            };
            let hello = oneiron::sync::transport::encode_protocol_hello();
            if socket.send(Message::Binary(hello.into())).await.is_err() {
                return Opened::Failed;
            }
            let (outbound, requests) = mpsc::unbounded_channel();
            runtime.spawn(drive(socket, requests));
            Opened::Session(Arc::new(Session { outbound }))
        })
    }
}

/// The socket's one owner: writes each request, hands each answer chunk to
/// the request it answers, and pings while quiet. When the socket ends, every
/// request still waiting hears why.
async fn drive(mut socket: Socket, mut requests: mpsc::UnboundedReceiver<Outbound>) {
    let mut waiting: HashMap<u64, mpsc::UnboundedSender<Inbound>> = HashMap::new();
    let mut ping = tokio::time::interval(SOCKET_PING_INTERVAL);
    let mut heard = tokio::time::Instant::now();
    let why = loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(request) = request else {
                    break "the bridge is ending".to_owned();
                };
                waiting.insert(request.id, request.chunks);
                if let Err(error) = socket.send(Message::Binary(request.frame.into())).await {
                    break format!("the MCP socket broke: {error}");
                }
            }
            frame = socket.next() => {
                heard = tokio::time::Instant::now();
                match frame {
                    Some(Ok(Message::Binary(data))) => {
                        if let Err(why) = route(&data, &mut waiting) {
                            break why;
                        }
                    }
                    Some(Ok(Message::Close(frame))) => {
                        break match frame {
                            Some(frame) => format!(
                                "the server closed the MCP socket ({}: {})",
                                u16::from(frame.code),
                                frame.reason.as_str()
                            ),
                            None => "the server closed the MCP socket".to_owned(),
                        };
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => break format!("the MCP socket broke: {error}"),
                    None => break "the server closed the MCP socket".to_owned(),
                }
            }
            _ = ping.tick() => {
                // A request that gave up no longer waits.
                waiting.retain(|_, chunks| !chunks.is_closed());
                // While calls run, the server may read nothing more until one
                // ends; each call keeps its own deadline meanwhile.
                if waiting.is_empty() && heard.elapsed() > SOCKET_SILENCE_LIMIT {
                    break "the server stopped answering on the MCP socket".to_owned();
                }
                if let Err(error) = socket.send(Message::Ping(Vec::new().into())).await {
                    break format!("the MCP socket broke: {error}");
                }
            }
        }
    };
    requests.close();
    for chunks in waiting.into_values() {
        let _ = chunks.send(Inbound::Closed(why.clone()));
    }
    while let Ok(request) = requests.try_recv() {
        let _ = request.chunks.send(Inbound::Unsent);
    }
    let _ = socket.close(None).await;
}

/// One frame from the server, to the request it answers.
fn route(
    data: &[u8],
    waiting: &mut HashMap<u64, mpsc::UnboundedSender<Inbound>>,
) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Envelope<P> {
        #[serde(rename = "type")]
        kind: String,
        id: u64,
        last: bool,
        payload: P,
    }
    fn decode<P: serde::de::DeserializeOwned>(envelope: &[u8]) -> Result<Envelope<P>, String> {
        rmp_serde::from_slice(envelope)
            .map_err(|_| "the server sent the MCP socket an undecodable frame".to_owned())
    }
    let Some((&oneiron::sync::transport::TAG_RPC, envelope)) = data.split_first() else {
        return Err("the server sent the MCP socket a frame that is not an app RPC".to_owned());
    };
    let head: Envelope<serde::de::IgnoredAny> = decode(envelope)?;
    match head.kind.as_str() {
        "rpc.res" => {
            let chunk: Envelope<serde_bytes::ByteBuf> = decode(envelope)?;
            if let Some(chunks) = waiting.get(&chunk.id) {
                let _ = chunks.send(Inbound::Chunk {
                    bytes: chunk.payload.into_vec(),
                    last: chunk.last,
                });
            }
            if chunk.last {
                waiting.remove(&chunk.id);
            }
        }
        "rpc.err" => {
            let refusal: Envelope<serde_json::Value> = decode(envelope)?;
            if let Some(chunks) = waiting.remove(&refusal.id) {
                let _ = chunks.send(Inbound::Closed(format!(
                    "the server refused the call on the MCP socket: {}",
                    refusal.payload
                )));
            }
        }
        // A ping's echo, or anything newer this bridge does not read.
        _ => {}
    }
    Ok(())
}

/// One request as an app RPC frame: the server's `mcp` method, carrying the
/// message as the client wrote it and this request's own proof.
fn request_frame(id: u64, surface: McpSurface, binding: &str, body: &str) -> Result<Vec<u8>, Cut> {
    #[derive(Serialize)]
    struct Request<'a> {
        #[serde(rename = "type")]
        kind: &'static str,
        id: u64,
        seq: u64,
        last: bool,
        payload: Rpc<'a>,
    }
    #[derive(Serialize)]
    struct Rpc<'a> {
        method: &'static str,
        params: Call<'a>,
    }
    #[derive(Serialize)]
    struct Call<'a> {
        surface: &'static str,
        binding: &'a str,
        body: &'a str,
    }
    let request = Request {
        kind: "rpc.req",
        id,
        seq: 0,
        last: true,
        payload: Rpc {
            method: crate::handler::MCP_RPC_METHOD,
            params: Call {
                surface: surface.path(),
                binding,
                body,
            },
        },
    };
    let mut frame = vec![oneiron::sync::transport::TAG_RPC];
    request
        .serialize(&mut rmp_serde::Serializer::new(&mut frame).with_struct_map())
        .map_err(|error| Cut::Failed(format!("could not frame the request: {error}")))?;
    Ok(frame)
}

/// The HTTP answer a socket call carries back.
#[derive(Deserialize)]
struct SocketAnswer {
    status: u16,
    body: String,
}
