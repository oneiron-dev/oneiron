//! Responses over a held socket (ARCH-0081 §5). An OpenAI-compatible
//! provider that serves one runs each call as one response on a pooled
//! WebSocket, and sends only the items past the response that socket last
//! completed when the call's conversation extends it. A call whose socket
//! will not open goes over the chat HTTP path, whole, as before.
//!
//! With `store` on (OF-602), the provider keeps every response, so a
//! conversation's chain outlives its socket: a replaced or reconnected socket
//! takes it up and still sends only the new items.
//!
//! Each call is still one gated call: a socket open is no admission, and a
//! dropped call drops its socket, which ends the response on it.
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::{FutureExt, SinkExt, StreamExt};
use oneiron::llm::SingleRouteBackend;
use oneiron::{
    BudgetLease, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest, LlmResult, LlmStream,
    LlmStreamResult, ModelId,
};
use oneiron_llm_openai::{
    OpenAiCompatBackend, OpenAiCompatProviderStream, OpenAiCompatStreamFrame,
    OpenAiCompatTransportError, OpenAiResponsesChain, OpenAiResponsesLlmStream,
    OpenAiResponsesTurn, RESPONSES_PREVIOUS_NOT_FOUND, RESPONSES_SOCKET_LIMIT,
    build_openai_responses_turn, responses_can_carry, responses_error_code,
    responses_event_is_terminal, responses_event_type,
};
use serde_json::Value as JsonValue;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, header::AUTHORIZATION};
use tokio_tungstenite::tungstenite::{self, Message};

use super::openai::OpenAiHttp;
use super::output_cap::OutputCap;
use super::served::record_served_model;
use crate::config::models::{ProviderConfig, ResponseFormatWire};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// How long before its age limit a socket is retired, so no response is cut
/// at the limit.
const RETIRE_BEFORE_LIMIT: Duration = Duration::from_secs(300);
/// How long an idle socket waits for its conversation's next turn.
const IDLE_KEEP: Duration = Duration::from_secs(600);
/// The most idle sockets one provider keeps.
const IDLE_SOCKETS: usize = 8;
/// The most conversations whose stored chain one provider keeps, with
/// `store` on.
const STORED_CHAINS: usize = 32;

/// The owner's Responses `store` switch (OF-602), off by default: read from
/// the vault at start-up and set again when the owner changes it.
static STORE: AtomicBool = AtomicBool::new(false);

/// Sets whether each Responses turn from here on asks its provider to keep
/// the response.
pub(crate) fn set_responses_store(on: bool) {
    STORE.store(on, Ordering::Relaxed);
}

/// One socket and the chain of responses it holds.
struct Session {
    socket: Socket,
    opened: Instant,
    idle_since: Instant,
    chain: OpenAiResponsesChain,
}

impl Session {
    /// Reads what arrived while the socket sat idle: a ping is answered on
    /// that read, a close ends the socket. `false` when it is gone.
    fn drain(&mut self) -> bool {
        loop {
            match self.socket.next().now_or_never() {
                None => return true,
                Some(None | Some(Err(_) | Ok(Message::Close(_)))) => return false,
                Some(Some(Ok(_))) => {}
            }
        }
    }
}

/// One provider's Responses sockets.
pub(super) struct ResponsesSockets {
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    open_timeout: Duration,
    read_timeout: Duration,
    max_age: Duration,
    idle: Mutex<Vec<Session>>,
    /// Set when the origin refused the upgrade for good: every later call
    /// takes HTTP for this process's life.
    refused: AtomicBool,
    /// The last completed chain of each recent conversation sent with
    /// `store` on, newest last.
    stored: Mutex<VecDeque<OpenAiResponsesChain>>,
}

impl ResponsesSockets {
    /// The sockets for `provider`, at `url` (its `/v1/responses`, as the
    /// HTTP client joins it). A configured `key_env` that is unset is a
    /// refusal here, as it is for the HTTP client.
    pub(super) fn new(
        provider: &ProviderConfig,
        url: &str,
        max_age_secs: u64,
    ) -> anyhow::Result<Self> {
        let url = if let Some(rest) = url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            anyhow::bail!("a Responses socket needs an http or https base_url");
        };
        let mut headers = Vec::new();
        for (name, value) in &provider.headers {
            headers.push((
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            ));
        }
        if let Some(env) = &provider.key_env {
            let key = std::env::var(env)
                .ok()
                .filter(|key| !key.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("{env} is not set"))?;
            let mut value = HeaderValue::from_str(&format!("Bearer {key}"))
                .map_err(|_| anyhow::anyhow!("{env} is not a header value"))?;
            value.set_sensitive(true);
            headers.push((AUTHORIZATION, value));
        }
        Ok(Self {
            url,
            headers,
            open_timeout: Duration::from_secs(provider.timeout_secs.min(30)),
            read_timeout: Duration::from_secs(provider.timeout_secs),
            max_age: Duration::from_secs(max_age_secs).saturating_sub(RETIRE_BEFORE_LIMIT),
            idle: Mutex::new(Vec::new()),
            refused: AtomicBool::new(false),
            stored: Mutex::new(VecDeque::new()),
        })
    }

    fn usable(&self) -> bool {
        !self.refused.load(Ordering::Relaxed)
    }

    /// A socket for `turn`: the idle one whose chain the turn extends, else
    /// the one idle longest, else a new one. `None` when no socket opens, so
    /// the call takes HTTP.
    async fn checkout(&self, turn: &OpenAiResponsesTurn) -> Option<Session> {
        if !self.usable() {
            return None;
        }
        let items = turn.items.as_slice();
        let session = loop {
            let picked = {
                let mut idle = self
                    .idle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let now = Instant::now();
                idle.retain(|session| {
                    now.duration_since(session.opened) < self.max_age
                        && now.duration_since(session.idle_since) < IDLE_KEEP
                });
                let index = idle
                    .iter()
                    .position(|session| session.chain.extended_by(items))
                    .or_else(|| {
                        idle.iter()
                            .enumerate()
                            .min_by_key(|(_, session)| session.idle_since)
                            .map(|(index, _)| index)
                    });
                index.map(|index| idle.swap_remove(index))
            };
            match picked {
                Some(mut session) => {
                    if session.drain() {
                        break session;
                    }
                }
                None => break self.open().await?,
            }
        };
        Some(self.resume(session, turn))
    }

    /// A stored turn on a socket whose chain it does not extend takes up its
    /// conversation's stored chain, as far as that chain reaches.
    fn resume(&self, mut session: Session, turn: &OpenAiResponsesTurn) -> Session {
        if turn.stored() && !session.chain.extended_by(&turn.items) {
            let stored = self
                .stored
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(chain) = stored
                .iter()
                .filter(|chain| chain.extended_by(&turn.items))
                .max_by_key(|chain| chain.covered())
            {
                session.chain = chain.clone();
            }
        }
        session
    }

    /// Keeps `chain` as its conversation's stored chain, in place of the one
    /// it continues.
    fn keep(&self, chain: &OpenAiResponsesChain) {
        let mut stored = self
            .stored
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stored.retain(|kept| !kept.continued_by(chain));
        if stored.len() >= STORED_CHAINS {
            stored.pop_front();
        }
        stored.push_back(chain.clone());
    }

    /// Drops the stored chain that ends at `response_id`: the provider no
    /// longer has it.
    fn forget(&self, response_id: &str) {
        self.stored
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|kept| kept.response_id() != Some(response_id));
    }

    async fn open(&self) -> Option<Session> {
        let mut request = self.url.as_str().into_client_request().ok()?;
        for (name, value) in &self.headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        match tokio::time::timeout(self.open_timeout, tokio_tungstenite::connect_async(request))
            .await
        {
            Ok(Ok((socket, _))) => {
                let now = Instant::now();
                Some(Session {
                    socket,
                    opened: now,
                    idle_since: now,
                    chain: OpenAiResponsesChain::default(),
                })
            }
            // An origin that answers the upgrade with a refusal serves no
            // socket here; a timeout or a busy answer may pass next time.
            Ok(Err(tungstenite::Error::Http(response)))
                if response.status().is_client_error()
                    && !matches!(response.status().as_u16(), 408 | 429) =>
            {
                self.refused.store(true, Ordering::Relaxed);
                None
            }
            Ok(Err(_)) | Err(_) => None,
        }
    }

    fn put_back(&self, mut session: Session) {
        session.idle_since = Instant::now();
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if idle.len() >= IDLE_SOCKETS
            && let Some(oldest) = idle
                .iter()
                .enumerate()
                .min_by_key(|(_, session)| session.idle_since)
                .map(|(index, _)| index)
        {
            idle.swap_remove(oldest);
        }
        idle.push(session);
    }

    /// Runs `turn` on `session`: sends what of it the socket's chain lacks,
    /// then yields its events up to and including the terminal one. The
    /// socket goes back to the pool only after a terminal event.
    fn run<'a>(
        &'a self,
        session: Session,
        turn: OpenAiResponsesTurn,
    ) -> OpenAiCompatProviderStream<'a> {
        Box::pin(futures_util::stream::unfold(
            Turn::Start(session, turn),
            move |state| self.step(state),
        ))
    }

    async fn step(&self, state: Turn) -> Option<(Frame, Turn)> {
        let (mut session, turn, mut chained) = match state {
            Turn::Done => return None,
            Turn::Reading(session, turn, chained) => (session, turn, chained),
            Turn::Start(mut session, turn) => {
                let (previous, input) = session.chain.plan(&turn.items);
                let chained = previous.is_some();
                let frame = turn.create_frame(previous, input);
                if session
                    .socket
                    .send(Message::text(frame.to_string()))
                    .await
                    .is_err()
                {
                    return Some((Err(OpenAiCompatTransportError::Connection), Turn::Done));
                }
                (session, turn, chained)
            }
        };
        loop {
            let message = match tokio::time::timeout(self.read_timeout, session.socket.next()).await
            {
                Err(_) => return Some((Err(OpenAiCompatTransportError::Timeout), Turn::Done)),
                Ok(Some(Ok(message))) => message,
                Ok(Some(Err(_)) | None) => {
                    return Some((Err(OpenAiCompatTransportError::StreamCut), Turn::Done));
                }
            };
            let text = match message {
                Message::Text(text) => text,
                Message::Close(_) => {
                    return Some((Err(OpenAiCompatTransportError::StreamCut), Turn::Done));
                }
                _ => continue,
            };
            let Ok(mut event) = serde_json::from_str::<JsonValue>(text.as_str()) else {
                return Some((Err(OpenAiCompatTransportError::StreamCut), Turn::Done));
            };
            match responses_error_code(&event) {
                // The socket no longer holds the chained response, and said so
                // before generating anything: the turn goes again, whole.
                Some(RESPONSES_PREVIOUS_NOT_FOUND) if chained => {
                    if let Some(id) = session.chain.response_id() {
                        self.forget(id);
                    }
                    session.chain.clear();
                    chained = false;
                    let frame = turn.create_frame(None, &turn.items);
                    if session
                        .socket
                        .send(Message::text(frame.to_string()))
                        .await
                        .is_err()
                    {
                        return Some((Err(OpenAiCompatTransportError::Connection), Turn::Done));
                    }
                    continue;
                }
                // The socket reached its age limit and is closing.
                Some(RESPONSES_SOCKET_LIMIT) => {
                    return Some((Err(OpenAiCompatTransportError::StreamCut), Turn::Done));
                }
                _ => {}
            }
            if let Some(response) = event.get_mut("response") {
                let served = response.get("model").cloned();
                record_served_model(response.get_mut("usage"), served);
            }
            if !responses_event_is_terminal(&event) {
                return Some((
                    Ok(OpenAiCompatStreamFrame::Chunk(event)),
                    Turn::Reading(session, turn, chained),
                ));
            }
            // A turn that did not complete leaves the chain where the provider
            // may have dropped it: the next turn sends everything.
            match event.get("response") {
                Some(response) if responses_event_type(&event) == "response.completed" => {
                    session.chain.record(&turn.items, response);
                    if turn.stored() && session.chain.response_id().is_some() {
                        self.keep(&session.chain);
                    }
                }
                _ => session.chain.clear(),
            }
            self.put_back(session);
            return Some((Ok(OpenAiCompatStreamFrame::Chunk(event)), Turn::Done));
        }
    }
}

type Frame = Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>;

enum Turn {
    Start(Session, OpenAiResponsesTurn),
    Reading(Session, OpenAiResponsesTurn, bool),
    Done,
}

/// An OpenAI-compatible provider's calls over its Responses sockets, with the
/// chat HTTP backend for a call no socket carries: one whose socket will not
/// open, or one the Responses codec cannot carry (audio input).
pub(super) struct OpenAiSessions {
    pub(super) chat: OpenAiCompatBackend<OpenAiHttp>,
    pub(super) sockets: ResponsesSockets,
    /// The provider's output ceiling, in the field Responses reads.
    pub(super) cap: OutputCap,
    pub(super) response_format: ResponseFormatWire,
}

impl OpenAiSessions {
    fn carries(&self, request: &LlmRequest) -> bool {
        self.sockets.usable() && responses_can_carry(request)
    }

    fn turn(&self, request: &LlmRequest, stream: bool) -> LlmResult<OpenAiResponsesTurn> {
        let mut turn = build_openai_responses_turn(self.chat.config(), request, stream)?;
        let mut head = JsonValue::Object(std::mem::take(&mut turn.head));
        self.cap.apply(&mut head);
        if let JsonValue::Object(head) = head {
            turn.head = head;
        }
        if self.response_format == ResponseFormatWire::Omitted {
            turn.head.remove("text");
        }
        if STORE.load(Ordering::Relaxed) {
            turn.head.insert("store".into(), JsonValue::Bool(true));
        }
        Ok(turn)
    }
}

impl LlmBackend for OpenAiSessions {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.chat.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            if !self.carries(&request) {
                return self.chat.generate(request, lease).await;
            }
            let turn = self.turn(&request, false)?;
            match self.sockets.checkout(&turn).await {
                Some(session) => {
                    OpenAiResponsesLlmStream::new(self.sockets.run(session, turn))
                        .into_response()
                        .await
                }
                None => self.chat.generate(request, lease).await,
            }
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        if !self.carries(&request) {
            return self.chat.stream(request, lease);
        }
        let turn = self.turn(&request, true)?;
        let opened = async move {
            match self.sockets.checkout(&turn).await {
                Some(session) => Ok(LlmStream::new(OpenAiResponsesLlmStream::new(
                    self.sockets.run(session, turn),
                ))),
                None => self.chat.stream(request, lease),
            }
        };
        Ok(LlmStream::new(futures_util::stream::once(opened).flat_map(
            |opened| match opened {
                Ok(stream) => stream.left_stream(),
                Err(error) => {
                    futures_util::stream::once(std::future::ready(Err(error))).right_stream()
                }
            },
        )))
    }
}

/// One call is one response on one socket, or one HTTP request when no
/// socket opens; neither is sent twice, save a chained turn the socket
/// refused before generating, which goes again whole on that socket.
impl SingleRouteBackend for OpenAiSessions {
    fn preflight(&self, request: &LlmRequest, stream: bool) -> LlmResult<()> {
        self.chat.preflight(request, stream)?;
        if self.carries(request) {
            self.turn(request, stream).map(drop)?;
        }
        Ok(())
    }
}
