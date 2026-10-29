//! Realtime voice sessions (FIX 462, OF-131): one websocket session on a
//! hosted speech-to-speech model, OpenAI Realtime, held as a voice-loop
//! session rather than an `ai.*` call. The session is admitted on a run of
//! its own ([`VOICE_LOOP_RUN`]) as the provider's realtime connector, one
//! unit per token the session reports.
//!
//! Each response the model gives goes out on a permit of its own: the first
//! is admitted before the socket opens, so a refused session opens none, and
//! each next one as the response before it ends. A `response.done` settles
//! its permit on the tokens its usage reports. A session that ends between
//! responses settles its open permit on none; one that ends while a response
//! is under way, with its usage never reported, pays that permit's
//! reservation as unknown usage.
//!
//! The key is read from the provider's `key_env` when the rung is built and
//! rides the WebSocket upgrade as a bearer, marked sensitive, and nowhere
//! else. Gemini Live is not built here yet.
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use oneiron::llm::run_admission::{CallOutcome, PaidConnector, RunAdmission, RunPermit};
use oneiron::{FatalLlmError, LlmResult, RetryableLlmError};
use serde_json::{Value as JsonValue, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, header::AUTHORIZATION};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::offer::realtime_connector;
use crate::config::models::ProviderConfig;

/// The run a realtime voice session is admitted on: a voice loop, not an
/// `ai.*` call.
pub const VOICE_LOOP_RUN: &str = "voice-loop";
/// The tokens each response's permit reserves before its usage is known.
const RESPONSE_RESERVED_TOKENS: u64 = 16_384;
/// The longest the upgrade may take, whatever the provider's own timeout.
const UPGRADE_TIMEOUT_CAP: Duration = Duration::from_secs(30);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Which realtime wire a rung speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtimeWire {
    /// OpenAI Realtime: `wss://…/v1/realtime?model=…`, JSON events both ways.
    OpenAiRealtime,
}

/// One realtime rung: where its socket opens, its key, and the connector
/// its sessions are admitted as.
pub struct RealtimeVoiceRung {
    wire: RealtimeWire,
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    timeout: Duration,
    connector: PaidConnector,
}

impl RealtimeVoiceRung {
    /// `model` on provider `name` over `wire`. A provider whose key is not
    /// in `key_env`, or whose base URL names no realtime socket, makes none.
    pub fn new(
        name: &str,
        provider: &ProviderConfig,
        model: &str,
        wire: RealtimeWire,
    ) -> anyhow::Result<Self> {
        let mut headers = Vec::new();
        for (header, value) in &provider.headers {
            headers.push((
                HeaderName::from_bytes(header.as_bytes())?,
                HeaderValue::from_str(value)?,
            ));
        }
        headers.push((AUTHORIZATION, bearer(provider)?));
        Ok(Self {
            wire,
            url: socket_url(&provider.base_url, model, wire)?,
            headers,
            timeout: Duration::from_secs(provider.timeout_secs).min(UPGRADE_TIMEOUT_CAP),
            connector: realtime_connector(provider, name)?,
        })
    }
}

/// The session socket's URL on `base_url`: its scheme as a socket's, the
/// wire's path below the base's, and the model as a query.
fn socket_url(base_url: &str, model: &str, wire: RealtimeWire) -> anyhow::Result<String> {
    let mut url = reqwest::Url::parse(base_url)?;
    let scheme = match url.scheme() {
        "https" | "wss" => "wss",
        "http" | "ws" => "ws",
        other => anyhow::bail!("a {other} base URL opens no realtime socket"),
    };
    url.set_scheme(scheme)
        .map_err(|()| anyhow::anyhow!("the base URL takes no socket scheme"))?;
    match wire {
        RealtimeWire::OpenAiRealtime => {
            let path = format!("{}/realtime", url.path().trim_end_matches('/'));
            url.set_path(&path);
            url.query_pairs_mut().append_pair("model", model);
        }
    }
    Ok(url.into())
}

fn bearer(provider: &ProviderConfig) -> anyhow::Result<HeaderValue> {
    let env = provider
        .key_env
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("a realtime voice rung takes its key from key_env"))?;
    let key = std::env::var(env)
        .ok()
        .filter(|key| !key.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{env} is not set"))?;
    let mut value = HeaderValue::from_str(&format!("Bearer {}", key.trim()))
        .map_err(|_| anyhow::anyhow!("{env} is not a header value"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// One open realtime voice session. The caller sends the wire's client
/// events and reads its server events; dropping it closes the socket and
/// settles its open permit.
pub struct RealtimeVoiceSession {
    socket: Socket,
    run: RunAdmission,
    connector: PaidConnector,
    /// The permit the response under way, or the next, is paid on.
    permit: Option<RunPermit>,
    /// A response started and has not reported its usage yet.
    responding: bool,
    /// The socket closed: no event follows.
    closed: bool,
}

impl RealtimeVoiceSession {
    /// Opens a session on `rung`, on `run`, its first permit admitted before
    /// the socket opens. `session`, when given, is the wire's session
    /// configuration, sent first. An upgrade that fails started nothing at
    /// the provider, so its permit settles on no usage.
    pub async fn open(
        rung: &RealtimeVoiceRung,
        run: RunAdmission,
        session: Option<JsonValue>,
    ) -> LlmResult<Self> {
        let permit = admit_response(&run, &rung.connector)?;
        let opened = connect(rung).await;
        let socket = match opened {
            Ok(socket) => socket,
            Err(error) => {
                settle(permit, CallOutcome::Used(0));
                return Err(error);
            }
        };
        let mut opened = Self {
            socket,
            run,
            connector: rung.connector.clone(),
            permit: Some(permit),
            responding: false,
            closed: false,
        };
        if let Some(session) = session {
            let update = match rung.wire {
                RealtimeWire::OpenAiRealtime => {
                    json!({"type": "session.update", "session": session})
                }
            };
            opened.send(&update).await?;
        }
        Ok(opened)
    }

    /// Sends one client event: the caller's audio, text, or a control.
    pub async fn send(&mut self, event: &JsonValue) -> LlmResult<()> {
        if self.closed {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.socket
            .send(Message::text(event.to_string()))
            .await
            .map_err(|_| RetryableLlmError::ServerError.into())
    }

    /// The next server event, in order; `None` once the socket closed. A
    /// `response.done` settles its response's permit on the tokens it
    /// reports, and the next response's permit is admitted; a refused one
    /// ends the session with its refusal.
    pub async fn next(&mut self) -> LlmResult<Option<JsonValue>> {
        while !self.closed {
            let frame = match self.socket.next().await {
                Some(Ok(Message::Text(text))) => text,
                // The pong a ping asks for goes out with the next send.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Binary(_))) => {
                    return Err(FatalLlmError::EmptyResponse.into());
                }
                Some(Ok(Message::Close(_))) | None => {
                    self.end();
                    return Ok(None);
                }
                Some(Err(_)) => {
                    self.end();
                    return Err(RetryableLlmError::ServerError.into());
                }
            };
            let event: JsonValue = serde_json::from_str(frame.as_str())
                .map_err(|_| FatalLlmError::EmptyResponse)?;
            match event["type"].as_str() {
                Some("response.created") => self.responding = true,
                Some("response.done") => self.answered(&event)?,
                _ => {}
            }
            return Ok(Some(event));
        }
        Ok(None)
    }

    /// Closes the session: the socket is closed and its open permit settles.
    pub async fn close(mut self) {
        if !self.closed {
            if let Err(error) = self.socket.close(None).await {
                tracing::debug!(%error, "a realtime voice socket did not close cleanly");
            }
            self.end();
        }
    }

    /// A response ended: its permit settles on the tokens it reports, and
    /// the next response's is admitted.
    fn answered(&mut self, event: &JsonValue) -> LlmResult<()> {
        self.responding = false;
        let tokens = event
            .pointer("/response/usage/total_tokens")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0);
        if let Some(permit) = self.permit.take() {
            settle(permit, CallOutcome::Used(tokens));
        }
        match admit_response(&self.run, &self.connector) {
            Ok(permit) => {
                self.permit = Some(permit);
                Ok(())
            }
            Err(refused) => {
                self.closed = true;
                Err(refused)
            }
        }
    }

    /// The session ended: its open permit settles, on no usage between
    /// responses, or as unknown usage when a response was under way.
    fn end(&mut self) {
        self.closed = true;
        if let Some(permit) = self.permit.take() {
            let outcome = if self.responding {
                CallOutcome::Failed
            } else {
                CallOutcome::Used(0)
            };
            settle(permit, outcome);
        }
    }
}

impl Drop for RealtimeVoiceSession {
    fn drop(&mut self) {
        self.end();
    }
}

/// One response's permit on `run`, reserved before its usage is known and
/// checked for dispatch on `connector`'s credential.
fn admit_response(run: &RunAdmission, connector: &PaidConnector) -> LlmResult<RunPermit> {
    let permit = run.admit_paid(connector, RESPONSE_RESERVED_TOKENS)?;
    run.dispatch_paid(permit.lease(), connector)?;
    Ok(permit)
}

fn settle(permit: RunPermit, outcome: CallOutcome<'_>) {
    if let Err(denied) = permit.settle(outcome) {
        tracing::error!(%denied, "a realtime voice response's settlement was refused");
    }
}

/// Opens `rung`'s socket within its upgrade timeout.
async fn connect(rung: &RealtimeVoiceRung) -> LlmResult<Socket> {
    let mut request = rung
        .url
        .as_str()
        .into_client_request()
        .map_err(|_| FatalLlmError::InvalidRequest)?;
    for (name, value) in &rung.headers {
        request.headers_mut().insert(name.clone(), value.clone());
    }
    let (socket, _) = tokio::time::timeout(rung.timeout, tokio_tungstenite::connect_async(request))
        .await
        .map_err(|_| RetryableLlmError::Timeout)?
        .map_err(|_| RetryableLlmError::ServerError)?;
    Ok(socket)
}
