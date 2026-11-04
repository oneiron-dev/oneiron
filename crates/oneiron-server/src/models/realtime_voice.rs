//! Realtime voice sessions (FIX 462, OF-131): one websocket session on a
//! hosted speech-to-speech model, OpenAI Realtime or Gemini Live, held as a voice-loop
//! session rather than an `ai.*` call. The session is admitted on a run of
//! its own ([`VOICE_LOOP_RUN`]) as the provider's realtime connector, one
//! unit per token the session reports.
//!
//! Each response the model gives goes out on a permit of its own: the first
//! is admitted before the socket opens, so a refused session opens none, and
//! each next one as the response before it ends, reserving what that response
//! reported when past the base (FIX 11481). A completed response settles
//! its permit on the tokens its usage reports. A session that ends between
//! responses settles its open permit on none; one that ends while a response
//! is under way, with its usage never reported, pays that permit's
//! reservation as unknown usage.
//!
//! The key is read from the provider's `key_env` when the rung is built and
//! rides the WebSocket upgrade in a sensitive header: an OpenAI bearer or
//! Gemini's `x-goog-api-key`. It never enters the socket URL.
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use oneiron::llm::run_admission::{CallOutcome, PaidConnector, RunAdmission, RunPermit};
use oneiron::{FatalLlmError, LlmError, LlmResult, RetryableLlmError};
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
    /// Gemini Live v1beta: `BidiGenerateContent`, JSON events both ways.
    GeminiLive,
}

/// One realtime rung: where its socket opens, its key, and the connector
/// its sessions are admitted as.
pub struct RealtimeVoiceRung {
    wire: RealtimeWire,
    model: String,
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
        let (header, prefix) = match wire {
            RealtimeWire::OpenAiRealtime => (AUTHORIZATION, "Bearer "),
            RealtimeWire::GeminiLive => (HeaderName::from_static("x-goog-api-key"), ""),
        };
        headers.push((header, key_header(provider, prefix)?));
        Ok(Self {
            wire,
            model: model.to_owned(),
            url: socket_url(&provider.base_url, model, wire)?,
            headers,
            timeout: Duration::from_secs(provider.timeout_secs).min(UPGRADE_TIMEOUT_CAP),
            connector: realtime_connector(provider, name)?,
        })
    }
}

/// The session socket's URL on `base_url`: its scheme as a socket's, the
/// wire's path below the base's. OpenAI takes the model as a query;
/// Gemini takes it in its setup message.
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
        RealtimeWire::GeminiLive => {
            let path = format!(
                "{}/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent",
                url.path().trim_end_matches('/')
            );
            url.set_path(&path);
        }
    }
    Ok(url.into())
}

fn key_header(provider: &ProviderConfig, prefix: &str) -> anyhow::Result<HeaderValue> {
    let env = provider
        .key_env
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("a realtime voice rung takes its key from key_env"))?;
    let key = std::env::var(env)
        .ok()
        .filter(|key| !key.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{env} is not set"))?;
    let mut value = HeaderValue::from_str(&format!("{prefix}{}", key.trim()))
        .map_err(|_| anyhow::anyhow!("{env} is not a header value"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// One open realtime voice session. The caller sends the wire's client
/// events and reads its server events; dropping it closes the socket and
/// settles its open permit.
pub struct RealtimeVoiceSession {
    socket: Socket,
    wire: RealtimeWire,
    run: RunAdmission,
    connector: PaidConnector,
    /// The permit the response under way, or the next, is paid on.
    permit: Option<RunPermit>,
    /// A response started and has not reported its usage yet.
    responding: bool,
    /// Gemini's latest usage report for the response under way, not a sum
    /// of the counts its successive events report.
    reported_tokens: Option<u64>,
    /// The tokens the last response reported, for the next one's reservation.
    last_tokens: u64,
    /// A refusal for the next response, reported after the completed event
    /// already paid for has reached its caller.
    terminal_error: Option<LlmError>,
    /// The socket closed: no event follows.
    closed: bool,
}

impl RealtimeVoiceSession {
    /// Opens a session on `rung`, on `run`, its first permit admitted before
    /// the socket opens. `session`, when given, is the wire's session
    /// configuration, sent first. Gemini always sends setup with the rung's
    /// model; its caller must read `setupComplete` before sending input.
    /// Server acknowledgments remain in the raw event stream. An upgrade
    /// that fails started nothing at the provider, so its permit settles
    /// on no usage.
    pub async fn open(
        rung: &RealtimeVoiceRung,
        run: RunAdmission,
        session: Option<JsonValue>,
    ) -> LlmResult<Self> {
        let permit = admit_response(&run, &rung.connector, RESPONSE_RESERVED_TOKENS)?;
        let opened = connect(rung).await;
        let socket = match opened {
            Ok(socket) => socket,
            Err(error) => {
                settle(permit, CallOutcome::UsedCounted(0));
                return Err(error);
            }
        };
        let mut opened = Self {
            socket,
            wire: rung.wire,
            run,
            connector: rung.connector.clone(),
            permit: Some(permit),
            responding: false,
            reported_tokens: None,
            last_tokens: 0,
            terminal_error: None,
            closed: false,
        };
        match rung.wire {
            RealtimeWire::OpenAiRealtime => {
                if let Some(session) = session {
                    let update = json!({"type": "session.update", "session": session});
                    opened.send(&update).await?;
                }
            }
            RealtimeWire::GeminiLive => {
                let mut setup = session.unwrap_or_else(|| json!({}));
                if let Some(fields) = setup.as_object_mut() {
                    let model = if rung.model.starts_with("models/") {
                        rung.model.clone()
                    } else {
                        format!("models/{}", rung.model)
                    };
                    fields.insert("model".to_owned(), JsonValue::String(model));
                }
                opened.send(&json!({"setup": setup})).await?;
            }
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
    /// `response.done`, or Gemini's `serverContent.turnComplete`, settles
    /// its response's permit on the tokens it reports, and the next
    /// response's permit is admitted. If that next permit is refused, this
    /// completed event is returned before the next read reports the refusal.
    /// Gemini's generation end or interruption alone does not
    /// complete the turn.
    pub async fn next(&mut self) -> LlmResult<Option<JsonValue>> {
        if let Some(error) = self.terminal_error.take() {
            return Err(error);
        }
        while !self.closed {
            let event: JsonValue = match self.socket.next().await {
                Some(Ok(Message::Text(text))) => {
                    serde_json::from_str(text.as_str()).map_err(|_| FatalLlmError::EmptyResponse)?
                }
                Some(Ok(Message::Binary(bytes))) if self.wire == RealtimeWire::GeminiLive => {
                    serde_json::from_slice(&bytes).map_err(|_| FatalLlmError::EmptyResponse)?
                }
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
            match self.wire {
                RealtimeWire::OpenAiRealtime => match event["type"].as_str() {
                    Some("response.created") => self.responding = true,
                    Some("response.done") => {
                        let reported = event
                            .pointer("/response/usage/total_tokens")
                            .and_then(JsonValue::as_u64);
                        self.terminal_error = self.answered(reported).err();
                    }
                    _ => {}
                },
                RealtimeWire::GeminiLive => {
                    let content = &event["serverContent"];
                    let complete = content["turnComplete"].as_bool() == Some(true);
                    if event.get("toolCall").is_some()
                        || content.get("modelTurn").is_some()
                        || content["generationComplete"].as_bool() == Some(true)
                        || content["interrupted"].as_bool() == Some(true)
                    {
                        self.responding = true;
                    }
                    if (self.responding || complete)
                        && let Some(tokens) = event
                            .pointer("/usageMetadata/totalTokenCount")
                            .and_then(JsonValue::as_u64)
                    {
                        self.reported_tokens = Some(tokens);
                    }
                    if complete {
                        let reported = self.reported_tokens.take();
                        self.terminal_error = self.answered(reported).err();
                    }
                }
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
    /// the next response's is admitted, reserving at least what this one
    /// reported (FIX 11481).
    fn answered(&mut self, reported: Option<u64>) -> LlmResult<()> {
        self.responding = false;
        let tokens = reported.unwrap_or(0);
        self.last_tokens = tokens;
        if let Some(permit) = self.permit.take() {
            // Absent usage settles as a counted zero, never the provider's
            // report (FIX 11481).
            let outcome = match reported {
                Some(_) => CallOutcome::Used(tokens),
                None => CallOutcome::UsedCounted(0),
            };
            settle(permit, outcome);
        }
        let reserve = self.last_tokens.max(RESPONSE_RESERVED_TOKENS);
        match admit_response(&self.run, &self.connector, reserve) {
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
                CallOutcome::UsedCounted(0)
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

/// One response's permit on `run`, reserving `reserve` before its usage is
/// known and checked for dispatch on `connector`'s credential.
fn admit_response(
    run: &RunAdmission,
    connector: &PaidConnector,
    reserve: u64,
) -> LlmResult<RunPermit> {
    let permit = run.admit_paid(connector, reserve)?;
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
