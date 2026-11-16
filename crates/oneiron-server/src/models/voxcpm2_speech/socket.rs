//! The voice socket a VoxCPM2 speech call renders through: one connection
//! per call (`GET /v1/voice` on the worker's loopback listener), the bearer
//! checked before the upgrade answers. The dialer holds the URL, the bearer
//! and the timeouts; the socket sends `start` once, then one `text` frame per
//! render, and reads each render's `audio` frames until its `usage`. Frames
//! of another generation, and every `done`, are skipped; an `error` for the
//! call's generation fails it. A message past the larger of the vault's
//! metadata ceiling and the audio frame bound is refused as it arrives, as
//! core's own client refuses it; from `start` on, a text frame past the
//! call's effective `max_header_bytes` is refused too. This module is the
//! host's I/O only: the frame shapes and checks are `oneiron_speech`'s and
//! core's pure codec.
use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use oneiron::voice_cascade::our_voice::{
    AUDIO_FRAME_MAX_BYTES, VoiceClientFrame, VoiceServerFrame,
};
use oneiron::voice_cascade::voxcpm2::WarmTarget;
use oneiron::{FatalLlmError, LlmError, LlmResult, RetryableLlmError};
use oneiron_speech::tts::voxcpm2::{
    VOICE_GENERATION, start_frame, started_matches, voice_socket_url, worker_error,
};
use serde_json::Value as JsonValue;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::config::models::ProviderConfig;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One worker's voice dialer: where its socket opens, its bearer, and how
/// long the upgrade and each exchange may take.
pub(in crate::models) struct VoiceSocketDialer {
    url: String,
    bearer: HeaderValue,
    connect_timeout: Duration,
    exchange_timeout: Duration,
}

impl VoiceSocketDialer {
    /// The dialer for a `voxcpm2` provider: its loopback origin spoken as
    /// `ws`, its bearer from `key_env`, its timeouts from `timeout_secs`.
    pub(in crate::models) fn new(provider: &ProviderConfig) -> anyhow::Result<Self> {
        let env = provider.key_env.as_deref().ok_or_else(|| {
            anyhow::anyhow!("a voxcpm2 worker takes a bearer credential; set key_env")
        })?;
        let key = std::env::var(env)
            .ok()
            .filter(|key| !key.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("{env} is not set"))?;
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", key.trim()))
            .map_err(|_| anyhow::anyhow!("{env} is not a header value"))?;
        bearer.set_sensitive(true);
        let url = voice_socket_url(&provider.base_url)?;
        Ok(Self {
            url,
            bearer,
            connect_timeout: Duration::from_secs(provider.timeout_secs.min(30)),
            exchange_timeout: Duration::from_secs(provider.timeout_secs),
        })
    }

    /// One socket to the worker, and the warm target its `ready` names.
    /// `max_header_bytes` is the vault's metadata ceiling for the call, when
    /// a vault binds it: no message past the larger of it and the audio
    /// frame bound is read (core's own client's bound).
    pub(in crate::models) async fn open(
        &self,
        max_header_bytes: Option<u64>,
    ) -> LlmResult<(VoiceSocket, WarmTarget)> {
        let mut request = self
            .url
            .as_str()
            .into_client_request()
            .map_err(|_| FatalLlmError::EmptyResponse)?;
        request
            .headers_mut()
            .insert(AUTHORIZATION, self.bearer.clone());
        let bound = max_header_bytes.map_or(AUDIO_FRAME_MAX_BYTES, |bytes| {
            usize::try_from(bytes)
                .unwrap_or(usize::MAX)
                .max(AUDIO_FRAME_MAX_BYTES)
        });
        let config = WebSocketConfig::default()
            .max_message_size(Some(bound))
            .max_frame_size(Some(bound));
        let (socket, _) = tokio::time::timeout(
            self.connect_timeout,
            tokio_tungstenite::connect_async_with_config(request, Some(config), false),
        )
        .await
        .map_err(|_| RetryableLlmError::Timeout)?
        .map_err(connect_error)?;
        let mut socket = VoiceSocket {
            socket,
            exchange_timeout: self.exchange_timeout,
            header_bound: None,
        };
        let warm = tokio::time::timeout(self.exchange_timeout, socket.read_ready())
            .await
            .map_err(|_| RetryableLlmError::Timeout)??;
        Ok((socket, warm))
    }
}

/// An upgrade answered with an HTTP status reads as any provider's status;
/// any other connect failure never reached one.
fn connect_error(error: WsError) -> LlmError {
    let WsError::Http(response) = error else {
        return RetryableLlmError::ServerError.into();
    };
    let status = response.status().as_u16();
    let headers: BTreeMap<String, String> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_lowercase(), value.to_owned()))
        })
        .collect();
    let body = response
        .body()
        .as_deref()
        .and_then(|body| serde_json::from_slice(body).ok())
        .unwrap_or(JsonValue::Null);
    oneiron_llm::openai_compat::classify_openai_status(status, &headers, &body)
}

/// A socket failure past the upgrade. A frame the bounds refused, one the
/// protocol forbids, or text that is not UTF-8 is the peer's malformed
/// reply. A connection reset without the closing handshake, a send after
/// the peer closed, and any other failure are a cut stream that never named
/// one.
fn socket_error(error: WsError) -> LlmError {
    match error {
        WsError::Protocol(
            ProtocolError::ResetWithoutClosingHandshake | ProtocolError::SendAfterClosing,
        ) => RetryableLlmError::ServerError.into(),
        WsError::Capacity(_) | WsError::Protocol(_) | WsError::Utf8 => {
            FatalLlmError::EmptyResponse.into()
        }
        _ => RetryableLlmError::ServerError.into(),
    }
}

/// One open voice socket, how long each of its exchanges may take, and,
/// from `start` on, the call's effective metadata ceiling.
pub(in crate::models) struct VoiceSocket {
    socket: Socket,
    exchange_timeout: Duration,
    header_bound: Option<u64>,
}

impl VoiceSocket {
    /// The socket's next message: a close stays a message for its caller to
    /// read as a cut stream; the stream ending is one already. A text frame
    /// past the call's metadata ceiling is malformed, as a reply header past
    /// it was.
    async fn next_message(&mut self) -> LlmResult<Message> {
        match self.socket.next().await {
            Some(Ok(Message::Text(text)))
                if self
                    .header_bound
                    .is_some_and(|bound| text.len() as u64 > bound) =>
            {
                Err(FatalLlmError::EmptyResponse.into())
            }
            Some(Ok(message)) => Ok(message),
            Some(Err(error)) => Err(socket_error(error)),
            None => Err(RetryableLlmError::ServerError.into()),
        }
    }

    /// Sends one message down the socket.
    async fn send(&mut self, message: Message) -> LlmResult<()> {
        self.socket.send(message).await.map_err(socket_error)
    }

    /// The binary frame an `audio` header announced: exactly its byte count,
    /// at most [`AUDIO_FRAME_MAX_BYTES`]. The socket's own bound can be wider
    /// (a metadata ceiling past it), so an audio frame is held to its own.
    async fn read_binary(&mut self, announced: u64) -> LlmResult<Vec<u8>> {
        if announced > AUDIO_FRAME_MAX_BYTES as u64 {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        loop {
            match self.next_message().await? {
                Message::Binary(bytes) => {
                    if bytes.len() as u64 != announced {
                        return Err(FatalLlmError::EmptyResponse.into());
                    }
                    return Ok(bytes.to_vec());
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => return Err(RetryableLlmError::ServerError.into()),
                _ => return Err(FatalLlmError::EmptyResponse.into()),
            }
        }
    }

    /// The warm target the worker's `ready` names now.
    async fn read_ready(&mut self) -> LlmResult<WarmTarget> {
        loop {
            match self.next_message().await? {
                Message::Text(text) => {
                    let frame = VoiceServerFrame::parse(text.as_str())
                        .map_err(|_| FatalLlmError::EmptyResponse)?;
                    match frame {
                        VoiceServerFrame::Ready { target, .. } => {
                            let (warm, _) = WarmTarget::from_ready(target)
                                .map_err(|_| FatalLlmError::EmptyResponse)?;
                            warm.validate().map_err(|_| FatalLlmError::EmptyResponse)?;
                            return Ok(warm);
                        }
                        _ => return Err(FatalLlmError::EmptyResponse.into()),
                    }
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => return Err(RetryableLlmError::ServerError.into()),
                _ => return Err(FatalLlmError::EmptyResponse.into()),
            }
        }
    }

    /// The generation's `start`, with the reference transcript and clip as
    /// their own binary frames: the `started` meta it answers. Every text
    /// frame from here on is held to `max_header_bytes`.
    pub(in crate::models) async fn start(
        &mut self,
        target: &JsonValue,
        sample_rate: u32,
        transcript: &str,
        audio: &[u8],
        max_header_bytes: u64,
    ) -> LlmResult<JsonValue> {
        let start = start_frame(target, transcript, audio, max_header_bytes)?;
        self.header_bound = Some(max_header_bytes);
        let exchange = self.exchange_timeout;
        tokio::time::timeout(exchange, self.start_inner(start, transcript, audio))
            .await
            .map_err(|_| RetryableLlmError::Timeout)?
            .and_then(|meta| {
                if started_matches(&meta, target, sample_rate) {
                    Ok(meta)
                } else {
                    Err(FatalLlmError::EmptyResponse.into())
                }
            })
    }

    /// Sends `start` and its two binaries, then reads until the `started`
    /// for this call's generation.
    async fn start_inner(
        &mut self,
        start: String,
        transcript: &str,
        audio: &[u8],
    ) -> LlmResult<JsonValue> {
        self.send(Message::text(start)).await?;
        self.send(Message::binary(transcript.as_bytes().to_vec()))
            .await?;
        self.send(Message::binary(audio.to_vec())).await?;
        loop {
            match self.next_message().await? {
                Message::Text(text) => {
                    let frame = VoiceServerFrame::parse(text.as_str())
                        .map_err(|_| FatalLlmError::EmptyResponse)?;
                    match frame {
                        VoiceServerFrame::Started { meta } => {
                            if meta.get("generation").and_then(JsonValue::as_u64)
                                != Some(VOICE_GENERATION)
                            {
                                continue;
                            }
                            return Ok(meta);
                        }
                        VoiceServerFrame::Error { generation, code }
                            if generation == Some(VOICE_GENERATION) || generation.is_none() =>
                        {
                            return Err(worker_error(&code));
                        }
                        VoiceServerFrame::Audio {
                            generation,
                            bytes: announced,
                            ..
                        } if generation != VOICE_GENERATION => {
                            self.read_binary(announced).await?;
                        }
                        VoiceServerFrame::Usage { generation, .. }
                            if generation != VOICE_GENERATION =>
                        {
                            continue;
                        }
                        VoiceServerFrame::Done { .. } | VoiceServerFrame::Error { .. } => continue,
                        _ => return Err(FatalLlmError::EmptyResponse.into()),
                    }
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => return Err(RetryableLlmError::ServerError.into()),
                _ => return Err(FatalLlmError::EmptyResponse.into()),
            }
        }
    }

    /// One render of `text`: every `audio` binary goes to `sink`, until its
    /// `usage` ends it.
    pub(in crate::models) async fn render(
        &mut self,
        text: &str,
        sink: &mut (dyn FnMut(&[u8]) -> LlmResult<()> + Send),
    ) -> LlmResult<()> {
        let frame = VoiceClientFrame::Text {
            generation: VOICE_GENERATION,
            text: text.to_owned(),
        }
        .to_json();
        let exchange = self.exchange_timeout;
        tokio::time::timeout(exchange, self.render_inner(frame, sink))
            .await
            .map_err(|_| RetryableLlmError::Timeout)?
    }

    /// Sends one `text` frame and spools its `audio` until its `usage`.
    async fn render_inner(
        &mut self,
        frame: String,
        sink: &mut (dyn FnMut(&[u8]) -> LlmResult<()> + Send),
    ) -> LlmResult<()> {
        self.send(Message::text(frame)).await?;
        loop {
            match self.next_message().await? {
                Message::Text(text) => {
                    let frame = VoiceServerFrame::parse(text.as_str())
                        .map_err(|_| FatalLlmError::EmptyResponse)?;
                    match frame {
                        VoiceServerFrame::Audio {
                            generation,
                            bytes: announced,
                            ..
                        } => {
                            let chunk = self.read_binary(announced).await?;
                            if generation == VOICE_GENERATION {
                                sink(&chunk)?;
                            }
                        }
                        VoiceServerFrame::Usage { generation, .. } => {
                            if generation != VOICE_GENERATION {
                                continue;
                            }
                            return Ok(());
                        }
                        VoiceServerFrame::Done { .. } => continue,
                        VoiceServerFrame::Error { generation, code } => {
                            if generation == Some(VOICE_GENERATION) || generation.is_none() {
                                return Err(worker_error(&code));
                            }
                        }
                        _ => return Err(FatalLlmError::EmptyResponse.into()),
                    }
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => return Err(RetryableLlmError::ServerError.into()),
                _ => return Err(FatalLlmError::EmptyResponse.into()),
            }
        }
    }

    /// The generation is over: `end`, then close, best effort and never past
    /// the exchange bound.
    pub(in crate::models) async fn end(self) {
        let Self {
            mut socket,
            exchange_timeout,
            ..
        } = self;
        let _ = tokio::time::timeout(exchange_timeout, async move {
            let end = VoiceClientFrame::End {
                generation: VOICE_GENERATION,
            }
            .to_json();
            let _ = socket.send(Message::text(end)).await;
            let _ = socket.close(None).await;
        })
        .await;
    }
}
