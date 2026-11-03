//! OpenAI Responses over one broker-upgraded WebSocket per call.
//!
//! The daemon's create frame is already checked and digest-bound. The broker
//! adds the upgrade and key, sends that frame, and strips every provider text
//! event through the same `KeyWatch` as any other streamed reply. A chained
//! `previous_response_not_found` goes again once, whole, on this same socket:
//! only `previous_response_id` is removed. No other retry exists here.

use std::io;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use serde_json::Value as JsonValue;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use zeroize::Zeroizing;

use crate::deadline::{CallDeadline, within};
use crate::frame::{MAX_STREAM, STREAM_CHUNK, write_chunk, write_stream_end, write_stream_header};
use crate::send::{answer, auth_value, push_wiped, reply_headers};
use crate::strip::KeyWatch;
use crate::{CallHeader, Failure, Outcome, PROTOCOL_VERSION, Refusal, ReplyHeader};

const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const PREVIOUS_NOT_FOUND: &str = "previous_response_not_found";
const SOCKET_LIMIT: &str = "websocket_connection_limit_reached";

type ProviderSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) async fn responses_to<W: AsyncWrite + Unpin>(
    call: &CallHeader,
    checked: Result<Url, Refusal>,
    body: Zeroizing<Vec<u8>>,
    secret: &[u8],
    writer: &mut W,
    deadline: CallDeadline,
) -> io::Result<()> {
    let url = match checked {
        Ok(url) => url,
        Err(reason) => return answer(writer, call, Outcome::Refused { reason }, deadline).await,
    };
    let auth = match auth_value(call, secret) {
        Ok(auth) => auth,
        Err(reason) => return answer(writer, call, Outcome::Refused { reason }, deadline).await,
    };
    let mut request = match url.as_str().into_client_request() {
        Ok(request) => request,
        Err(_) => {
            return answer(
                writer,
                call,
                Outcome::Refused {
                    reason: Refusal::Origin,
                },
                deadline,
            )
            .await;
        }
    };
    request
        .headers_mut()
        .insert(call.shape.auth_header().parse().unwrap(), auth);
    request.headers_mut().insert(
        reqwest::header::ACCEPT_ENCODING,
        reqwest::header::HeaderValue::from_static("identity"),
    );
    for (name, value) in &call.headers {
        let name = match name.parse() {
            Ok(name) => name,
            Err(_) => {
                return answer(
                    writer,
                    call,
                    Outcome::Refused {
                        reason: Refusal::Header,
                    },
                    deadline,
                )
                .await;
            }
        };
        let value = match reqwest::header::HeaderValue::from_str(value) {
            Ok(value) => value,
            Err(_) => {
                return answer(
                    writer,
                    call,
                    Outcome::Refused {
                        reason: Refusal::Header,
                    },
                    deadline,
                )
                .await;
            }
        };
        request.headers_mut().insert(name, value);
    }
    let Some(left) = deadline.send_left() else {
        return answer(
            writer,
            call,
            Outcome::Failed {
                reason: Failure::Timeout,
            },
            deadline,
        )
        .await;
    };
    let connected = tokio::time::timeout(OPEN_TIMEOUT.min(left), connect_async(request)).await;
    let (mut socket, _) = match connected {
        Ok(Ok(connected)) => connected,
        Ok(Err(WsError::Http(response))) => {
            return write_http_refusal(writer, call, response, secret, deadline).await;
        }
        Ok(Err(WsError::Io(_) | WsError::Tls(_))) => {
            return answer(
                writer,
                call,
                Outcome::Refused {
                    reason: Refusal::Connect,
                },
                deadline,
            )
            .await;
        }
        Ok(Err(_)) => return cut_before_header(writer, call, Failure::Send, deadline).await,
        Err(_) => {
            return cut_before_header(writer, call, Failure::Timeout, deadline).await;
        }
    };

    let create = match serde_json::from_slice::<JsonValue>(&body) {
        Ok(create) => create,
        Err(_) => return cut_before_header(writer, call, Failure::Send, deadline).await,
    };
    let chained = create
        .get("previous_response_id")
        .and_then(JsonValue::as_str)
        .is_some();
    let create_text = match std::str::from_utf8(&body) {
        Ok(create) => create,
        Err(_) => return cut_before_header(writer, call, Failure::Send, deadline).await,
    };
    if let Err(error) = within(deadline, async {
        socket
            .send(Message::text(create_text))
            .await
            .map_err(io::Error::other)
    })
    .await
    {
        let _ = error;
        return cut_before_header(writer, call, Failure::Send, deadline).await;
    }
    let header = ReplyHeader {
        version: PROTOCOL_VERSION,
        call: call.call.clone(),
        digest: call.digest.clone(),
        outcome: Outcome::Answered {
            status: 200,
            headers: Vec::new(),
        },
    };
    within(deadline, write_stream_header(writer, &header)).await?;

    let mut watch = KeyWatch::new(secret);
    let mut cleared = Zeroizing::new(Vec::new());
    let mut received = 0_usize;
    let mut chained = chained;
    let mut create = create;
    loop {
        let Some(left) = deadline.send_left() else {
            return cut_after_header(writer, Failure::Timeout, deadline).await;
        };
        let next = match tokio::time::timeout(left, socket.next()).await {
            Ok(Some(Ok(next))) => next,
            Ok(Some(Err(_)) | None) => {
                return cut_after_header(writer, Failure::Send, deadline).await;
            }
            Err(_) => return cut_after_header(writer, Failure::Timeout, deadline).await,
        };
        match next {
            Message::Text(text) => {
                let event = match serde_json::from_str::<JsonValue>(text.as_str()) {
                    Ok(event) => event,
                    Err(_) => return cut_after_header(writer, Failure::Send, deadline).await,
                };
                let code = event
                    .get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(JsonValue::as_str);
                if code == Some(PREVIOUS_NOT_FOUND) && chained {
                    // The daemon sees this marker and forgets its stale row;
                    // it is not a terminal provider verdict for this turn.
                    if let Err(error) = pass_event(
                        writer,
                        deadline,
                        &mut watch,
                        &mut cleared,
                        text.as_str().as_bytes(),
                        false,
                        &mut received,
                    )
                    .await
                    {
                        if error.kind() == io::ErrorKind::InvalidData {
                            return cut_after_header(writer, Failure::ReplyTooLarge, deadline)
                                .await;
                        }
                        let _ = error;
                        return cut_after_header(writer, Failure::Send, deadline).await;
                    }
                    chained = false;
                    if let Some(object) = create.as_object_mut() {
                        object.remove("previous_response_id");
                    }
                    let retry = match serde_json::to_string(&create) {
                        Ok(retry) => retry,
                        Err(_) => return cut_after_header(writer, Failure::Send, deadline).await,
                    };
                    if let Err(error) = within(deadline, async {
                        socket
                            .send(Message::text(retry))
                            .await
                            .map_err(io::Error::other)
                    })
                    .await
                    {
                        let _ = error;
                        return cut_after_header(writer, Failure::Send, deadline).await;
                    }
                    continue;
                }
                if code == Some(SOCKET_LIMIT) {
                    return cut_after_header(writer, Failure::Send, deadline).await;
                }
                let terminal = matches!(
                    event.get("type").and_then(JsonValue::as_str),
                    Some(
                        "response.completed" | "response.incomplete" | "response.failed" | "error"
                    )
                );
                if let Err(error) = pass_event(
                    writer,
                    deadline,
                    &mut watch,
                    &mut cleared,
                    text.as_str().as_bytes(),
                    terminal,
                    &mut received,
                )
                .await
                {
                    if error.kind() == io::ErrorKind::InvalidData {
                        return cut_after_header(writer, Failure::ReplyTooLarge, deadline).await;
                    }
                    let _ = error;
                    return cut_after_header(writer, Failure::Send, deadline).await;
                }
                if terminal {
                    let _ = within(deadline, async {
                        socket.close().await.map_err(io::Error::other)
                    })
                    .await;
                    return within(deadline, write_stream_end(writer, None)).await;
                }
            }
            Message::Ping(bytes) => {
                if let Err(error) = within(deadline, async {
                    socket
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(io::Error::other)
                })
                .await
                {
                    let _ = error;
                    return cut_after_header(writer, Failure::Send, deadline).await;
                }
            }
            Message::Pong(_) | Message::Frame(_) => {}
            Message::Binary(_) | Message::Close(_) => {
                return cut_after_header(writer, Failure::Send, deadline).await;
            }
        }
    }
}

async fn cut_before_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    call: &CallHeader,
    reason: Failure,
    deadline: CallDeadline,
) -> io::Result<()> {
    answer(writer, call, Outcome::Failed { reason }, deadline).await
}

async fn cut_after_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reason: Failure,
    deadline: CallDeadline,
) -> io::Result<()> {
    within(deadline, write_stream_end(writer, Some(reason))).await
}

async fn write_http_refusal<W: AsyncWrite + Unpin>(
    writer: &mut W,
    call: &CallHeader,
    response: tokio_tungstenite::tungstenite::http::Response<Option<Vec<u8>>>,
    secret: &[u8],
    deadline: CallDeadline,
) -> io::Result<()> {
    let status = response.status().as_u16();
    let headers = reply_headers(response.headers(), secret);
    let header = ReplyHeader {
        version: PROTOCOL_VERSION,
        call: call.call.clone(),
        digest: call.digest.clone(),
        outcome: Outcome::Answered { status, headers },
    };
    within(deadline, write_stream_header(writer, &header)).await?;
    let body = response.into_body().unwrap_or_default();
    if body.len() > MAX_STREAM {
        return cut_after_header(writer, Failure::ReplyTooLarge, deadline).await;
    }
    let mut watch = KeyWatch::new(secret);
    let mut cleared = Zeroizing::new(Vec::new());
    let mut received = 0_usize;
    pass_event(
        writer,
        deadline,
        &mut watch,
        &mut cleared,
        &body,
        true,
        &mut received,
    )
    .await?;
    within(deadline, write_stream_end(writer, None)).await
}

async fn pass_event<W: AsyncWrite + Unpin>(
    writer: &mut W,
    deadline: CallDeadline,
    watch: &mut KeyWatch,
    cleared: &mut Zeroizing<Vec<u8>>,
    event: &[u8],
    last: bool,
    received: &mut usize,
) -> io::Result<()> {
    if received.saturating_add(event.len()) > MAX_STREAM {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    *received += event.len();
    let passed = if last {
        watch.finish()
    } else {
        watch.push(event)
    };
    push_wiped(cleared, &passed);
    let mut sent = 0;
    while cleared.len() - sent >= STREAM_CHUNK || (last && sent < cleared.len()) {
        let end = (sent + STREAM_CHUNK).min(cleared.len());
        within(deadline, write_chunk(writer, &cleared[sent..end])).await?;
        sent = end;
    }
    if sent > 0 {
        *cleared = Zeroizing::new(cleared[sent..].to_vec());
    }
    Ok(())
}
