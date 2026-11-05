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
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use zeroize::Zeroizing;

use crate::deadline::{CallDeadline, within};
use crate::frame::{MAX_STREAM, STREAM_CHUNK, write_chunk, write_stream_end, write_stream_header};
use crate::send::{answer, auth_value, reply_headers};
use crate::strip::strip;
use crate::{CallHeader, Failure, Outcome, PROTOCOL_VERSION, Refusal, ReplyHeader};

const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const PREVIOUS_NOT_FOUND: &str = "previous_response_not_found";
const SOCKET_LIMIT: &str = "websocket_connection_limit_reached";

pub(crate) async fn responses_to<W: AsyncWrite + Unpin>(
    call: &CallHeader,
    checked: Result<Url, Refusal>,
    body: Zeroizing<Vec<u8>>,
    whole: Option<Zeroizing<Vec<u8>>>,
    secret: &[u8],
    writer: &mut W,
    deadline: CallDeadline,
) -> io::Result<()> {
    let Some(whole) = whole else {
        return cut_before_header(writer, call, Failure::Send, deadline).await;
    };
    let url = match checked {
        Ok(url) => url,
        Err(reason) => return answer(writer, call, Outcome::Refused { reason }, deadline).await,
    };
    let auth = match auth_value(call, secret) {
        Ok(auth) => auth,
        Err(reason) => return answer(writer, call, Outcome::Refused { reason }, deadline).await,
    };
    let ws_url = url.as_str().replacen("https://", "wss://", 1);
    let mut request = match ws_url.as_str().into_client_request() {
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
    request.headers_mut().insert(
        call.shape
            .auth_header()
            .parse::<reqwest::header::HeaderName>()
            .expect("Responses auth header is a valid header name"),
        auth,
    );
    request.headers_mut().insert(
        reqwest::header::ACCEPT_ENCODING,
        reqwest::header::HeaderValue::from_static("identity"),
    );
    for (name, value) in &call.headers {
        if name == "content-type" {
            continue;
        }
        let name: reqwest::header::HeaderName = match name.parse() {
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
        // No create frame ran, so a failed upgrade is safe to answer as chat.
        Ok(Err(_)) => {
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
        Err(_) => {
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
        let reason = send_or_timeout(&error);
        return cut_before_header(writer, call, reason, deadline).await;
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

    let mut received = 0_usize;
    let mut chained = chained;
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
                let code = (event.get("type").and_then(JsonValue::as_str) == Some("error"))
                    .then(|| event.get("error")?.get("code")?.as_str())
                    .flatten();
                if code == Some(PREVIOUS_NOT_FOUND) && chained {
                    // The daemon sees this marker and forgets its stale row;
                    // it is not a terminal provider verdict for this turn.
                    if let Err(error) = pass_event(
                        writer,
                        deadline,
                        secret,
                        text.as_str().as_bytes(),
                        &mut received,
                    )
                    .await
                    {
                        if error.kind() == io::ErrorKind::InvalidData {
                            return cut_after_header(writer, Failure::ReplyTooLarge, deadline)
                                .await;
                        }
                        let reason = send_or_timeout(&error);
                        return cut_after_header(writer, reason, deadline).await;
                    }
                    chained = false;
                    let mut retry_create = match serde_json::from_slice::<JsonValue>(&whole) {
                        Ok(create) => create,
                        Err(_) => return cut_after_header(writer, Failure::Send, deadline).await,
                    };
                    if let Some(object) = retry_create.as_object_mut() {
                        object.remove("previous_response_id");
                    }
                    let retry = match serde_json::to_string(&retry_create) {
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
                        let reason = send_or_timeout(&error);
                        return cut_after_header(writer, reason, deadline).await;
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
                    secret,
                    text.as_str().as_bytes(),
                    &mut received,
                )
                .await
                {
                    if error.kind() == io::ErrorKind::InvalidData {
                        return cut_after_header(writer, Failure::ReplyTooLarge, deadline).await;
                    }
                    let reason = send_or_timeout(&error);
                    return cut_after_header(writer, reason, deadline).await;
                }
                if terminal {
                    let _ = within(deadline, async {
                        socket.close(None).await.map_err(io::Error::other)
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
                    let reason = send_or_timeout(&error);
                    return cut_after_header(writer, reason, deadline).await;
                }
            }
            Message::Pong(_) | Message::Frame(_) | Message::Binary(_) => {}
            Message::Close(_) => {
                return cut_after_header(writer, Failure::Send, deadline).await;
            }
        }
    }
}

/// A `within` wait that ran out of time is a timeout; anything else that
/// broke the socket after the request may have left is a failed send.
fn send_or_timeout(error: &io::Error) -> Failure {
    if error.kind() == io::ErrorKind::TimedOut {
        Failure::Timeout
    } else {
        Failure::Send
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
    // A failed upgrade is not a socket, even if the HTTP status is 2xx.
    let status = if (200..=299).contains(&status) {
        502
    } else {
        status
    };
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
    let mut received = 0_usize;
    pass_event(writer, deadline, secret, &body, &mut received).await?;
    within(deadline, write_stream_end(writer, None)).await
}

async fn pass_event<W: AsyncWrite + Unpin>(
    writer: &mut W,
    deadline: CallDeadline,
    secret: &[u8],
    event: &[u8],
    received: &mut usize,
) -> io::Result<()> {
    if received.saturating_add(event.len()) > MAX_STREAM {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    *received += event.len();
    // One WS text event is one daemon event. Per-event stripping cannot split
    // or coalesce JSON, and a key cannot span the `}{` boundary of two events.
    let passed = strip(secret, event);
    if passed.len() > STREAM_CHUNK {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    if !passed.is_empty() {
        within(deadline, write_chunk(writer, &passed)).await?;
    }
    Ok(())
}
