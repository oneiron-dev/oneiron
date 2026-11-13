//! One HTTP/1.1 exchange with a llama.cpp worker on its own Unix socket
//! (`listen = "unix"`, L9-15), over a connection checked against the
//! launch's supervised child before any byte of the request leaves
//! ([`crate::models::peer_socket::connect_launch`]). Each exchange opens its
//! own connection and sends once, following no redirect; nothing is resent.
use std::collections::BTreeMap;
use std::time::Duration;

use hyper::body::Body as _;
use hyper::{Method, Request, header};
use hyper_util::rt::TokioIo;
use serde_json::Value as JsonValue;

use super::{BytesReply, HttpFailure, JsonReply, ReplyBytes, json_reply};
use crate::models::peer_socket::connect_launch;
use crate::models::worker_host::SocketLaunch;

/// `body` posted as JSON to `path` on `launch`'s socket, the whole exchange
/// within `timeout`: its reply read whole, however large, as
/// [`super::ProviderHttp::post_json`] reads one.
pub(in crate::models) async fn post_json_on(
    launch: &SocketLaunch,
    path: &str,
    body: &JsonValue,
    timeout: Duration,
) -> Result<JsonReply, HttpFailure> {
    let body = serde_json::to_string(body).map_err(|_| HttpFailure::Malformed)?;
    let (status, headers, bytes) =
        exchange(launch, Method::POST, path, body, None, timeout).await?;
    json_reply(status, headers, &bytes)
}

/// A GET of `path` on `launch`'s socket, the whole exchange within
/// `timeout`: a body whose bytes pass `max_bytes` is refused there.
pub(in crate::models) async fn get_within_on(
    launch: &SocketLaunch,
    path: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<BytesReply, HttpFailure> {
    let (status, headers, body) = exchange(
        launch,
        Method::GET,
        path,
        String::new(),
        Some(max_bytes),
        timeout,
    )
    .await?;
    Ok(BytesReply {
        status,
        headers,
        body,
        held: ReplyBytes::default(),
    })
}

/// One request on a fresh checked connection: the reply's status, headers
/// and body bytes.
async fn exchange(
    launch: &SocketLaunch,
    method: Method,
    path: &str,
    body: String,
    max_bytes: Option<usize>,
    timeout: Duration,
) -> Result<(u16, BTreeMap<String, String>, Vec<u8>), HttpFailure> {
    let json = method == Method::POST;
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost");
    if json {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let request = request.body(body).map_err(|_| HttpFailure::Malformed)?;
    let exchanged = async {
        let stream = connect_launch(launch)
            .await
            .map_err(|_| HttpFailure::Connection)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| HttpFailure::Connection)?;
        let reply = async move {
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| HttpFailure::Connection)?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect();
            let bytes = read_body(response.into_body(), max_bytes).await?;
            Ok((status, headers, bytes))
        };
        // The connection is driven until it ends, and the reply is taken as
        // soon as it is read whole, whichever comes first.
        let mut reply = std::pin::pin!(reply);
        let mut connection = std::pin::pin!(connection);
        let mut driving = true;
        loop {
            tokio::select! {
                read = &mut reply => break read,
                _ = &mut connection, if driving => driving = false,
            }
        }
    };
    tokio::time::timeout(timeout, exchanged)
        .await
        .map_err(|_| HttpFailure::Timeout)?
}

/// A reply body read whole, or refused at `max_bytes`; only a real
/// allocation failure ends an unbounded read.
async fn read_body(
    body: hyper::body::Incoming,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>, HttpFailure> {
    let mut body = std::pin::pin!(body);
    let mut bytes = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
        let frame = frame.map_err(|_| HttpFailure::StreamCut)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if max_bytes.is_some_and(|max| bytes.len().saturating_add(data.len()) > max) {
            return Err(HttpFailure::BodyTooLarge);
        }
        bytes
            .try_reserve(data.len())
            .map_err(|_| HttpFailure::OutOfMemory)?;
        bytes.extend_from_slice(&data);
    }
    Ok(bytes)
}
