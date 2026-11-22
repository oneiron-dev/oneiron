//! A gRPC client of the smallest kind (L8-43): unary and server-streaming
//! calls over one HTTP/2 connection, on TLS with the web's roots, or in the
//! clear to an `http://` address (a loopback stand-in). The caller writes
//! and reads each message's protobuf bytes ([`super::protobuf`]); this
//! module frames them, sends the call's metadata and deadline, and reads
//! the call's status from its trailers. It compresses nothing and accepts
//! no compressed message.

use std::convert::Infallible;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::client::conn::http2::{self, SendRequest};
use hyper::header::{CONTENT_TYPE, TE};
use hyper::{HeaderMap, Request, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

/// The longest wait for a service's TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest message this client reads.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// A message's frame: a compression flag, then its length.
const FRAME_HEADER_BYTES: usize = 5;

/// The status a service ends a call with when the call's deadline passed.
pub(super) const DEADLINE_EXCEEDED: u32 = 4;

/// A failed call.
#[derive(Debug)]
pub(super) enum GrpcError {
    /// The call got no status: the connection, TLS, HTTP/2 or the framing
    /// of an answer failed.
    Transport(String),
    /// The service ended the call with a status other than OK.
    Status { code: u32, message: String },
}

impl GrpcError {
    /// The name gRPC gives the status `code`.
    pub(super) fn code_name(code: u32) -> &'static str {
        match code {
            0 => "OK",
            1 => "CANCELLED",
            2 => "UNKNOWN",
            3 => "INVALID_ARGUMENT",
            4 => "DEADLINE_EXCEEDED",
            5 => "NOT_FOUND",
            6 => "ALREADY_EXISTS",
            7 => "PERMISSION_DENIED",
            8 => "RESOURCE_EXHAUSTED",
            9 => "FAILED_PRECONDITION",
            10 => "ABORTED",
            11 => "OUT_OF_RANGE",
            12 => "UNIMPLEMENTED",
            13 => "INTERNAL",
            14 => "UNAVAILABLE",
            15 => "DATA_LOSS",
            16 => "UNAUTHENTICATED",
            _ => "an unknown status",
        }
    }
}

fn transport(detail: impl Into<String>) -> GrpcError {
    GrpcError::Transport(detail.into())
}

fn hyper_failed(error: hyper::Error) -> GrpcError {
    transport(format!("the HTTP/2 call failed: {error}"))
}

/// Where one gRPC service answers.
#[derive(Clone, Debug)]
pub(super) struct GrpcEndpoint {
    tls: bool,
    host: String,
    port: u16,
    /// `scheme://authority`, which each call's path follows.
    origin: String,
}

impl GrpcEndpoint {
    /// The service at `url`: `https://host[:port]`, or `http://host[:port]`
    /// with no TLS. A URL with a user, a path or a query names no service.
    pub(super) fn parse(url: &str) -> Option<Self> {
        let uri: Uri = url.parse().ok()?;
        let tls = match uri.scheme_str()? {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        let authority = uri.authority()?;
        let plain = !authority.as_str().contains('@')
            && matches!(uri.path(), "" | "/")
            && uri.query().is_none();
        let host = authority.host().trim_matches(['[', ']']);
        if !plain || host.is_empty() {
            return None;
        }
        Some(Self {
            tls,
            host: host.to_owned(),
            port: authority.port_u16().unwrap_or(if tls { 443 } else { 80 }),
            origin: format!("{}://{authority}", uri.scheme_str()?),
        })
    }

    /// Whether the service is reached over TLS.
    pub(super) fn tls(&self) -> bool {
        self.tls
    }

    /// The service's host name, without its port.
    pub(super) fn host(&self) -> &str {
        &self.host
    }
}

fn tls_config() -> Result<Arc<ClientConfig>, GrpcError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Do not depend on a process-global default crypto provider.
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| transport(format!("the TLS client could not be built: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// A request body of one framed message.
struct FramedMessage(Option<Bytes>);

impl Body for FramedMessage {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.take().map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |data| data.len() as u64))
    }
}

/// The status in `map` (an answer's headers, or its trailers), if it
/// carries one.
fn status_of(map: &HeaderMap) -> Option<Result<(), GrpcError>> {
    let code = map.get("grpc-status")?;
    let code = code
        .to_str()
        .ok()
        .and_then(|code| code.parse().ok())
        .unwrap_or(2);
    if code == 0 {
        return Some(Ok(()));
    }
    let message = map
        .get("grpc-message")
        .map_or_else(String::new, |message| percent_decoded(message.as_bytes()));
    Some(Err(GrpcError::Status { code, message }))
}

/// A `grpc-message` as its sender wrote it: gRPC percent-encodes it.
fn percent_decoded(text: &[u8]) -> String {
    let mut decoded = Vec::with_capacity(text.len());
    let mut rest = text;
    while let Some((&byte, tail)) = rest.split_first() {
        let escaped = if byte == b'%' {
            tail.get(..2)
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        } else {
            None
        };
        if let Some(escaped) = escaped {
            decoded.push(escaped);
            rest = &tail[2..];
        } else {
            decoded.push(byte);
            rest = tail;
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// A call's deadline as the `grpc-timeout` header writes it: milliseconds,
/// in at most eight digits.
fn grpc_timeout(timeout: Duration) -> String {
    format!("{}m", timeout.as_millis().clamp(1, 99_999_999))
}

/// One HTTP/2 connection to a service. It lives on the runtime that made
/// it, and ends when it drops.
pub(super) struct GrpcChannel {
    send: SendRequest<FramedMessage>,
    origin: String,
}

impl GrpcChannel {
    /// A connection to `endpoint`.
    pub(super) async fn connect(endpoint: &GrpcEndpoint) -> Result<Self, GrpcError> {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
        )
        .await
        .map_err(|_| transport("the connection timed out"))?
        .map_err(|error| transport(format!("the connection failed: {error}")))?;
        tcp.set_nodelay(true)
            .map_err(|error| transport(format!("the connection failed: {error}")))?;
        let builder = http2::Builder::new(TokioExecutor::new());
        let send = if endpoint.tls {
            let name = ServerName::try_from(endpoint.host.clone())
                .map_err(|_| transport("the service has no valid TLS server name"))?;
            let stream = TlsConnector::from(tls_config()?)
                .connect(name, tcp)
                .await
                .map_err(|error| transport(format!("the TLS handshake failed: {error}")))?;
            if stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                return Err(transport("the service does not speak HTTP/2"));
            }
            let (send, connection) = builder
                .handshake(TokioIo::new(stream))
                .await
                .map_err(hyper_failed)?;
            tokio::spawn(connection);
            send
        } else {
            let (send, connection) = builder
                .handshake(TokioIo::new(tcp))
                .await
                .map_err(hyper_failed)?;
            tokio::spawn(connection);
            send
        };
        Ok(Self {
            send,
            origin: endpoint.origin.clone(),
        })
    }

    /// Starts the call of `path` with `message`, `metadata` and a deadline
    /// `timeout` away, and answers its reply once the service answered.
    pub(super) async fn call(
        &mut self,
        path: &str,
        metadata: &HeaderMap,
        message: &[u8],
        timeout: Duration,
    ) -> Result<GrpcReply, GrpcError> {
        let length =
            u32::try_from(message.len()).map_err(|_| transport("a request message is too long"))?;
        let mut framed = Vec::with_capacity(FRAME_HEADER_BYTES + message.len());
        framed.push(0);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(message);
        let mut request = Request::post(format!("{}{path}", self.origin))
            .header(CONTENT_TYPE, "application/grpc")
            .header(TE, "trailers")
            .header("grpc-timeout", grpc_timeout(timeout))
            .body(FramedMessage(Some(Bytes::from(framed))))
            .map_err(|_| transport("a request could not be built"))?;
        request.headers_mut().extend(metadata.clone());
        self.send.ready().await.map_err(hyper_failed)?;
        let response = self
            .send
            .send_request(request)
            .await
            .map_err(hyper_failed)?;
        let (parts, body) = response.into_parts();
        // A call that ends before any message answers its status in its
        // headers alone.
        if let Some(status) = status_of(&parts.headers) {
            status?;
            return Ok(GrpcReply {
                body: None,
                buffer: Vec::new(),
            });
        }
        if parts.status != StatusCode::OK {
            return Err(transport(format!(
                "the service answered HTTP {}",
                parts.status.as_u16()
            )));
        }
        let grpc = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/grpc"));
        if !grpc {
            return Err(transport("the service answered no gRPC"));
        }
        Ok(GrpcReply {
            body: Some(body),
            buffer: Vec::new(),
        })
    }

    /// The one message a unary call of `path` answers.
    pub(super) async fn unary(
        &mut self,
        path: &str,
        metadata: &HeaderMap,
        message: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, GrpcError> {
        let mut reply = self.call(path, metadata, message, timeout).await?;
        let answer = reply
            .next_message()
            .await?
            .ok_or_else(|| transport("the service answered no message"))?;
        if reply.next_message().await?.is_some() {
            return Err(transport("the service answered more than one message"));
        }
        Ok(answer)
    }
}

/// The messages of one call's answer, then its status.
pub(super) struct GrpcReply {
    /// `None` once the status was read.
    body: Option<Incoming>,
    buffer: Vec<u8>,
}

impl GrpcReply {
    /// The next whole message in the buffer, if one is there.
    fn buffered_message(&mut self) -> Result<Option<Vec<u8>>, GrpcError> {
        let Some(header) = self.buffer.get(..FRAME_HEADER_BYTES) else {
            return Ok(None);
        };
        if header[0] != 0 {
            return Err(transport("the service sent a compressed message"));
        }
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = usize::try_from(length)
            .ok()
            .filter(|length| *length <= MAX_MESSAGE_BYTES)
            .ok_or_else(|| transport("the service sent a message too long to read"))?;
        if self.buffer.len() < FRAME_HEADER_BYTES + length {
            return Ok(None);
        }
        let message = self.buffer[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + length].to_vec();
        self.buffer.drain(..FRAME_HEADER_BYTES + length);
        Ok(Some(message))
    }

    /// The answer's next message, or `None` at its end once its status is
    /// OK. A status other than OK is the error.
    pub(super) async fn next_message(&mut self) -> Result<Option<Vec<u8>>, GrpcError> {
        loop {
            if let Some(message) = self.buffered_message()? {
                return Ok(Some(message));
            }
            let Some(body) = self.body.as_mut() else {
                return Ok(None);
            };
            let frame = poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx))
                .await
                .ok_or_else(|| transport("the call ended with no status"))?
                .map_err(hyper_failed)?;
            match frame.into_data() {
                Ok(data) => {
                    if self.buffer.len() + data.len() > FRAME_HEADER_BYTES + MAX_MESSAGE_BYTES {
                        return Err(transport("the service sent a message too long to read"));
                    }
                    self.buffer.extend_from_slice(&data);
                }
                Err(frame) => {
                    let Ok(trailers) = frame.into_trailers() else {
                        continue;
                    };
                    self.body = None;
                    if !self.buffer.is_empty() {
                        return Err(transport("the service cut a message short"));
                    }
                    status_of(&trailers)
                        .ok_or_else(|| transport("the call ended with no status"))??;
                    return Ok(None);
                }
            }
        }
    }
}
