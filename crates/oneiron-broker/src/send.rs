//! The broker's one send: verified TLS, no redirect, no retry, no proxy, and
//! no content encoding, so the reply it strips is the reply the daemon reads.
//! The one exception to "no redirect" is a shape row's own: one hop, to the
//! path the row names under the same origin, without the key.

use std::future::Future;
use std::io;
use std::time::Duration;

use reqwest::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap, HeaderValue, LOCATION, TRANSFER_ENCODING,
};
use reqwest::{Certificate, Client, Method, Url};
use tokio::io::AsyncWrite;
use zeroize::Zeroizing;

use crate::frame::{STREAM_CHUNK, write_chunk, write_stream_end, write_stream_header};
use crate::strip::{KeyWatch, admits, contains_key, strip};
use crate::{
    CallHeader, Failure, MAX_BODY, MAX_SECRET, MAX_STREAM, Outcome, PROTOCOL_VERSION, Refusal,
    ReplyHeader,
};

/// The shortest key the broker injects. Stripping a shorter one would redact
/// ordinary text, and no provider issues one.
const MIN_SECRET: usize = 8;

/// The reply headers kept, at most, and their total size.
const MAX_REPLY_HEADERS: usize = 64;
const MAX_REPLY_HEADER_BYTES: usize = 32 << 10;

/// How the broker's client sends.
#[derive(Debug, Clone)]
pub struct SendPolicy {
    /// The whole call's time limit, from connect to the last reply byte.
    pub timeout: Duration,
    /// Extra trust anchors (PEM) for a self-hosted provider's private CA,
    /// beside the WebPKI and the platform roots.
    pub extra_roots: Vec<Vec<u8>>,
}

/// The client every call of one broker sends through.
pub(crate) struct Sender {
    client: Client,
}

impl Sender {
    pub(crate) fn new(policy: &SendPolicy) -> Result<Self, reqwest::Error> {
        let mut builder = Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .tls_built_in_root_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(policy.timeout.min(Duration::from_secs(30)))
            .timeout(policy.timeout);
        for pem in &policy.extra_roots {
            for root in Certificate::from_pem_bundle(pem)? {
                builder = builder.add_root_certificate(root);
            }
        }
        Ok(Self {
            client: builder.build()?,
        })
    }

    /// Sends `body` to `url` once with the key in the shape's auth header,
    /// then strips the key from what came back. `call` has passed
    /// [`CallHeader::check`].
    pub(crate) async fn send(
        &self,
        call: &CallHeader,
        url: Url,
        body: &[u8],
        secret: &[u8],
    ) -> (Outcome, Zeroizing<Vec<u8>>) {
        let empty = Zeroizing::new(Vec::new());
        let mut response = match self.reach(call, url, body, secret).await {
            Ok(response) => response,
            Err(outcome) => return (outcome, empty),
        };
        let mut raw = Zeroizing::new(Vec::new());
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if raw.len() + chunk.len() > MAX_BODY {
                        return (
                            Outcome::Failed {
                                reason: Failure::ReplyTooLarge,
                            },
                            empty,
                        );
                    }
                    push_wiped(&mut raw, &chunk);
                }
                Ok(None) => break,
                Err(error) => return (failed(&error), empty),
            }
        }
        let headers = reply_headers(response.headers(), secret);
        let body = strip(secret, &raw);
        let status = response.status().as_u16();
        (Outcome::Answered { status, headers }, body)
    }

    /// Sends a call whose shape streams ([`crate::Shape::streams`]) and
    /// writes its reply to `writer` as it comes: the header, then the body in
    /// chunks [`KeyWatch`] has cleared, then the end. The body is never
    /// changed: one that holds a form of the key is cut, never stripped. So
    /// the key stays until the last chunk is checked. `checked` is the call's
    /// [`CallHeader::check`]. Each write has `deadline`; a daemon that takes
    /// longer is gone, and the reply is dropped.
    pub(crate) async fn stream<W: AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        checked: Result<Url, Refusal>,
        body: &[u8],
        secret: &[u8],
        writer: &mut W,
        deadline: Duration,
    ) {
        let _ = self
            .stream_to(call, checked, body, secret, writer, deadline)
            .await;
    }

    async fn stream_to<W: AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        checked: Result<Url, Refusal>,
        body: &[u8],
        secret: &[u8],
        writer: &mut W,
        deadline: Duration,
    ) -> io::Result<()> {
        let header = |outcome| ReplyHeader {
            version: PROTOCOL_VERSION,
            call: call.call.clone(),
            digest: call.digest.clone(),
            outcome,
        };
        let reached = match checked {
            Ok(url) => self.reach(call, url, body, secret).await,
            Err(reason) => Err(Outcome::Refused { reason }),
        };
        let mut response = match reached {
            Ok(response) => response,
            Err(outcome) => {
                within(deadline, write_stream_header(writer, &header(outcome))).await?;
                return within(deadline, write_stream_end(writer, None)).await;
            }
        };
        let answered = Outcome::Answered {
            status: response.status().as_u16(),
            headers: reply_headers(response.headers(), secret),
        };
        within(deadline, write_stream_header(writer, &header(answered))).await?;
        let mut watch = KeyWatch::new(secret);
        let mut cleared = Zeroizing::new(Vec::new());
        let mut read = 0_usize;
        let cut = loop {
            let (next, last) = match response.chunk().await {
                Ok(Some(chunk)) if read + chunk.len() > MAX_STREAM => {
                    break Some(Failure::ReplyTooLarge);
                }
                Ok(Some(chunk)) => {
                    read += chunk.len();
                    (watch.push(&chunk), false)
                }
                Ok(None) => (watch.finish(), true),
                Err(error) => break Some(failure(&error)),
            };
            let Ok(passed) = next else {
                break Some(Failure::ReplyHoldsKey);
            };
            push_wiped(&mut cleared, &passed);
            // Whole chunks as they fill; at the end, the rest too.
            let mut sent = 0;
            while cleared.len() - sent >= STREAM_CHUNK || (last && sent < cleared.len()) {
                let end = cleared.len().min(sent + STREAM_CHUNK);
                within(deadline, write_chunk(writer, &cleared[sent..end])).await?;
                sent = end;
            }
            if last {
                break None;
            }
            if sent > 0 {
                cleared = Zeroizing::new(cleared[sent..].to_vec());
            }
        };
        within(deadline, write_stream_end(writer, cut)).await
    }

    /// Sends the request once with the key, and for a shape that follows one
    /// redirect, follows it once: only to the row's path under the call's own
    /// origin, and without the key or the call's headers. Returns the
    /// response whose body is the reply, or the outcome that ends the call
    /// before one.
    async fn reach(
        &self,
        call: &CallHeader,
        url: Url,
        body: &[u8],
        secret: &[u8],
    ) -> Result<reqwest::Response, Outcome> {
        let request = self
            .request(call, url.clone(), body, secret)
            .map_err(|reason| Outcome::Refused { reason })?;
        let mut response = match self.client.execute(request).await {
            Ok(response) => response,
            // A connect error comes before any request byte is written.
            Err(error) if error.is_connect() => {
                return Err(Outcome::Refused {
                    reason: Refusal::Connect,
                });
            }
            Err(error) => return Err(failed(&error)),
        };
        if let Some(prefix) = call.shape.redirect()
            && response.status().is_redirection()
        {
            let redirected = Outcome::Failed {
                reason: Failure::Redirect,
            };
            let expected = format!("{}{prefix}{}", call.origin, call.path);
            let target = response
                .headers()
                .get(LOCATION)
                .and_then(|location| location.to_str().ok())
                .and_then(|location| url.join(location).ok())
                .filter(|target| target.as_str() == expected)
                .ok_or_else(|| redirected.clone())?;
            drop(response);
            let follow = self
                .client
                .get(target)
                .header(ACCEPT_ENCODING, "identity")
                .build()
                .map_err(|_| redirected.clone())?;
            response = self
                .client
                .execute(follow)
                .await
                .map_err(|error| failed(&error))?;
            if response.status().is_redirection() {
                return Err(redirected);
            }
        }
        if encoded(response.headers()) {
            return Err(Outcome::Failed {
                reason: Failure::ReplyEncoded,
            });
        }
        Ok(response)
    }

    fn request(
        &self,
        call: &CallHeader,
        url: Url,
        body: &[u8],
        secret: &[u8],
    ) -> Result<reqwest::Request, Refusal> {
        // Only a key the strip rule is sure to find in a reply: ASCII, so no
        // key byte hides inside a multibyte one, in the rule's own alphabet.
        if secret.len() < MIN_SECRET || secret.len() > MAX_SECRET || !admits(secret) {
            return Err(Refusal::Secret);
        }
        let mut auth = Zeroizing::new(call.shape.auth_prefix().as_bytes().to_vec());
        auth.extend_from_slice(secret);
        let mut auth = HeaderValue::from_bytes(&auth).map_err(|_| Refusal::Secret)?;
        auth.set_sensitive(true);
        let method = Method::from_bytes(call.method.as_bytes()).map_err(|_| Refusal::Method)?;
        let mut builder = self
            .client
            .request(method, url)
            .header(ACCEPT_ENCODING, "identity")
            .header(call.shape.auth_header(), auth);
        for (name, value) in &call.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        // A bodyless read or removal sends no body, not an empty one.
        if !body.is_empty() {
            builder = builder.body(body.to_vec());
        }
        builder.build().map_err(|_| Refusal::Header)
    }
}

/// Whether the body arrives under a coding the HTTP stack did not undo, so
/// the strip would read encoded bytes: any content coding but `identity`, or
/// any transfer coding but `chunked`, in any value of either header.
fn encoded(headers: &HeaderMap) -> bool {
    let other = |name: reqwest::header::HeaderName, plain: &[&str]| {
        headers.get_all(name).iter().any(|value| {
            !value.to_str().is_ok_and(|codings| {
                codings.split(',').all(|coding| {
                    plain
                        .iter()
                        .any(|plain| coding.trim().eq_ignore_ascii_case(plain))
                })
            })
        })
    };
    other(CONTENT_ENCODING, &["identity"]) || other(TRANSFER_ENCODING, &["chunked"])
}

fn failed(error: &reqwest::Error) -> Outcome {
    Outcome::Failed {
        reason: failure(error),
    }
}

fn failure(error: &reqwest::Error) -> Failure {
    if error.is_timeout() {
        Failure::Timeout
    } else {
        Failure::Send
    }
}

/// One write to the daemon, within `deadline`.
async fn within(deadline: Duration, write: impl Future<Output = io::Result<()>>) -> io::Result<()> {
    tokio::time::timeout(deadline, write)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Appends `chunk`, growing into a fresh buffer when full so the old one is
/// wiped as it drops instead of freed with reply bytes in it.
pub(crate) fn push_wiped(buffer: &mut Zeroizing<Vec<u8>>, chunk: &[u8]) {
    let needed = buffer.len() + chunk.len();
    if needed > buffer.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(buffer.capacity() * 2)));
        grown.extend_from_slice(buffer);
        *buffer = grown;
    }
    buffer.extend_from_slice(chunk);
}

/// The reply's headers, each value stripped. A header whose name holds the
/// key is dropped whole, and so is any past the bounds.
fn reply_headers(headers: &reqwest::header::HeaderMap, secret: &[u8]) -> Vec<(String, String)> {
    let mut kept = Vec::new();
    let mut size = 0;
    for (name, value) in headers {
        if contains_key(secret, name.as_str().as_bytes()) {
            continue;
        }
        let value = strip(secret, value.as_bytes());
        let value = String::from_utf8_lossy(&value).into_owned();
        size += name.as_str().len() + value.len();
        if kept.len() == MAX_REPLY_HEADERS || size > MAX_REPLY_HEADER_BYTES {
            break;
        }
        kept.push((name.as_str().to_owned(), value));
    }
    kept
}
