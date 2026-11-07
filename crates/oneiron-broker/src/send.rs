//! The broker's one send: verified TLS, no redirect, no retry, no proxy, and
//! no content encoding, so the reply it strips is the reply the daemon reads.
//! The one exception to "no redirect" is a shape row's own: one hop, to the
//! path the row names under the same origin (scheme, host and port), with
//! the key, which goes back only to the host it was already sent to. The one
//! exception to "no retry" is a gzip-sent body answered 400 or 415: it goes
//! once more, plain, with the exact checked bytes, before any redirect
//! follow or reply guard (OF-603).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use reqwest::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap, HeaderValue, LOCATION, TRANSFER_ENCODING,
};
use reqwest::{Certificate, Client, Method, Url};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::frame::dispatch::{DispatchPoint, request_dispatch};
use zeroize::Zeroizing;

use crate::deadline::{CallDeadline, within};
use crate::frame::{STREAM_CHUNK, write_chunk, write_reply, write_stream_end, write_stream_header};
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
    /// The send's time limit. A call's deadline is this and one frame
    /// allowance from the moment the broker accepts it: the wait for a slot,
    /// the frame read and the send, to the last reply byte, end within this
    /// much of it (FIX 8559).
    pub timeout: Duration,
    /// Extra trust anchors (PEM) for a self-hosted provider's private CA,
    /// beside the WebPKI and the platform roots.
    pub extra_roots: Vec<Vec<u8>>,
}

/// The client every call of one broker sends through.
pub(crate) struct Sender {
    client: Client,
    /// The client a git exchange sends through: the same verified TLS and
    /// the same no-redirect, no-retry, no-proxy, no-decoding rules, and no
    /// timer of its own, so each exchange's idle bound times its connect
    /// and its send (OSH-3), never a model send's timeout.
    git: Client,
    ws_tls: Arc<rustls::ClientConfig>,
    /// [`SendPolicy::timeout`].
    timeout: Duration,
    /// Whether gzip request bodies still go: on, until a gzip-sent body is
    /// answered 400 or 415 and its one plain resend answers differently —
    /// the encoding was the cause, so this process sends plain from then
    /// on, as the daemon's provider leg latches off (OF-603).
    gzip: AtomicBool,
}

impl Sender {
    pub(crate) fn new(policy: &SendPolicy) -> io::Result<Self> {
        let client = client_builder(policy)?
            .connect_timeout(policy.timeout.min(Duration::from_secs(30)))
            .timeout(policy.timeout)
            .build()
            .map_err(io::Error::other)?;
        let git = client_builder(policy)?.build().map_err(io::Error::other)?;
        let ws_tls = ws_client_config(&policy.extra_roots)?;
        Ok(Self {
            client,
            git,
            ws_tls,
            timeout: policy.timeout,
            gzip: AtomicBool::new(true),
        })
    }

    /// The deadline of a call accepted now.
    pub(crate) fn deadline(&self) -> CallDeadline {
        CallDeadline::start(self.timeout)
    }

    /// The verified client a git exchange sends through, under its own
    /// idle bound, never this policy's timeout.
    pub(crate) fn git_client(&self) -> &Client {
        &self.git
    }

    /// Sends `body` to `url` once with the key in the shape's auth header,
    /// then strips the key from what came back. `call` has passed
    /// [`CallHeader::check`] on `body`. The send ends by `deadline`'s send
    /// limit.
    pub(crate) async fn send<W: AsyncRead + AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        url: Url,
        body: Zeroizing<Vec<u8>>,
        secret: &[u8],
        writer: &mut W,
        released: bool,
        deadline: CallDeadline,
    ) -> (Outcome, Zeroizing<Vec<u8>>) {
        let empty = Zeroizing::new(Vec::new());
        let mut response = match self
            .reach(
                call,
                url,
                body,
                secret,
                released.then_some(&mut *writer),
                released,
                deadline,
            )
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => {
                return (
                    Outcome::Failed {
                        reason: Failure::Send,
                    },
                    empty,
                );
            }
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
                    if push_wiped(&mut raw, &chunk).is_err() {
                        return (
                            Outcome::Failed {
                                reason: Failure::Send,
                            },
                            empty,
                        );
                    }
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
    /// chunks [`KeyWatch`] has released, then the end. Each form of the key
    /// in the body is replaced at its bytes as the buffered strip replaces
    /// it, and the stream goes on (FIX 6103): nothing is cut for holding the
    /// key. So the key stays until the last chunk is read. `checked` is the call's
    /// [`CallHeader::check`]. The send ends by `deadline`'s send limit, and
    /// each write within its frame allowance and the deadline; a daemon that
    /// takes longer is gone, and the reply is dropped.
    pub(crate) async fn stream<W: AsyncRead + AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        checked: Result<Url, Refusal>,
        body: Zeroizing<Vec<u8>>,
        whole: Option<Zeroizing<Vec<u8>>>,
        released: bool,
        secret: &[u8],
        writer: &mut W,
        deadline: CallDeadline,
    ) {
        let _ = self
            .stream_to(
                call, checked, body, whole, released, secret, writer, deadline,
            )
            .await;
    }

    async fn stream_to<W: AsyncRead + AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        checked: Result<Url, Refusal>,
        body: Zeroizing<Vec<u8>>,
        whole: Option<Zeroizing<Vec<u8>>>,
        released: bool,
        secret: &[u8],
        writer: &mut W,
        deadline: CallDeadline,
    ) -> io::Result<()> {
        if call.shape == crate::Shape::OpenAiResponses {
            return crate::responses::responses_to(
                &self.ws_tls,
                call,
                checked,
                body,
                whole,
                released,
                secret,
                writer,
                deadline,
            )
            .await;
        }
        let reached = match checked {
            Ok(url) => {
                self.reach(
                    call,
                    url,
                    body,
                    secret,
                    Some(&mut *writer),
                    released,
                    deadline,
                )
                .await
            }
            Err(reason) => Err(Outcome::Refused { reason }),
        };
        let response = match reached {
            Ok(Some(response)) => response,
            Ok(None) => return Ok(()),
            Err(outcome) => return answer(writer, call, outcome, deadline).await,
        };
        if call.shape.relays_events() {
            // HTTP release checks finish before this header/body phase.
            let (mut reading, mut writing) = tokio::io::split(writer);
            while_daemon_waits(
                Some(&mut reading),
                stream_reply_to(&mut writing, call, response, secret, deadline),
            )
            .await
            .unwrap_or(Ok(()))
        } else {
            stream_reply_to(writer, call, response, secret, deadline).await
        }
    }

    /// Sends the request once with the key, and for a shape that follows one
    /// redirect, follows it once: only to the row's path under the call's own
    /// origin, with the key but none of the call's other headers. A gzip-sent
    /// body answered 400 or 415 goes once more, plain, with the exact checked
    /// bytes; when that answer differs the encoding was the cause and gzip
    /// turns off for this process. Any other answer stands, and a send that
    /// never reached the provider is never resent. Returns the response whose
    /// body is the reply, or the outcome that ends the call before one. Each
    /// request gets only the send's time left, to the last reply byte; a call
    /// with none left is not sent (FIX 8559).
    async fn reach<W: AsyncRead + AsyncWrite + Unpin>(
        &self,
        call: &CallHeader,
        url: Url,
        body: Zeroizing<Vec<u8>>,
        secret: &[u8],
        mut release: Option<&mut W>,
        released: bool,
        deadline: CallDeadline,
    ) -> Result<Option<reqwest::Response>, Outcome> {
        let timed_out = || Outcome::Failed {
            reason: Failure::Timeout,
        };
        let left = deadline.send_left().ok_or_else(timed_out)?;
        let (mut request, plain) = self
            .request(call, url.clone(), body, secret, left)
            .map_err(|reason| Outcome::Refused { reason })?;
        if released && let Some(stream) = release.as_deref_mut() {
            release_http_send(stream, call, DispatchPoint::Initial, deadline).await?;
            *request.timeout_mut() = Some(deadline.send_left().ok_or_else(timed_out)?);
        }
        let Some(executed) = while_daemon_waits(
            if call.shape.relays_events() {
                release.as_deref_mut()
            } else {
                None
            },
            self.client.execute(request),
        )
        .await
        else {
            return Ok(None);
        };
        let mut response = match executed {
            Ok(response) => response,
            // A connect error comes before any request byte is written.
            Err(error) if error.is_connect() => {
                return Err(Outcome::Refused {
                    reason: Refusal::Connect,
                });
            }
            Err(error) => return Err(failed(&error)),
        };
        // OF-603: the route may not decode gzip, so a gzip-sent body answered
        // 400 or 415 goes once more, plain. Ahead of the redirect follow and
        // the reply guards, so those read the final response.
        if let Some(plain) = plain
            && matches!(response.status().as_u16(), 400 | 415)
        {
            let refused = response.status();
            drop(response);
            let left = deadline.send_left().ok_or_else(timed_out)?;
            let mut resend = self
                .request_plain(call, url.clone(), plain, secret, left)
                .map_err(|_| Outcome::Failed {
                    reason: Failure::Send,
                })?;
            if released && let Some(stream) = release.as_deref_mut() {
                release_http_send(stream, call, DispatchPoint::PlainRetry, deadline).await?;
                *resend.timeout_mut() = Some(deadline.send_left().ok_or_else(timed_out)?);
            }
            // The first 400 or 415 proves bytes reached the provider, so a
            // resend that fails is `Failed`, never `Refused{Connect}`.
            let Some(executed) = while_daemon_waits(
                if call.shape.relays_events() {
                    release.as_deref_mut()
                } else {
                    None
                },
                self.client.execute(resend),
            )
            .await
            else {
                return Ok(None);
            };
            response = executed.map_err(|error| failed(&error))?;
            if response.status() != refused {
                self.gzip.store(false, Ordering::Relaxed);
                eprintln!(
                    "oneiron-broker: a provider refused a gzip request body with status {}; sending plain from now on",
                    refused.as_u16()
                );
            }
        }
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
                .filter(|target| target.origin() == url.origin() && target.as_str() == expected)
                .ok_or_else(|| redirected.clone())?;
            drop(response);
            // The same scheme, host and port the key was just sent to, so
            // the key goes along: the provider's download hop asks for it.
            let auth = auth_value(call, secret).map_err(|reason| Outcome::Refused { reason })?;
            let left = deadline.send_left().ok_or_else(timed_out)?;
            let mut follow = self
                .client
                .get(target)
                .header(ACCEPT_ENCODING, "identity")
                .header(call.shape.auth_header(), auth)
                .timeout(left)
                .build()
                .map_err(|_| redirected.clone())?;
            if released && let Some(stream) = release.as_deref_mut() {
                release_http_send(stream, call, DispatchPoint::Redirect, deadline).await?;
                *follow.timeout_mut() = Some(deadline.send_left().ok_or_else(timed_out)?);
            }
            let Some(executed) = while_daemon_waits(
                if call.shape.relays_events() {
                    release.as_deref_mut()
                } else {
                    None
                },
                self.client.execute(follow),
            )
            .await
            else {
                return Ok(None);
            };
            response = executed.map_err(|error| failed(&error))?;
            if response.status().is_redirection() {
                return Err(redirected);
            }
        }
        if encoded(response.headers()) {
            return Err(Outcome::Failed {
                reason: Failure::ReplyEncoded,
            });
        }
        Ok(Some(response))
    }

    /// Builds the request, and the checked plain body when it goes gzip-sent:
    /// what the one plain resend carries if a 400 or 415 answers.
    fn request(
        &self,
        call: &CallHeader,
        url: Url,
        mut body: Zeroizing<Vec<u8>>,
        secret: &[u8],
        left: Duration,
    ) -> Result<(reqwest::Request, Option<Zeroizing<Vec<u8>>>), Refusal> {
        let builder = self.head(call, url, secret, left)?;
        // A bodyless read or removal sends no body, not an empty one.
        if body.is_empty() {
            return builder
                .build()
                .map(|request| (request, None))
                .map_err(|_| Refusal::Header);
        }
        // OF-603: past the plaintext checks and the digest binding.
        match self.compressed(call, &body) {
            Some(encoded) => builder
                .header(CONTENT_ENCODING, "gzip")
                .body(encoded)
                .build()
                .map(|request| (request, Some(body)))
                .map_err(|_| Refusal::Header),
            // The checked bytes themselves, moved, not copied: a body
            // can run to `MAX_STREAM` (FIX 1895).
            None => builder
                .body(std::mem::take(&mut *body))
                .build()
                .map(|request| (request, None))
                .map_err(|_| Refusal::Header),
        }
    }

    /// The request's head — method, timeout, identity accept, the shape's
    /// auth and the call's headers — shared by the first send and its one
    /// plain resend, so the two are identical but for the encoding.
    fn head(
        &self,
        call: &CallHeader,
        url: Url,
        secret: &[u8],
        left: Duration,
    ) -> Result<reqwest::RequestBuilder, Refusal> {
        let auth = auth_value(call, secret)?;
        let method = Method::from_bytes(call.method.as_bytes()).map_err(|_| Refusal::Method)?;
        let mut builder = self
            .client
            .request(method, url)
            .timeout(left)
            .header(ACCEPT_ENCODING, "identity")
            .header(call.shape.auth_header(), auth);
        for (name, value) in &call.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        Ok(builder)
    }

    /// The identical request without `Content-Encoding`, carrying the exact
    /// checked plain bytes: the one resend when a gzip-sent body is answered
    /// 400 or 415. It always carries a body: gzip applies only past
    /// [`MIN_COMPRESSED_BODY`].
    fn request_plain(
        &self,
        call: &CallHeader,
        url: Url,
        mut body: Zeroizing<Vec<u8>>,
        secret: &[u8],
        left: Duration,
    ) -> Result<reqwest::Request, Refusal> {
        let builder = self.head(call, url, secret, left)?;
        // Moved, not copied, as the first send moves them.
        builder
            .body(std::mem::take(&mut *body))
            .build()
            .map_err(|_| Refusal::Header)
    }

    /// `body` as gzip-1, just before send: only for Anthropic's Messages API
    /// at [`GZIP_ORIGIN`], a body of at least [`MIN_COMPRESSED_BODY`], and
    /// an encoding that is smaller. Never on a cloud node
    /// ([`CallHeader::cloud`]), where gzip costs more on the link than it
    /// saves, and never once a route has refused one and latched the process
    /// plain. The call is checked and its digest bound to the plain bytes
    /// already; the reply still arrives identity, so the strip reads plain
    /// bytes.
    fn compressed(&self, call: &CallHeader, body: &[u8]) -> Option<Vec<u8>> {
        if !self.gzip.load(Ordering::Relaxed)
            || call.cloud
            || call.shape != crate::Shape::AnthropicMessages
            || call.origin != GZIP_ORIGIN
            || body.len() < MIN_COMPRESSED_BODY
        {
            return None;
        }
        let sink = crate::body::FallibleBody::with_capacity(body.len() / 2).ok()?;
        let mut encoder = flate2::write::GzEncoder::new(sink, flate2::Compression::new(1));
        io::Write::write_all(&mut encoder, body).ok()?;
        let encoded = encoder.finish().ok()?.into_bytes();
        (encoded.len() < body.len()).then_some(encoded)
    }
}

async fn stream_reply_to<W: AsyncWrite + Unpin>(
    writer: &mut W,
    call: &CallHeader,
    mut response: reqwest::Response,
    secret: &[u8],
    deadline: CallDeadline,
) -> io::Result<()> {
    let answered = Outcome::Answered {
        status: response.status().as_u16(),
        headers: reply_headers(response.headers(), secret),
    };
    let header = reply(call, answered);
    within(deadline, write_stream_header(writer, &header)).await?;
    let mut watch = KeyWatch::new(secret);
    let mut cleared = Zeroizing::new(Vec::new());
    let mut read = 0_usize;
    // Relayed events go on as soon as the watch clears them, a frame at
    // most at a time; other streamed bodies go in whole frames (FIX
    // 15702). The watch still holds back any bytes that could begin a
    // form of the key.
    let eager = call.shape.relays_events();
    let cut = loop {
        let (passed, last) = match response.chunk().await {
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
        if push_wiped(&mut cleared, &passed).is_err() {
            break Some(Failure::Send);
        }
        // Whole chunks as they fill; at the end, the rest too.
        let mut sent = 0;
        while cleared.len() - sent >= STREAM_CHUNK || ((last || eager) && sent < cleared.len()) {
            let end = cleared.len().min(sent + STREAM_CHUNK);
            within(deadline, write_chunk(writer, &cleared[sent..end])).await?;
            sent = end;
        }
        if last {
            break None;
        }
        if sent > 0 {
            let mut remainder = Zeroizing::new(Vec::new());
            if push_wiped(&mut remainder, &cleared[sent..]).is_err() {
                break Some(Failure::Send);
            }
            cleared = remainder;
        }
    };
    within(deadline, write_stream_end(writer, cut)).await
}

/// Watches the existing close/input signal only between release handshakes.
async fn while_daemon_waits<R, F>(reading: Option<&mut R>, work: F) -> Option<F::Output>
where
    R: AsyncRead + Unpin,
    F: std::future::Future,
{
    let Some(reading) = reading else {
        return Some(work.await);
    };
    let mut byte = [0_u8; 1];
    tokio::select! {
        biased;
        result = work => Some(result),
        _ = reading.read(&mut byte) => None,
    }
}

async fn release_http_send<W: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut W,
    call: &CallHeader,
    point: DispatchPoint,
    deadline: CallDeadline,
) -> Result<(), Outcome> {
    let failure = |reason| Outcome::Failed { reason };
    tokio::time::timeout_at(deadline.send_by(), request_dispatch(stream, call, point))
        .await
        .map_err(|_| failure(Failure::Timeout))?
        .map_err(|error| {
            failure(if error.kind() == io::ErrorKind::TimedOut {
                Failure::Timeout
            } else {
                Failure::Send
            })
        })?;
    deadline
        .send_left()
        .ok_or_else(|| failure(Failure::Timeout))?;
    Ok(())
}

/// The rules every client of the broker shares: rustls with the WebPKI, the
/// platform and the policy's private-CA roots, `https` only, no redirect,
/// no retry, no proxy and no automatic decoding.
fn client_builder(policy: &SendPolicy) -> io::Result<reqwest::ClientBuilder> {
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
        .no_zstd();
    for pem in &policy.extra_roots {
        for root in Certificate::from_pem_bundle(pem).map_err(io::Error::other)? {
            builder = builder.add_root_certificate(root);
        }
    }
    Ok(builder)
}

/// Uses the HTTPS sender's WebPKI, platform and configured private-CA trust.
/// The HTTPS client has already validated every configured PEM bundle.
fn ws_client_config(extra_roots: &[Vec<u8>]) -> io::Result<Arc<rustls::ClientConfig>> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    for pem in extra_roots {
        for cert in CertificateDer::pem_reader_iter(io::BufReader::new(pem.as_slice())) {
            let cert = cert.map_err(io::Error::other)?;
            roots.add(cert).map_err(io::Error::other)?;
        }
    }
    // Match reqwest: respect an installed provider, otherwise use ring.
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The origin whose Messages API takes a gzip request body (ARCH-0081 §6).
const GZIP_ORIGIN: &str = "https://api.anthropic.com";
/// The smallest request body worth compressing.
const MIN_COMPRESSED_BODY: usize = 16 << 10;

/// Whether `secret` is a key the strip rule is sure to find in a reply:
/// long enough, short enough, ASCII in the rule's own alphabet.
pub(crate) fn watchable(secret: &[u8]) -> bool {
    secret.len() >= MIN_SECRET && secret.len() <= MAX_SECRET && admits(secret)
}

/// Whether a git credential's watched token is one the broker sends: any
/// bytes, up to [`MAX_SECRET`]. The git reply's echo watch searches the
/// token's literal forms and never rewrites a reply, which every byte
/// supports, so a Basic password with a `%`, or one shorter than a model
/// key, goes as it did before the broker ([`git_echo_form`] says which
/// forms a short one is watched by).
pub(crate) fn git_watchable(token: &[u8]) -> bool {
    !token.is_empty() && token.len() <= MAX_SECRET
}

/// The literal forms of a git credential's `token` the git reply watch
/// searches for, in its headers and its body: each of at least
/// [`git_echo_form`]'s length.
pub(crate) fn git_echo_forms(token: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut forms = crate::strip::forms(token);
    forms.extend(crate::strip::base64_forms(token));
    forms.retain(|form| git_echo_form(form));
    forms
}

/// A git reply's headers as the daemon gets them: each one whose name or
/// value holds one of `forms` ([`git_echo_forms`]) is left out whole, and
/// every other passes byte for byte, under the model reply's count and byte
/// bounds. Nothing is rewritten: the model strip would redact a short
/// token's text inside git's own values (a password `git` in
/// `application/x-git-upload-pack-advertisement`), and Git would not know
/// the reply.
pub(crate) fn git_reply_headers(
    headers: &reqwest::header::HeaderMap,
    forms: &[Zeroizing<Vec<u8>>],
) -> Vec<(String, String)> {
    let holds = |bytes: &[u8]| {
        forms
            .iter()
            .any(|form| memchr::memmem::find(bytes, form).is_some())
    };
    let mut kept = Vec::new();
    let mut size = 0;
    for (name, value) in headers {
        if holds(name.as_str().as_bytes()) || holds(value.as_bytes()) {
            continue;
        }
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        size += name.as_str().len() + value.len();
        if kept.len() == MAX_REPLY_HEADERS || size > MAX_REPLY_HEADER_BYTES {
            break;
        }
        kept.push((name.as_str().to_owned(), value));
    }
    kept
}

/// Whether the git echo watch searches a reply for `form`, one literal form
/// of a git credential's token: one of at least a model key's least length.
/// A shorter one would be found among a pack's bytes by chance and cut a
/// clean reply, so a short token is watched by its longer forms alone (its
/// `Bearer`, percent and base64 forms).
pub(crate) fn git_echo_form(form: &[u8]) -> bool {
    form.len() >= MIN_SECRET
}

/// The shape's key header value for `secret`, marked sensitive.
pub(crate) fn auth_value(call: &CallHeader, secret: &[u8]) -> Result<HeaderValue, Refusal> {
    // Only a key the strip rule is sure to find in a reply: ASCII, so no key
    // byte hides inside a multibyte one, in the rule's own alphabet.
    if !watchable(secret) {
        return Err(Refusal::Secret);
    }
    let mut auth = Zeroizing::new(call.shape.auth_prefix().as_bytes().to_vec());
    auth.extend_from_slice(secret);
    let mut auth = HeaderValue::from_bytes(&auth).map_err(|_| Refusal::Secret)?;
    auth.set_sensitive(true);
    Ok(auth)
}

/// Whether the body arrives under a coding the HTTP stack did not undo, so
/// the strip would read encoded bytes: any content coding but `identity`, or
/// any transfer coding but `chunked`, in any value of either header.
pub(crate) fn encoded(headers: &HeaderMap) -> bool {
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

/// The reply header that answers `call` with `outcome`.
fn reply(call: &CallHeader, outcome: Outcome) -> ReplyHeader {
    ReplyHeader {
        version: PROTOCOL_VERSION,
        call: call.call.clone(),
        digest: call.digest.clone(),
        outcome,
    }
}

/// Answers `call` with `outcome` and no body, in its shape's reply form: one
/// segment, or a stream that ends clean at once. Each write is within its
/// frame allowance and `deadline`.
pub(crate) async fn answer<W: AsyncWrite + Unpin>(
    writer: &mut W,
    call: &CallHeader,
    outcome: Outcome,
    deadline: CallDeadline,
) -> io::Result<()> {
    let header = reply(call, outcome);
    if call.shape.streams() {
        within(deadline, write_stream_header(writer, &header)).await?;
        within(deadline, write_stream_end(writer, None)).await
    } else {
        within(deadline, write_reply(writer, &header, &[])).await
    }
}

/// Appends `chunk`, growing into a fresh buffer when full so the old one is
/// wiped as it drops instead of freed with reply bytes in it.
pub(crate) fn push_wiped(buffer: &mut Zeroizing<Vec<u8>>, chunk: &[u8]) -> io::Result<()> {
    let needed = buffer
        .len()
        .checked_add(chunk.len())
        .ok_or(io::ErrorKind::OutOfMemory)?;
    if needed > buffer.capacity() {
        let mut grown = Zeroizing::new(Vec::new());
        grown
            .try_reserve_exact(needed.max(buffer.capacity().saturating_mul(2)))
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        grown.extend_from_slice(buffer);
        *buffer = grown;
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

/// The reply's headers, each value stripped. A header whose name holds the
/// key is dropped whole, and so is any past the bounds.
pub(crate) fn reply_headers(
    headers: &reqwest::header::HeaderMap,
    secret: &[u8],
) -> Vec<(String, String)> {
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
