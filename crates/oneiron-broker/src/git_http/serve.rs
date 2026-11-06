//! The broker's side of a git exchange, from its header on (see the parent
//! module's steps): spool and check the body, acknowledge, take the
//! credential, send once, and relay the reply exactly as it came.

use std::future::Future;
use std::io::{self, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, USER_AGENT,
};
use reqwest::{Body, Client, Method, Url};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::{GitCallHeader, GitExchange, GitPrepared, GitRequestDigest};
use crate::deadline::FAR_FUTURE;
use crate::frame::{
    STREAM_CHUNK, read_chunk, read_segment, write_chunk, write_segment, write_stream_end,
    write_stream_header,
};
use crate::send::{Sender, encoded, push_wiped, reply_headers, watchable};
use crate::{Failure, MAX_SECRET, Outcome, PROTOCOL_VERSION, Refusal, ReplyHeader};

/// The user agent of a git exchange: a smart-HTTP server serves its smart
/// protocol to a `git/` agent.
const GIT_USER_AGENT: &str = "git/oneiron-broker";

/// How much of the spool one read takes as it streams to the repository.
const SPOOL_READ: usize = 64 << 10;

/// Serves one git exchange whose header the frame opened with. The
/// connection is closed at the end; a broken one ends the exchange where it
/// broke, and nothing is sent once the daemon is gone.
pub(crate) async fn serve_git(mut stream: UnixStream, header: GitCallHeader, sender: &Sender) {
    let _ = exchange(&mut stream, &header, sender).await;
}

async fn exchange(
    stream: &mut UnixStream,
    header: &GitCallHeader,
    sender: &Sender,
) -> io::Result<()> {
    let client = sender.git_client();
    let idle = header.idle();
    let prepared = match header.check() {
        Ok(url) => spool(stream, header, idle).await?.map(|spool| (url, spool)),
        Err(reason) => {
            drain(stream, idle).await?;
            Err(reason)
        }
    };
    let (url, spool) = match prepared {
        Ok(prepared) => prepared,
        Err(reason) => return acknowledge(stream, header, Some(reason), idle).await,
    };
    acknowledge(stream, header, None, idle).await?;
    let secret = idle_bound(idle, read_segment(stream, MAX_SECRET)).await?;
    let credential = match git_credential(&secret) {
        Ok(credential) => credential,
        Err(reason) => return answer(stream, header, Outcome::Refused { reason }, idle).await,
    };
    drop(secret);
    let progress = Arc::new(AtomicU64::new(0));
    let body = (header.target.exchange == GitExchange::Rpc)
        .then(|| (spool.len, spool_body(spool, Arc::clone(&progress))));
    let request = match request(client, header, url, body, &credential) {
        Ok(request) => request,
        Err(reason) => return answer(stream, header, Outcome::Refused { reason }, idle).await,
    };
    let mut response = match send(client, request, stream, &progress, idle).await {
        Sent::Response(response) => response,
        Sent::Outcome(outcome) => return answer(stream, header, outcome, idle).await,
        Sent::Cancelled => return Ok(()),
    };
    if encoded(response.headers()) {
        let outcome = Outcome::Failed {
            reason: Failure::ReplyEncoded,
        };
        return answer(stream, header, outcome, idle).await;
    }
    let answered = Outcome::Answered {
        status: response.status().as_u16(),
        headers: reply_headers(response.headers(), &credential.watched),
    };
    idle_bound(idle, write_stream_header(stream, &reply(header, answered))).await?;
    let cut = relay(&mut response, stream, &credential.watched, idle).await?;
    idle_bound(idle, write_stream_end(stream, cut)).await
}

/// One step on the daemon's socket, within `idle`.
async fn idle_bound<T>(idle: Duration, step: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(idle, step)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// A body held for its one send: a private unnamed file, rewound, of the
/// header's length and digest.
struct Spool {
    file: tokio::fs::File,
    len: u64,
}

/// Reads the body's chunks into a private unnamed file, taking its digest
/// as they pass. The body is refused when the disk has no room for it, it
/// runs past its length, or its digest is not the header's; its chunks are
/// still read to its end, so the refusal answers in turn.
async fn spool(
    stream: &mut UnixStream,
    header: &GitCallHeader,
    idle: Duration,
) -> io::Result<Result<Spool, Refusal>> {
    let file = match tempfile::tempfile() {
        Ok(file) if room_for(&file, header.body_len) => file,
        Ok(_) | Err(_) => {
            drain(stream, idle).await?;
            return Ok(Err(Refusal::Spool));
        }
    };
    let mut file = tokio::fs::File::from_std(file);
    let mut digest = GitRequestDigest::new(&header.target, &header.headers, header.body_len);
    let mut seen = 0_u64;
    let mut refused = None;
    while let Some(chunk) = idle_bound(idle, read_chunk(stream)).await? {
        if refused.is_some() {
            continue;
        }
        seen = seen.saturating_add(chunk.len() as u64);
        if seen > header.body_len {
            refused = Some(Refusal::Body);
            continue;
        }
        digest.update(&chunk);
        if file.write_all(&chunk).await.is_err() {
            refused = Some(Refusal::Spool);
        }
    }
    if let Some(reason) = refused {
        return Ok(Err(reason));
    }
    match digest.finish() {
        Ok(found) if found == header.digest => {}
        Ok(_) => return Ok(Err(Refusal::Digest)),
        Err(reason) => return Ok(Err(reason)),
    }
    if file.flush().await.is_err() || file.seek(SeekFrom::Start(0)).await.is_err() {
        return Ok(Err(Refusal::Spool));
    }
    Ok(Ok(Spool {
        file,
        len: header.body_len,
    }))
}

/// Whether the disk under `file` has room for `len` more bytes.
fn room_for(file: &std::fs::File, len: u64) -> bool {
    rustix::fs::fstatvfs(file).is_ok_and(|stat| stat.f_bavail.saturating_mul(stat.f_frsize) >= len)
}

/// Reads a refused body's chunks to its end, keeping none.
async fn drain(stream: &mut UnixStream, idle: Duration) -> io::Result<()> {
    while idle_bound(idle, read_chunk(stream)).await?.is_some() {}
    Ok(())
}

/// Answers the header and body: prepared, or refused.
async fn acknowledge(
    stream: &mut UnixStream,
    header: &GitCallHeader,
    refused: Option<Refusal>,
    idle: Duration,
) -> io::Result<()> {
    let prepared = GitPrepared {
        version: PROTOCOL_VERSION,
        call: header.call.clone(),
        digest: header.digest.clone(),
        refused,
    };
    let bytes = serde_json::to_vec(&prepared).map_err(io::Error::other)?;
    idle_bound(idle, async {
        write_segment(stream, &bytes).await?;
        stream.flush().await
    })
    .await
}

/// The credential a git exchange carries: the complete `Authorization`
/// value, marked sensitive, and the token in it the reply is watched for.
struct GitCredential {
    header: HeaderValue,
    watched: Zeroizing<Vec<u8>>,
}

/// Reads `secret` as one `Authorization` value, its outer whitespace
/// trimmed: visible ASCII and spaces, a scheme, then its credentials. The
/// token watched for is the credentials, or for `Basic` the password the
/// base64 holds (its user name when the password is empty or GitHub's
/// `x-oauth-basic`). The token must be one the strip rule is sure to find.
fn git_credential(secret: &[u8]) -> Result<GitCredential, Refusal> {
    let value = secret.trim_ascii();
    if value.is_empty()
        || value.len() > MAX_SECRET
        || !value.iter().all(|byte| (0x20..0x7f).contains(byte))
    {
        return Err(Refusal::Secret);
    }
    let space = value
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(Refusal::Secret)?;
    let scheme = &value[..space];
    let credentials = value[space..].trim_ascii();
    if credentials.is_empty()
        || !scheme
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+".contains(byte))
    {
        return Err(Refusal::Secret);
    }
    let watched = if scheme.eq_ignore_ascii_case(b"basic") {
        let decoded = Zeroizing::new(STANDARD.decode(credentials).map_err(|_| Refusal::Secret)?);
        let colon = decoded
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(Refusal::Secret)?;
        let (user, password) = (&decoded[..colon], &decoded[colon + 1..]);
        let token = if password.is_empty() || password == b"x-oauth-basic" {
            user
        } else {
            password
        };
        Zeroizing::new(token.to_vec())
    } else {
        Zeroizing::new(credentials.to_vec())
    };
    if !watchable(&watched) {
        return Err(Refusal::Secret);
    }
    let mut header = HeaderValue::from_bytes(value).map_err(|_| Refusal::Secret)?;
    header.set_sensitive(true);
    Ok(GitCredential { header, watched })
}

/// The spool as the request's body, read as the send takes it; each read
/// counts as progress.
fn spool_body(spool: Spool, progress: Arc<AtomicU64>) -> Body {
    let reads = futures_util::stream::try_unfold(
        (spool.file, progress),
        |(mut file, progress)| async move {
            let mut buffer = vec![0; SPOOL_READ];
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                return Ok::<_, io::Error>(None);
            }
            buffer.truncate(read);
            progress.fetch_add(read as u64, Ordering::Relaxed);
            Ok(Some((buffer, (file, progress))))
        },
    );
    Body::wrap_stream(reads)
}

/// The exchange's request: its target's method, URL, content types and
/// agent, identity coding, the one `git-protocol` header the call may
/// carry, and the credential as the one auth header. An RPC carries its
/// spooled body at its exact length. No total timeout: the send's idle
/// bound and the daemon's hang-up end it ([`send`]).
fn request(
    client: &Client,
    header: &GitCallHeader,
    url: Url,
    body: Option<(u64, Body)>,
    credential: &GitCredential,
) -> Result<reqwest::Request, Refusal> {
    let method =
        Method::from_bytes(header.target.method().as_bytes()).map_err(|_| Refusal::Method)?;
    let mut builder = client
        .request(method, url)
        .timeout(FAR_FUTURE)
        .header(ACCEPT_ENCODING, "identity")
        .header(ACCEPT, header.target.reply_content_type())
        .header(USER_AGENT, GIT_USER_AGENT)
        .header(AUTHORIZATION, credential.header.clone());
    for (name, value) in &header.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    if let (Some(content_type), Some((len, body))) = (header.target.request_content_type(), body) {
        builder = builder
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_LENGTH, len)
            .body(body);
    }
    builder.build().map_err(|_| Refusal::Header)
}

/// How the send ended.
enum Sent {
    /// The repository answered; its body is still to come.
    Response(reqwest::Response),
    /// It ends the exchange.
    Outcome(Outcome),
    /// The daemon hung up, or wrote past its frame: the send is dropped.
    Cancelled,
}

/// Sends the request once, until its reply's head: dropped when the daemon
/// hangs up, and timed out once `idle` passes with no body byte sent.
async fn send(
    client: &Client,
    request: reqwest::Request,
    stream: &UnixStream,
    progress: &AtomicU64,
    idle: Duration,
) -> Sent {
    let execute = client.execute(request);
    tokio::pin!(execute);
    loop {
        let before = progress.load(Ordering::Relaxed);
        tokio::select! {
            sent = &mut execute => {
                return match sent {
                    Ok(response) => Sent::Response(response),
                    // A connect error comes before any request byte is written.
                    Err(error) if error.is_connect() => Sent::Outcome(Outcome::Refused {
                        reason: Refusal::Connect,
                    }),
                    Err(error) => Sent::Outcome(Outcome::Failed {
                        reason: failure(&error),
                    }),
                };
            }
            ready = stream.readable() => {
                if ready.is_err() || cancelled(stream) {
                    return Sent::Cancelled;
                }
            }
            () = tokio::time::sleep(idle) => {
                if progress.load(Ordering::Relaxed) == before {
                    return Sent::Outcome(Outcome::Failed {
                        reason: Failure::Timeout,
                    });
                }
            }
        }
    }
}

/// Whether the daemon, which sends nothing after the credential, hung up or
/// wrote past its frame. A readiness with nothing to read is neither.
fn cancelled(stream: &UnixStream) -> bool {
    let mut byte = [0; 1];
    match stream.try_read(&mut byte) {
        Ok(_) => true,
        Err(error) => error.kind() != io::ErrorKind::WouldBlock,
    }
}

fn failure(error: &reqwest::Error) -> Failure {
    if error.is_timeout() {
        Failure::Timeout
    } else {
        Failure::Send
    }
}

/// Relays the reply's body as it comes, byte for byte, in chunks of at most
/// [`STREAM_CHUNK`]. [`EchoWatch`] reads it for the literal forms of the
/// token and holds back only the bytes a form could still end in; a reply
/// that holds a form is cut before any byte of it goes. Returns how the body
/// ended: clean, or cut.
async fn relay(
    response: &mut reqwest::Response,
    stream: &mut UnixStream,
    watched: &[u8],
    idle: Duration,
) -> io::Result<Option<Failure>> {
    let mut watch = EchoWatch::new(watched);
    loop {
        let (released, last) = match tokio::time::timeout(idle, response.chunk()).await {
            Err(_) => return Ok(Some(Failure::Timeout)),
            Ok(Err(error)) => return Ok(Some(failure(&error))),
            Ok(Ok(Some(chunk))) => (watch.push(&chunk)?, false),
            Ok(Ok(None)) => (Some(watch.finish()), true),
        };
        let Some(released) = released else {
            return Ok(Some(Failure::ReplyHoldsKey));
        };
        for piece in released.chunks(STREAM_CHUNK) {
            idle_bound(idle, write_chunk(stream, piece)).await?;
        }
        if last {
            return Ok(None);
        }
    }
}

/// The git reply's credential watch: the token's literal forms (raw,
/// JSON-escaped, `Bearer`, percent-encoded, and its base64, whole and at
/// each byte offset), searched across chunk edges. Unlike the model strip,
/// it never marks a run it cannot settle: a pack or an advertisement full of
/// escapes is passed byte for byte unless a form is in it. It holds back
/// only the bytes a form could still end in.
struct EchoWatch {
    forms: Vec<Zeroizing<Vec<u8>>>,
    /// The longest form's length less one: what a form split across chunks
    /// can have shown so far.
    keep: usize,
    /// The bytes that came and are not released yet.
    held: Zeroizing<Vec<u8>>,
}

impl EchoWatch {
    fn new(token: &[u8]) -> Self {
        let mut forms = crate::strip::forms(token);
        forms.extend(crate::strip::base64_forms(token));
        forms.retain(|form| !form.is_empty());
        let keep = forms
            .iter()
            .map(|form| form.len())
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        Self {
            forms,
            keep,
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// Takes the next `chunk` and answers the bytes released with it, or
    /// `None` when a form of the token is in what came.
    fn push(&mut self, chunk: &[u8]) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        push_wiped(&mut self.held, chunk)?;
        if self
            .forms
            .iter()
            .any(|form| memchr::memmem::find(&self.held, form).is_some())
        {
            return Ok(None);
        }
        let release = self.held.len().saturating_sub(self.keep);
        let mut released = Zeroizing::new(Vec::new());
        push_wiped(&mut released, &self.held[..release])?;
        let rest = self.held.len() - release;
        self.held.copy_within(release.., 0);
        self.held.truncate(rest);
        Ok(Some(released))
    }

    /// The bytes still held once the reply ended: no form ends in them,
    /// since every form was searched as they came.
    fn finish(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::replace(&mut self.held, Zeroizing::new(Vec::new()))
    }
}

/// The reply header that answers `header` with `outcome`.
fn reply(header: &GitCallHeader, outcome: Outcome) -> ReplyHeader {
    ReplyHeader {
        version: PROTOCOL_VERSION,
        call: header.call.clone(),
        digest: header.digest.clone(),
        outcome,
    }
}

/// Answers the exchange with `outcome` and no body: a streamed reply that
/// ends clean at once.
async fn answer(
    stream: &mut UnixStream,
    header: &GitCallHeader,
    outcome: Outcome,
    idle: Duration,
) -> io::Result<()> {
    idle_bound(idle, write_stream_header(stream, &reply(header, outcome))).await?;
    idle_bound(idle, write_stream_end(stream, None)).await
}
