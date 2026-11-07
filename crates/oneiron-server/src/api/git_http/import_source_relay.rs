//! An outside import's bound source fetch through the credential broker
//! (ARCH-0069 OSH-3, FIX 15702).
//!
//! A source bound to a custody credential is read only through the broker,
//! which alone installs the credential and sends each git exchange:
//!
//! - **Probe.** The source's advertisement is asked for through the broker,
//!   one exchange per hop. A redirect that stays on the source's own https
//!   host is asked for again there; any other is the refusal naming its
//!   target, as for an anonymous source.
//! - **Fetch.** Stock Git fetches, with no credential, from a source relay
//!   of this invocation alone: a loopback listener on an OS-assigned port,
//!   serving the upload-pack advertisement and RPC of the one resolved
//!   repository. Its URL rides Git's argv, which other local users can
//!   read, so it is no capability: each request must carry the relay's
//!   random ticket in a header Git's environment holds, and anything else
//!   is not found. Each request is judged again (the call's credential not
//!   revoked, the binding still admitting this importer for this host), its
//!   body spooled to a private unnamed file, decoded from any gzip, and its
//!   digest taken; the broker gets the exchange and its body, acknowledges
//!   both, and only then is the credential read at the custody door
//!   (`origin:import-fetch`) in the one snapshot that judges the binding
//!   once more, copied once and handed to the broker. The reply streams back to Git exactly as
//!   the repository sent it; a reply the broker cut ends Git's read broken,
//!   never clean.
//!
//! No pack size or call time is bounded here: each step waits at most the
//! host's transfer idle limit without progress, and Git's exit or the
//! import's own cancel ends the relay. The relay is no public route, mints
//! no token and stops when the fetch returns. A refused exchange's code is
//! the fetch's refusal.

use std::collections::BTreeSet;
use std::future::Future;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderValue};
use axum::http::request::Parts;
use axum::response::Response;
use axum::routing::{get, post};
use futures_util::StreamExt as _;
use oneiron::EntityId;
use oneiron::git_wire::{
    GitImportFetchOutcome, GitOid, GitRefName, GitWire, SOURCE_RELAY_TICKET_HEADER,
};
use oneiron::repo_mutation::external_import::{ExternalImportSource, REDIRECT_REFUSED};
use oneiron_broker::{
    BrokerError, GitCallHeader, GitExchange, GitReply, GitRepository, GitRequestDigest, GitTarget,
    MAX_SECRET, Outcome, StreamPart, git_request_digest,
};
use tokio::io::AsyncRead;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::gate::{advertised_service, header_value, text_response};
use super::import_relay::{authority, redirected_repository, revoked};
use super::routes::GitService;
use crate::auth::CoreAuth;
use crate::models::BrokerContext;
use crate::server::SyncServer;

/// The served name every source relay path carries; it serves one repo.
const SOURCE_REPO_SEGMENT: &str = "source.git";

/// The content type of an upload-pack RPC request.
const UPLOAD_PACK_REQUEST: &str = "application/x-git-upload-pack-request";

/// How much of a spool one read takes as its digest is taken.
const SPOOL_READ: usize = 64 << 10;

/// One bound fetch's call: its server, its verified credential and that
/// credential's principal, the runtime its relay serves on, and the
/// custody secret it is bound to.
pub(super) struct SourceCall<'a> {
    pub(super) server: &'a Arc<SyncServer>,
    pub(super) auth: &'a CoreAuth,
    pub(super) importer: EntityId,
    pub(super) runtime: &'a Handle,
    pub(super) binding: &'a str,
}

/// Fetches exactly `source_ref` of the bound `source` through the broker,
/// then proves it (`GitWire::fetch_external_exact_via_relay`). `refs` is
/// the source ref, the base and the head.
///
/// # Errors
/// A relay that cannot start, or a process or store failure. A refused
/// probe, exchange, fetch or proof is an outcome.
pub(super) fn fetch_through_broker(
    call: &SourceCall<'_>,
    wire: &GitWire<'_>,
    source: &ExternalImportSource,
    (source_ref, base, head): (&GitRefName, &GitOid, &GitOid),
) -> oneiron::Result<GitImportFetchOutcome> {
    let Some(broker) = call.server.broker_context().cloned() else {
        return Ok(GitImportFetchOutcome::Refused(
            "source_broker_unavailable".to_owned(),
        ));
    };
    let mut id = [0_u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    let leg = Arc::new(SourceLeg {
        server: Arc::clone(call.server),
        auth: call.auth.clone(),
        importer: call.importer,
        binding: call.binding.to_owned(),
        origin: source.host.clone(),
        broker,
        idle: call.server.transfers.idle,
        id: id.iter().map(|byte| format!("{byte:02x}")).collect(),
        sequence: AtomicU64::new(0),
        noted: Mutex::new(None),
    });
    let resolved = match block_on(call.runtime, leg.resolve(&source.repository)) {
        Ok(repository) => repository,
        Err(refused) => return Ok(refused),
    };
    let relay = SourceRelay::start(call.runtime, Arc::clone(&leg), resolved)?;
    let fetched =
        wire.fetch_external_exact_via_relay(&relay.url, &relay.ticket, source_ref, base, head);
    let noted = relay.stop();
    Ok(match (fetched?, noted) {
        (GitImportFetchOutcome::Refused(_), Some(code)) => GitImportFetchOutcome::Refused(code),
        (outcome, _) => outcome,
    })
}

/// Runs `future` on the serve `runtime` from this blocking caller: from
/// this thread, or from a scoped one when this thread is inside a runtime.
fn block_on<F>(runtime: &Handle, future: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    if Handle::try_current().is_err() {
        return runtime.block_on(future);
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| runtime.block_on(future))
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// One bound fetch's broker leg: what each exchange is judged and sent
/// under, and the first refusal any exchange met.
struct SourceLeg {
    server: Arc<SyncServer>,
    auth: CoreAuth,
    importer: EntityId,
    binding: String,
    /// The source's own `https://host[:port]`.
    origin: String,
    broker: BrokerContext,
    /// The host's transfer idle limit.
    idle: Duration,
    /// This fetch's random id, which each exchange's call id carries.
    id: String,
    sequence: AtomicU64,
    noted: Mutex<Option<String>>,
}

impl SourceLeg {
    /// Notes the first refusal code any exchange met.
    fn note(&self, code: &str) {
        if let Ok(mut noted) = self.noted.lock() {
            noted.get_or_insert_with(|| code.to_owned());
        }
    }

    /// Notes `code` and answers Git with it.
    fn refuse(&self, status: StatusCode, code: &str) -> Response {
        self.note(code);
        text_response(status, code)
    }

    /// The call's credential, not revoked, and the binding, still admitting
    /// this importer for this host, judged again now.
    fn admitted(&self) -> Result<(), String> {
        if revoked(&self.server, &self.auth) {
            return Err("external_import_credential_revoked".to_owned());
        }
        self.server
            .vault()
            .check_external_import_source_binding(&self.binding, &self.origin, self.importer)
            .map_err(|error| match error {
                oneiron::Error::Refused(reason) => reason
                    .split(':')
                    .next()
                    .unwrap_or("binding_refused")
                    .to_owned(),
                _ => "binding_unreadable".to_owned(),
            })
    }

    /// The binding's credential, read at the custody door in the one
    /// snapshot that judges the binding again (its scopes still this host,
    /// its actor still this importer or behind its Grant), and copied once
    /// into a buffer wiped on drop. A binding rebound since it was judged
    /// never reaches the broker.
    fn credential(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut secret = Zeroizing::new(Vec::new());
        let mut oversized = false;
        self.server
            .vault()
            .inject_external_import_source_credential(
                &self.binding,
                &self.origin,
                self.importer,
                &mut |value: &[u8]| {
                    if value.len() > MAX_SECRET {
                        oversized = true;
                        return Ok(());
                    }
                    // Sized once, so no reallocation leaves a copy behind.
                    secret.reserve_exact(value.len());
                    secret.extend_from_slice(value);
                    Ok(())
                },
            )
            .map_err(|error| match error {
                oneiron::Error::Refused(reason) => reason
                    .split(':')
                    .next()
                    .unwrap_or("binding_refused")
                    .to_owned(),
                _ => "binding_refused_at_door".to_owned(),
            })?;
        if oversized || secret.is_empty() {
            return Err("binding_not_a_header".to_owned());
        }
        Ok(secret)
    }

    /// Sends one upload-pack exchange with `repository` through the broker:
    /// judged again, its body (`body`, spooled and rewound) digested, the
    /// broker reached and its acknowledgement taken, then the credential
    /// read and handed over. Answers the reply, its body still to come, or
    /// the refusal's code.
    async fn send(
        &self,
        repository: &GitRepository,
        exchange: GitExchange,
        git_protocol: Option<String>,
        body: Option<std::fs::File>,
    ) -> Result<GitReply, String> {
        self.admitted()?;
        let target = GitTarget {
            repository: repository.clone(),
            service: oneiron_broker::GitService::UploadPack,
            exchange,
        };
        let headers: Vec<(String, String)> = git_protocol
            .map(|value| ("git-protocol".to_owned(), value))
            .into_iter()
            .collect();
        let (digest, len, body) = digest_body(&target, &headers, body)?;
        let call = format!(
            "import-source/{}/{}",
            self.id,
            self.sequence.fetch_add(1, Ordering::Relaxed)
        );
        let header = GitCallHeader::new(call, target, headers, len, digest, self.idle);
        let (connection, isolation) =
            self.broker
                .git_connection(self.idle)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "no credential broker for an outside import's source");
                    "source_broker_unavailable".to_owned()
                })?;
        let mut body: Box<dyn AsyncRead + Unpin + Send> = match body {
            Some(file) => Box::new(tokio::fs::File::from_std(file)),
            None => Box::new(tokio::io::empty()),
        };
        let prepared = connection
            .prepare_git(&header, &mut body)
            .await
            .map_err(broker_code)?;
        let secret = self.credential()?;
        let reply = prepared.open(secret).await.map_err(broker_code)?;
        tracing::info!(
            exchange = ?exchange,
            digest = %header.digest,
            isolation = isolation.as_str(),
            "an outside import's source exchange went through the credential broker"
        );
        Ok(reply)
    }

    /// The repository the source's advertisement answers from, each hop one
    /// broker exchange: a redirect on the source's own https host is asked
    /// for again there, any other refuses naming its target, and a loop
    /// refuses.
    async fn resolve(&self, repository: &str) -> Result<GitRepository, GitImportFetchOutcome> {
        let refused = |reason: &str| GitImportFetchOutcome::Refused(reason.to_owned());
        let mut url = repository.trim_end_matches('/').to_owned();
        let mut seen = BTreeSet::new();
        while seen.insert(url.clone()) {
            let repository =
                GitRepository::parse(&url).map_err(|_| refused("source_url_malformed"))?;
            let asked = GitTarget {
                repository: repository.clone(),
                service: oneiron_broker::GitService::UploadPack,
                exchange: GitExchange::Advertisement,
            }
            .url()
            .map_err(|_| refused("source_url_malformed"))?;
            let reply = self
                .send(&repository, GitExchange::Advertisement, None, None)
                .await
                .map_err(|code| refused(&code))?;
            let (status, headers) = match reply.outcome() {
                Outcome::Answered { status, headers } => (*status, headers.clone()),
                Outcome::Refused { reason } => {
                    return Err(refused(&format!("source_refused_{}", code(reason))));
                }
                Outcome::Failed { reason } => {
                    return Err(refused(&format!("source_failed_{}", code(reason))));
                }
            };
            // The advertisement itself is not read: Git asks for it again.
            drop(reply);
            if !(300..400).contains(&status) {
                return Ok(repository);
            }
            let target = headers
                .iter()
                .find(|(name, _)| name == "location")
                .and_then(|(_, location)| asked.join(location).ok())
                .ok_or_else(|| refused("source_redirect_without_target"))?;
            let redirected = redirected_repository(&target);
            if target.scheme() != "https"
                || format!("https://{}", authority(&target)) != self.origin
            {
                return Err(GitImportFetchOutcome::Refused(format!(
                    "{REDIRECT_REFUSED}{redirected}"
                )));
            }
            url = redirected;
        }
        Err(refused("source_redirect_loop"))
    }
}

/// The digest of an exchange to `target` with `headers` and the spooled
/// `body` (none for an advertisement), its length, and the body rewound.
fn digest_body(
    target: &GitTarget,
    headers: &[(String, String)],
    body: Option<std::fs::File>,
) -> Result<(String, u64, Option<std::fs::File>), String> {
    let spool = || "source_request_spool_failed".to_owned();
    let Some(mut file) = body else {
        let digest = git_request_digest(target, headers, &[]).map_err(|_| spool())?;
        return Ok((digest, 0, None));
    };
    let len = file.metadata().map_err(|_| spool())?.len();
    let mut digest = GitRequestDigest::new(target, headers, len);
    let mut buffer = vec![0; SPOOL_READ];
    loop {
        let read = file.read(&mut buffer).map_err(|_| spool())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| spool())?;
    let digest = digest.finish().map_err(|_| spool())?;
    Ok((digest, len, Some(file)))
}

/// A broker error's refusal code.
fn broker_code(error: BrokerError) -> String {
    match error {
        BrokerError::Refused(reason) => format!("source_refused_{}", code(&reason)),
        BrokerError::Lost => "source_broker_lost".to_owned(),
        BrokerError::Unreachable => "source_broker_unreachable".to_owned(),
        BrokerError::Peer => "source_broker_peer_refused".to_owned(),
    }
}

/// A broker code's wire spelling.
fn code<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// What one source relay serves: its leg, the one resolved repository, and
/// the ticket each request must carry.
struct RelayState {
    leg: Arc<SourceLeg>,
    repository: GitRepository,
    ticket: Zeroizing<String>,
}

impl RelayState {
    /// Whether `parts` carries this relay's ticket, compared in constant
    /// time.
    fn ticketed(&self, parts: &Parts) -> bool {
        let presented = parts
            .headers
            .get(SOURCE_RELAY_TICKET_HEADER)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        let expected = self.ticket.as_bytes();
        presented.len() == expected.len()
            && presented
                .iter()
                .zip(expected)
                .fold(0_u8, |differ, (left, right)| differ | (left ^ right))
                == 0
    }

    /// Sends Git's request through the broker and answers with the reply:
    /// its status and content type, and its body streamed as it comes.
    async fn forward(
        &self,
        exchange: GitExchange,
        parts: &Parts,
        body: Option<std::fs::File>,
    ) -> Response {
        let git_protocol = header_value(&parts.headers, "git-protocol");
        let reply = match self
            .leg
            .send(&self.repository, exchange, git_protocol, body)
            .await
        {
            Ok(reply) => reply,
            Err(code) => return self.leg.refuse(StatusCode::BAD_GATEWAY, &code),
        };
        let (status, headers) = match reply.outcome() {
            Outcome::Answered { status, headers } => (*status, headers.clone()),
            Outcome::Refused { reason } => {
                let code = format!("source_refused_{}", code(reason));
                return self.leg.refuse(StatusCode::BAD_GATEWAY, &code);
            }
            Outcome::Failed { reason } => {
                let code = format!("source_failed_{}", code(reason));
                return self.leg.refuse(StatusCode::BAD_GATEWAY, &code);
            }
        };
        if !(200..300).contains(&status) {
            self.leg.note(&format!("source_http_{status}"));
        }
        let mut response = Response::new(reply_body(reply, Arc::clone(&self.leg)));
        *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
        if let Some(value) = headers
            .iter()
            .find(|(name, _)| name == "content-type")
            .and_then(|(_, value)| HeaderValue::from_str(value).ok())
        {
            response.headers_mut().insert(CONTENT_TYPE, value);
        }
        response
    }
}

/// A reply's body as Git reads it: each chunk as it comes, the end clean
/// only when the broker says so. A cut or broken reply ends with an error,
/// so Git never reads a cut pack as whole.
fn reply_body(reply: GitReply, leg: Arc<SourceLeg>) -> Body {
    let chunks = futures_util::stream::unfold(Some((reply, leg)), |state| async move {
        let (mut reply, leg) = state?;
        match reply.next().await {
            Ok(StreamPart::Chunk(mut chunk)) => Some((
                Ok::<Vec<u8>, io::Error>(std::mem::take(&mut *chunk)),
                Some((reply, leg)),
            )),
            Ok(StreamPart::End) => None,
            Ok(StreamPart::Cut(reason)) => {
                leg.note(&format!("source_cut_{}", code(&reason)));
                Some((Err(io::Error::other("the brokered reply was cut")), None))
            }
            Err(_) => {
                leg.note("source_broker_lost");
                Some((Err(io::Error::other("the brokered reply broke")), None))
            }
        }
    });
    Body::from_stream(chunks)
}

/// `GET <relay>/info/refs?service=git-upload-pack`: the advertisement.
async fn source_info_refs(
    State(relay): State<Arc<RelayState>>,
    RawQuery(query): RawQuery,
    parts: Parts,
) -> Response {
    if !relay.ticketed(&parts) {
        return text_response(StatusCode::NOT_FOUND, "not found");
    }
    match advertised_service(&query.unwrap_or_default()) {
        Ok(GitService::UploadPack) => {}
        Ok(GitService::ReceivePack) => {
            return relay.leg.refuse(
                StatusCode::FORBIDDEN,
                "source_relay_serves_upload_pack_only",
            );
        }
        Err(refusal) => return refusal.response(),
    }
    relay
        .forward(GitExchange::Advertisement, &parts, None)
        .await
}

/// `POST <relay>/git-upload-pack`: the negotiation and the pack, streamed.
async fn source_upload_pack(
    State(relay): State<Arc<RelayState>>,
    parts: Parts,
    body: Body,
) -> Response {
    if !relay.ticketed(&parts) {
        return text_response(StatusCode::NOT_FOUND, "not found");
    }
    if header_value(&parts.headers, CONTENT_TYPE.as_str()).as_deref() != Some(UPLOAD_PACK_REQUEST) {
        return relay.leg.refuse(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "source_request_not_upload_pack",
        );
    }
    let spool = match spool_request(&parts, body, relay.leg.idle).await {
        Ok(spool) => spool,
        Err(code) => return relay.leg.refuse(StatusCode::BAD_REQUEST, code),
    };
    relay.forward(GitExchange::Rpc, &parts, Some(spool)).await
}

/// Where a request body is spooled: as it came, or decoded from gzip.
enum Sink {
    Plain(std::fs::File),
    Gzip(flate2::write::GzDecoder<std::fs::File>),
}

impl Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain(file) => file.write_all(bytes),
            Self::Gzip(decoder) => decoder.write_all(bytes),
        }
    }

    fn finish(self) -> io::Result<std::fs::File> {
        match self {
            Self::Plain(file) => Ok(file),
            Self::Gzip(decoder) => decoder.finish(),
        }
    }
}

/// Spools Git's request body to a private unnamed file, decoded from its
/// outer gzip when it carries one, so the digest and the send cover the
/// identity bytes; rewound. Each frame waits at most `idle`.
async fn spool_request(
    parts: &Parts,
    body: Body,
    idle: Duration,
) -> Result<std::fs::File, &'static str> {
    let encoding = header_value(&parts.headers, CONTENT_ENCODING.as_str()).unwrap_or_default();
    let encoding = encoding.trim();
    let gzip = if encoding.is_empty() || encoding.eq_ignore_ascii_case("identity") {
        false
    } else if encoding.eq_ignore_ascii_case("gzip") || encoding.eq_ignore_ascii_case("x-gzip") {
        true
    } else {
        return Err("source_request_encoding_unsupported");
    };
    let file = tempfile::tempfile().map_err(|_| "source_request_spool_failed")?;
    let mut sink = if gzip {
        Sink::Gzip(flate2::write::GzDecoder::new(file))
    } else {
        Sink::Plain(file)
    };
    let mut frames = body.into_data_stream();
    loop {
        let frame = match tokio::time::timeout(idle, frames.next()).await {
            Err(_) => return Err("source_request_idle"),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err("source_request_broken"),
            Ok(Some(Ok(frame))) => frame,
        };
        sink.write(&frame)
            .map_err(|_| "source_request_unreadable")?;
    }
    let mut file = sink.finish().map_err(|_| "source_request_unreadable")?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "source_request_spool_failed")?;
    Ok(file)
}

/// One bound fetch's loopback source relay.
struct SourceRelay {
    url: String,
    /// The ticket Git presents in [`SOURCE_RELAY_TICKET_HEADER`].
    ticket: Zeroizing<String>,
    stop: Option<oneshot::Sender<()>>,
    leg: Arc<SourceLeg>,
}

impl SourceRelay {
    /// Serves `repository`'s upload-pack through `leg` on an OS-assigned
    /// loopback port under a fresh random path, to requests carrying a
    /// fresh random ticket.
    fn start(
        runtime: &Handle,
        leg: Arc<SourceLeg>,
        repository: GitRepository,
    ) -> oneiron::Result<Self> {
        let mut secret = [0_u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret);
        let secret: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut ticket = Zeroizing::new([0_u8; 32]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut *ticket);
        let mut hex = Zeroizing::new(String::with_capacity(64));
        for &byte in ticket.iter() {
            hex.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            hex.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
        }
        let state = Arc::new(RelayState {
            leg: Arc::clone(&leg),
            repository,
            ticket: hex.clone(),
        });
        let base = format!("/{secret}/{SOURCE_REPO_SEGMENT}");
        let app = Router::new()
            .route(&format!("{base}/info/refs"), get(source_info_refs))
            .route(&format!("{base}/git-upload-pack"), post(source_upload_pack))
            .with_state(state);
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let listener = {
            let _entered = runtime.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let (stop, stopped) = oneshot::channel::<()>();
        drop(runtime.spawn(async move {
            let shutdown = async move {
                let _ = stopped.await;
            };
            if let Err(error) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
            {
                tracing::warn!(%error, "an outside import's source relay stopped with an error");
            }
        }));
        Ok(Self {
            url: format!("http://127.0.0.1:{port}{base}"),
            ticket: hex,
            stop: Some(stop),
            leg,
        })
    }

    /// Stops the relay and answers the first refusal code any exchange met.
    fn stop(mut self) -> Option<String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.leg.noted.lock().ok().and_then(|noted| noted.clone())
    }
}

impl Drop for SourceRelay {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
