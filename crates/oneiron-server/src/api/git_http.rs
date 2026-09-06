//! Git smart-HTTP routes (ARCH-0068 Phase A, ONE-1908).
//!
//! Protocol only. This module owns routes, the auth gate, and the streaming
//! bridge onto [`oneiron::origin::smart_http`]; it owns no landing logic and no
//! publication logic, so the object-storage and publication routes that come
//! next nest beside it without rework.
//!
//! # Credentials on the wire
//!
//! One credential travels, and it is the one the rest of the server already
//! speaks: `Authorization: Bearer`. A stock git client carries it with
//!
//! ```text
//! git -c http.extraHeader="Authorization: Bearer <token>" clone http://127.0.0.1:7777/git/demo.git
//! ```
//!
//! That is client configuration, not a protocol change. An unauthenticated
//! `info/refs` answers `401` with a bearer challenge, which is what makes a
//! stock client ask for credentials instead of failing opaquely.
//!
//! # The gates
//!
//! | Route | Gate |
//! |---|---|
//! | `GET  /git/{repo}/info/refs?service=git-upload-pack` | `Read` |
//! | `GET  /git/{repo}/info/refs?service=git-receive-pack` | `Write` + a registered `principal_ref` |
//! | `POST /git/{repo}/git-upload-pack` | `Read` |
//! | `POST /git/{repo}/git-receive-pack` | `Write` + a registered `principal_ref` |
//!
//! RC4 is the second row of that table read twice: a push needs a real bearer
//! that resolves to a *registered principal*, and it needs it on `127.0.0.1`
//! exactly as much as anywhere else. The unauthenticated-dev escape hatch is
//! untouched here and cannot admit a push, because the identity it mints
//! carries no `principal_ref` — a route address is not a principal, so no
//! loopback branch exists to take.
//!
//! The first two rows are told apart by the `service=` parameter, so that
//! parameter is canonicalized before anything reads it: exactly one is
//! required, a query naming zero or several is `400`, and the backend is handed
//! the single value the gate decided about rather than the client's query
//! string. The gate and the advertisement can therefore never be about
//! different services.
//!
//! # Streaming
//!
//! Request bodies stream into the backend and response bodies stream back out,
//! one bounded chunk at a time. Nothing is buffered whole, no size cap and no
//! rate cap is added here, and a large pack rides through without ever being
//! materialized.

use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::auth::RevokedTokenJtis;
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use axum::Router;
use axum::body::Body;
use axum::body::Bytes;
use axum::extract::Path;
use axum::extract::RawQuery;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CONTENT_ENCODING;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_TYPE;
use axum::http::header::WWW_AUTHENTICATE;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use futures_util::StreamExt;
use oneiron::origin::smart_http;
use std::io;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// The bearer challenge an unauthenticated smart-HTTP request receives.
const GIT_HTTP_CHALLENGE: &str = "Bearer realm=\"oneiron-origin\"";

/// Bounded in-flight chunks in each direction. Backpressure, not buffering:
/// the producer blocks instead of accumulating a body.
const GIT_HTTP_STREAM_CHUNKS: usize = 4;

/// The two smart-HTTP services, and the only two this origin serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitService {
    UploadPack,
    ReceivePack,
}

impl GitService {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    const fn scope(self) -> CoreScope {
        match self {
            Self::UploadPack => CoreScope::Read,
            Self::ReceivePack => CoreScope::Write,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "git-upload-pack" => Some(Self::UploadPack),
            "git-receive-pack" => Some(Self::ReceivePack),
            _ => None,
        }
    }
}

/// Builds the git smart-HTTP routes.
pub(crate) fn git_http_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/git/{repo}/info/refs", get(git_info_refs))
        .route("/git/{repo}/git-upload-pack", post(git_upload_pack))
        .route("/git/{repo}/git-receive-pack", post(git_receive_pack))
        .merge(crate::api::git_lfs::lfs_routes())
}

/// `GET /git/{repo}/info/refs` — the ref advertisement, streamed.
pub(crate) async fn git_info_refs(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let service = match advertised_service(&query.unwrap_or_default()) {
        Ok(service) => service,
        Err(refusal) => return refusal.response(),
    };
    let auth = match authenticate(&headers, &server.config, server.vault().as_ref(), service) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let name = repo_name(&repo).to_owned();
    let request = advertisement_request(&name, service, remote_user(&auth));
    run_serve(server, name, request, Body::empty()).await
}

/// The advertisement invocation this route hands to the serving plane.
///
/// Built as a value so the one property that matters can be asserted without a
/// transport around it: this is the request shape
/// [`smart_http::ServeRequest::is_ref_advertisement`] recognizes, and therefore
/// the one the publication projection gates. An advertisement the gate does not
/// recognize would be a ref list nobody projected.
fn advertisement_request(
    name: &str,
    service: GitService,
    remote_user: Option<String>,
) -> smart_http::ServeRequest {
    smart_http::ServeRequest {
        method: "GET".to_owned(),
        path_info: format!("/{name}.git/info/refs"),
        // The CANONICAL spelling of the service the gate just authorized, never
        // the client's query. What the backend advertises and what the gate
        // decided are one value by construction.
        query_string: format!("service={}", service.as_str()),
        content_type: None,
        content_length: None,
        content_encoding: None,
        // The client's `Git-Protocol` is read and not forwarded. Protocol v2
        // moves the ref list out of this response and into an `ls-refs` command
        // inside the RPC body, where the publication projection cannot reach
        // it; declining the version is what keeps "every advertised ref is a
        // published ref" true. A stock client falls back on its own.
        git_protocol: None,
        remote_user,
        remote_addr: None,
    }
}

/// `POST /git/{repo}/git-upload-pack` — fetch/clone negotiation, streamed.
pub(crate) async fn git_upload_pack(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    serve_rpc(server, repo, headers, body, GitService::UploadPack).await
}

/// `POST /git/{repo}/git-receive-pack` — the push, streamed.
///
/// The gate is the whole of RC4: `Write` scope plus a registered
/// `principal_ref` proved by a real bearer, on loopback and everywhere else
/// alike. The door window and the single-writer landing happen inside
/// [`smart_http::serve`]; this handler adds no ref logic of its own.
pub(crate) async fn git_receive_pack(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    serve_rpc(server, repo, headers, body, GitService::ReceivePack).await
}

async fn serve_rpc(
    server: Arc<SyncServer>,
    repo: String,
    headers: HeaderMap,
    body: Body,
    service: GitService,
) -> Response {
    let auth = match authenticate(&headers, &server.config, server.vault().as_ref(), service) {
        Ok(auth) => auth,
        Err(response) => return *response,
    };
    let name = repo_name(&repo).to_owned();
    let request = smart_http::ServeRequest {
        method: "POST".to_owned(),
        path_info: format!("/{name}.git/{}", service.as_str()),
        query_string: String::new(),
        content_type: header_value(&headers, CONTENT_TYPE.as_str()),
        content_length: header_value(&headers, CONTENT_LENGTH.as_str())
            .and_then(|value| value.parse::<u64>().ok()),
        content_encoding: header_value(&headers, CONTENT_ENCODING.as_str()),
        // Pinned for the same reason the advertisement pins it: an exchange
        // whose advertisement spoke v0 and whose RPC speaks v2 is not one
        // conversation.
        git_protocol: None,
        remote_user: remote_user(&auth),
        remote_addr: None,
    };
    run_serve(server, name, request, body).await
}

// ---------------------------------------------------------------------------
// The auth gate
// ---------------------------------------------------------------------------

/// Authenticates one smart-HTTP request.
///
/// Split from the handlers so the gate is testable as itself: the dev hatch,
/// the scope check, and the registered-principal demand are one function with
/// no transport around them.
fn authenticate(
    headers: &HeaderMap,
    config: &SyncServerConfig,
    revoked: &dyn RevokedTokenJtis,
    service: GitService,
) -> Result<CoreAuth, Box<Response>> {
    let auth =
        CoreAuth::from_headers(headers, config, revoked).map_err(|_| Box::new(challenge()))?;
    auth.require(service.scope())
        .map_err(|error| Box::new(text_response(error.status(), "insufficient scope")))?;
    if service == GitService::ReceivePack {
        // RC4. A hatch-only identity and a bare trust-root secret both reach
        // here with every scope and no principal_ref; neither is a registered
        // actor, so neither may push — including on 127.0.0.1.
        auth.require_registered_principal().map_err(|error| {
            Box::new(text_response(
                error.status(),
                "receive-pack requires a registered principal_ref",
            ))
        })?;
    }
    Ok(auth)
}

fn challenge() -> Response {
    let mut response = text_response(StatusCode::UNAUTHORIZED, "authentication required");
    if let Ok(value) = GIT_HTTP_CHALLENGE.parse() {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}

/// The reflog identity of anything this request lands: the registered
/// principal when there is one, and never a fabricated stand-in.
fn remote_user(auth: &CoreAuth) -> Option<String> {
    auth.principal_ref().map(str::to_owned)
}

/// Why an `info/refs` query names no service this origin will advertise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceRefusal {
    /// No `service=` at all: a dumb-protocol probe.
    Missing,
    /// More than one `service=`. The value is ambiguous, so there is no
    /// question to answer.
    Ambiguous,
    /// A `service=` this origin does not serve.
    Unsupported,
}

impl ServiceRefusal {
    fn response(self) -> Response {
        match self {
            // Only the smart protocol is served. A dumb-protocol probe is
            // refused here rather than answered with a directory listing.
            Self::Missing => text_response(
                StatusCode::BAD_REQUEST,
                "oneiron origin serves the smart protocol only: name one service=",
            ),
            Self::Ambiguous => text_response(
                StatusCode::BAD_REQUEST,
                "info/refs accepts exactly one service= parameter",
            ),
            Self::Unsupported => text_response(
                StatusCode::FORBIDDEN,
                "oneiron origin serves git-upload-pack and git-receive-pack only",
            ),
        }
    }
}

/// The one service an `info/refs` query names, or why it names none.
///
/// Exactly one is the whole rule. `git http-backend` reads the LAST `service=`
/// in the query string it is handed, so a gate that read the first would decide
/// about one service while the backend advertised another — a `core:read`
/// bearer could ask for `git-upload-pack` and be handed the `git-receive-pack`
/// advertisement. A query carrying zero or several is refused HERE, before the
/// auth gate and before any child exists, and the value this returns is the
/// only spelling the backend is ever given.
fn advertised_service(query: &str) -> Result<GitService, ServiceRefusal> {
    let mut named = query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("service="));
    let value = named.next().ok_or(ServiceRefusal::Missing)?;
    if named.next().is_some() {
        return Err(ServiceRefusal::Ambiguous);
    }
    GitService::parse(value).ok_or(ServiceRefusal::Unsupported)
}

/// `demo` and `demo.git` name the same served repository; the `.git` suffix is
/// URL convention, not part of the name.
fn repo_name(segment: &str) -> &str {
    segment.strip_suffix(".git").unwrap_or(segment)
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn text_response(status: StatusCode, message: &str) -> Response {
    (status, message.to_owned()).into_response()
}

// ---------------------------------------------------------------------------
// The streaming bridge
// ---------------------------------------------------------------------------

/// Runs one serve invocation on a blocking worker and streams both directions
/// through bounded channels.
///
/// The worker owns the subprocess; the async side owns the socket. Neither ever
/// holds a whole body: a chunk moves when the far side has room for it.
async fn run_serve(
    server: Arc<SyncServer>,
    repo: String,
    request: smart_http::ServeRequest,
    body: Body,
) -> Response {
    // A push is held until its landing is journaled; everything else streams.
    let held = request.is_receive_pack();
    let (request_tx, request_rx) = mpsc::channel::<Bytes>(GIT_HTTP_STREAM_CHUNKS);
    let (head_tx, head_rx) = oneshot::channel::<ResponseHead>();
    let (response_tx, response_rx) = mpsc::channel::<Bytes>(GIT_HTTP_STREAM_CHUNKS);

    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else {
                break;
            };
            if request_tx.send(chunk).await.is_err() {
                break;
            }
        }
    });

    let worker = tokio::task::spawn_blocking(move || {
        let mut reader = ChannelReader::new(request_rx);
        let mut sink = ChannelSink::new(head_tx, response_tx);
        // CoreAuth's validated principal_ref travels unchanged. The existing
        // serve path persists landed admission and observed outcome evidence;
        // this bridge supplies neither a claim id nor an alternate credential.
        smart_http::serve(
            server.vault(),
            &repo,
            &request,
            smart_http::DoorSeam::Landed,
            &mut reader,
            &mut sink,
        )
    });

    if held {
        return held_response(head_rx, response_rx, worker).await;
    }
    match head_rx.await {
        // The backend answered, and a fetch's answer is the pack itself: it
        // streams out as it is produced and is never held.
        Ok(head) => streaming_response(head, response_rx),
        Err(_) => serve_failure(worker.await),
    }
}

/// Holds a push's response until its landing is journaled.
///
/// A fetch's response is a pack and must never be buffered. A push's response
/// is git's own status report — a handful of pkt-lines, bounded by the number
/// of refs the push named — while the pack it answers has already streamed IN.
/// Holding it costs nothing and buys the one thing a push needs: the client is
/// told the push succeeded only after the publication protocol says it did.
///
/// Streaming the report first and journaling afterwards is what made a refused
/// publication indistinguishable from a landed one. The client saw `ok`, the
/// origin recorded nothing, and the ref the client believed it had pushed was
/// never advertised.
async fn held_response(
    head: oneshot::Receiver<ResponseHead>,
    mut chunks: mpsc::Receiver<Bytes>,
    worker: tokio::task::JoinHandle<oneiron::Result<smart_http::ServeReport>>,
) -> Response {
    let head = head.await.ok();
    let mut body = Vec::new();
    // Drained as it arrives, never after: the worker writes into a bounded
    // channel with a blocking send, so a reader that waited for the worker
    // before draining would wedge them against each other.
    while let Some(chunk) = chunks.recv().await {
        body.push(chunk);
    }
    landed_response(head, body, worker.await)
}

/// The response a held push produces, decided by the landing rather than by the
/// backend.
///
/// `git receive-pack` reports on what IT did — it moved refs and migrated the
/// objects — and it has no opinion about the publication protocol that runs
/// after it. When that protocol refuses (an availability proof that failed, a
/// compare-and-swap another writer won), the push did not land, and the only
/// honest answer is a failure the client surfaces rather than the backend's
/// `ok`.
fn landed_response(
    head: Option<ResponseHead>,
    body: Vec<Bytes>,
    joined: Result<oneiron::Result<smart_http::ServeReport>, tokio::task::JoinError>,
) -> Response {
    match joined {
        Ok(Ok(_)) => {}
        refused => return serve_failure(refused),
    }
    let Some((status, headers)) = head else {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git smart-http produced no response",
        );
    };
    let mut response = Response::new(Body::from(concat_chunks(body)));
    apply_response_head(&mut response, status, headers);
    response
}

fn concat_chunks(chunks: Vec<Bytes>) -> Bytes {
    let total = chunks.iter().map(Bytes::len).sum();
    let mut buffer = Vec::with_capacity(total);
    for chunk in chunks {
        buffer.extend_from_slice(&chunk);
    }
    Bytes::from(buffer)
}

type ResponseHead = (u16, Vec<(String, String)>);

fn serve_failure(
    joined: Result<oneiron::Result<smart_http::ServeReport>, tokio::task::JoinError>,
) -> Response {
    let (status, message) = match joined {
        Ok(Ok(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "git smart-http produced no response".to_owned(),
        ),
        Ok(Err(error @ oneiron::Error::ReceivePackLandingRefused { .. })) => {
            (StatusCode::CONFLICT, error.to_string())
        }
        Ok(Err(
            error @ (oneiron::Error::ConcurrentWrite(_) | oneiron::Error::RepoMutationFailed(_)),
        )) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
        Ok(Err(error)) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "git smart-http worker did not complete".to_owned(),
        ),
    };
    let mut response = text_response(status, &message);
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
    }
    response
}

/// Wraps the backend's own status and headers around a body that is still
/// arriving. The body is a stream, so a large pack leaves the process the same
/// way it entered: in chunks, never whole.
fn streaming_response(head: ResponseHead, chunks: mpsc::Receiver<Bytes>) -> Response {
    let (status, headers) = head;
    let stream = futures_util::stream::unfold(chunks, |mut chunks| async move {
        chunks
            .recv()
            .await
            .map(|chunk| (Ok::<Bytes, io::Error>(chunk), chunks))
    });
    let mut response = Response::new(Body::from_stream(stream));
    apply_response_head(&mut response, status, headers);
    response
}

/// Puts the backend's own status and headers on a response, whatever the body
/// turned out to be.
fn apply_response_head(response: &mut Response, status: u16, headers: Vec<(String, String)>) {
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    for (name, value) in headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&value) else {
            continue;
        };
        response.headers_mut().append(name, value);
    }
}

/// The request body, as a blocking reader over the async stream.
struct ChannelReader {
    chunks: mpsc::Receiver<Bytes>,
    carry: Bytes,
}

impl ChannelReader {
    fn new(chunks: mpsc::Receiver<Bytes>) -> Self {
        Self {
            chunks,
            carry: Bytes::new(),
        }
    }
}

impl io::Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.carry.is_empty() {
            match self.chunks.blocking_recv() {
                Some(chunk) => self.carry = chunk,
                None => return Ok(0),
            }
        }
        let take = self.carry.len().min(out.len());
        out[..take].copy_from_slice(&self.carry[..take]);
        self.carry = self.carry.slice(take..);
        Ok(take)
    }
}

/// The response, as a blocking sink onto the async stream.
struct ChannelSink {
    head: Option<oneshot::Sender<ResponseHead>>,
    chunks: mpsc::Sender<Bytes>,
}

impl ChannelSink {
    fn new(head: oneshot::Sender<ResponseHead>, chunks: mpsc::Sender<Bytes>) -> Self {
        Self {
            head: Some(head),
            chunks,
        }
    }
}

impl smart_http::ServeSink for ChannelSink {
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        let Some(head) = self.head.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "git smart-http produced two header blocks",
            ));
        };
        head.send((status, headers.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client went away"))
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.chunks
            .blocking_send(Bytes::copy_from_slice(bytes))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client went away"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::mint_core_token_v2;
    use axum::http::HeaderValue;
    use axum::http::header::AUTHORIZATION;

    struct NoRevocations;

    impl RevokedTokenJtis for NoRevocations {
        fn is_revoked(&self, _jti: &str) -> Result<bool, ()> {
            Ok(false)
        }
    }

    fn secret_config() -> SyncServerConfig {
        SyncServerConfig {
            auth_secret: Some("trust-root-secret".to_owned()),
            ..SyncServerConfig::default()
        }
    }

    fn hatch_config() -> SyncServerConfig {
        SyncServerConfig {
            auth_secret: None,
            allow_unauthenticated: true,
            ..SyncServerConfig::default()
        }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer header");
        headers.insert(AUTHORIZATION, value);
        headers
    }

    /// A registered principal is an entity id, so the fixture mints one rather
    /// than inventing a spelling the grammar would reject.
    fn principal() -> String {
        oneiron::EntityId::now().to_hex()
    }

    fn scoped_token(config: &SyncServerConfig, scopes: &str, principal: Option<&str>) -> String {
        let secret = config
            .auth_secret
            .as_deref()
            .expect("fixture configures a trust root");
        let claims = match principal {
            Some(principal_ref) => format!("scope={scopes};principal_ref={principal_ref}"),
            None => format!("scope={scopes}"),
        };
        mint_core_token_v2(secret, &claims)
    }

    #[test]
    fn git_smart_http_unauthenticated_info_refs_is_401() {
        let config = secret_config();
        let refused = authenticate(
            &HeaderMap::new(),
            &config,
            &NoRevocations,
            GitService::UploadPack,
        )
        .expect_err("unauthenticated info/refs is refused");
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            refused
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(GIT_HTTP_CHALLENGE),
            "a stock client is told how to authenticate"
        );
    }

    #[test]
    fn git_http_read_scope_serves_upload_pack() {
        let config = secret_config();
        let token = scoped_token(&config, "core:read", None);
        let auth = authenticate(
            &bearer(&token),
            &config,
            &NoRevocations,
            GitService::UploadPack,
        )
        .expect("read scope serves a fetch");
        assert!(auth.has_scope(CoreScope::Read));
    }

    #[test]
    fn git_smart_http_receive_pack_without_registered_principal_ref_refused_even_on_loopback() {
        let config = secret_config();
        // A write-scoped bearer with no principal_ref: authenticated, but not a
        // registered actor. There is no loopback branch that could admit it,
        // because the gate never reads an address.
        let token = scoped_token(&config, "core:read,core:write", None);
        let refused = authenticate(
            &bearer(&token),
            &config,
            &NoRevocations,
            GitService::ReceivePack,
        )
        .expect_err("a push without a registered principal_ref is refused");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn git_http_receive_pack_refuses_the_unauthenticated_dev_hatch() {
        let config = hatch_config();
        // The hatch identity carries every scope and no principal_ref. The
        // hatch itself is untouched: a fetch still passes.
        assert!(
            authenticate(
                &HeaderMap::new(),
                &config,
                &NoRevocations,
                GitService::UploadPack,
            )
            .is_ok(),
            "the dev hatch still serves reads"
        );
        assert!(
            authenticate(
                &HeaderMap::new(),
                &config,
                &NoRevocations,
                GitService::ReceivePack,
            )
            .is_err(),
            "the dev escape hatch can never admit a push"
        );
    }

    #[test]
    fn git_http_receive_pack_admits_a_registered_principal() {
        let config = secret_config();
        let pusher = principal();
        let token = scoped_token(&config, "core:read,core:write", Some(&pusher));
        let auth = authenticate(
            &bearer(&token),
            &config,
            &NoRevocations,
            GitService::ReceivePack,
        )
        .expect("a registered principal with write scope may push");
        assert_eq!(remote_user(&auth).as_deref(), Some(pusher.as_str()));
    }

    fn stock_git(root: &std::path::Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("stock Git starts");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn git_http_stock_git_authenticated_publication_roundtrip() {
        let dir = tempfile::tempdir().expect("vault");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("open vault"),
        );
        let config = secret_config();
        let pusher = principal();
        let token = scoped_token(&config, "core:read,core:write", Some(&pusher));
        let server = Arc::new(SyncServer::new(Arc::clone(&vault), config).expect("server"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let url = format!(
            "http://{}/git/demo.git",
            listener.local_addr().expect("address")
        );
        let routes = git_http_routes().with_state(server);
        let serving = tokio::spawn(async move {
            axum::serve(listener, routes).await.expect("serve");
        });
        let checked = tokio::task::spawn_blocking(move || {
            let source = tempfile::tempdir().expect("source");
            stock_git(source.path(), &["init", "--initial-branch=main"]);
            std::fs::write(
                source.path().join("README.md"),
                "public repository content\n",
            )
            .expect("readme");
            stock_git(source.path(), &["add", "README.md"]);
            stock_git(
                source.path(),
                &[
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-m",
                    "initial",
                ],
            );
            let oid = stock_git(source.path(), &["rev-parse", "HEAD"]);
            let root = smart_http::origin_serving_root(&vault).expect("serving root");
            stock_git(
                &root,
                &[
                    "clone",
                    "--bare",
                    source.path().to_str().expect("source path"),
                    "demo.git",
                ],
            );
            let repo_dir = root.join("demo.git");
            let auth = format!("http.extraHeader=Authorization: Bearer {token}");
            let unpublished = stock_git(source.path(), &["-c", &auth, "ls-remote", &url]);
            assert!(
                !unpublished.contains("refs/heads/main") && !unpublished.contains("\tHEAD"),
                "raw main and HEAD are not advertisement authority"
            );
            stock_git(&repo_dir, &["update-ref", "-d", "refs/heads/main"]);
            // No fixture attribution and no serve_with_provenance call. This is
            // CoreAuth -> run_serve -> serve -> landed door -> durable producer.
            stock_git(
                source.path(),
                &["-c", &auth, "push", &url, "refs/heads/main"],
            );
            let rows: Vec<_> = vault
                .origin_publication_ids(None)
                .expect("publication ids")
                .into_iter()
                .map(|id| {
                    vault
                        .origin_publication(id)
                        .expect("publication")
                        .expect("durable publication")
                })
                .collect();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].actor_id.to_hex(), pusher);
            assert_eq!(
                rows[0].status,
                oneiron::origin::publication::OriginPublicationStatus::Published
            );
            let evidence = vault
                .get_claim(&rows[0].provenance_claim_id)
                .expect("source")
                .expect("durable claim");
            assert_eq!(evidence.predicate, "repo.receive_pack_outcome");
            assert_eq!(
                evidence.lifecycle,
                oneiron::claim::ClaimLifecycleStatus::Active
            );
            let fields = evidence.value.as_map().expect("outcome fields");
            let field = |key: &str| {
                fields
                    .iter()
                    .find(|(name, _)| name.as_str() == Some(key))
                    .map(|(_, value)| value)
                    .expect("evidence field")
            };
            assert_eq!(field("actor_id").as_str(), Some(pusher.as_str()));
            assert_eq!(
                field("repo_id").as_str(),
                Some(rows[0].repo_id.to_hex().as_str())
            );
            assert_eq!(field("scan").as_str(), Some("clean"));
            let operation =
                oneiron::EntityId::from_hex(field("operation_id").as_str().expect("operation id"))
                    .expect("entity id");
            let admission = vault
                .get_claim(&operation)
                .expect("admission")
                .expect("durable admission");
            assert_eq!(admission.predicate, "repo.receive_pack_admission");
            let admission_fields = admission.value.as_map().expect("admission fields");
            assert!(admission_fields.contains(&(
                rmpv::Value::from("credential_presented"),
                rmpv::Value::from(false)
            )));
            assert!(admission_fields.contains(&(
                rmpv::Value::from("method"),
                rmpv::Value::from("bearer+registered-principal")
            )));
            let refs = stock_git(source.path(), &["-c", &auth, "ls-remote", &url]);
            assert!(refs.contains(&format!("{oid}\trefs/heads/main")));
            let clone = tempfile::tempdir().expect("client");
            stock_git(clone.path(), &["-c", &auth, "clone", &url, "checkout"]);
            assert_eq!(
                std::fs::read_to_string(clone.path().join("checkout/README.md")).expect("checkout"),
                "public repository content\n"
            );
            assert_eq!(
                vault
                    .origin_publication_ids(None)
                    .expect("publication ids")
                    .len(),
                1
            );

            // The server has not silently switched to the explicit no-op seam.
            std::fs::write(
                source.path().join("secret.txt"),
                "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
            )
            .expect("scan fixture");
            stock_git(source.path(), &["add", "secret.txt"]);
            stock_git(
                source.path(),
                &[
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-m",
                    "refused scan fixture",
                ],
            );
            let refused = std::process::Command::new("git")
                .current_dir(source.path())
                .args(["-c", &auth, "push", &url, "refs/heads/main"])
                .env("GIT_TERMINAL_PROMPT", "0")
                .output()
                .expect("push starts");
            assert!(
                !refused.status.success(),
                "the landed scan refuses the secret fixture"
            );
            assert_eq!(stock_git(&repo_dir, &["rev-parse", "refs/heads/main"]), oid);
            assert_eq!(
                vault
                    .origin_publication_ids(None)
                    .expect("publication ids")
                    .len(),
                1
            );
        })
        .await;
        serving.abort();
        checked.expect("authenticated stock Git path");
    }

    #[tokio::test]
    async fn git_http_missing_push_auth_is_rejected_before_repository_or_git() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().expect("vault");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("vault"),
        );
        let config = secret_config();
        let no_principal = scoped_token(&config, "core:write", None);
        let server = Arc::new(SyncServer::new(vault, config).expect("server"));
        for (token, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(no_principal), StatusCode::FORBIDDEN),
        ] {
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/git/missing.git/git-receive-pack");
            if let Some(token) = token {
                request = request.header(AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = git_http_routes()
                .with_state(Arc::clone(&server))
                .oneshot(request.body(Body::from("not a pack")).expect("request"))
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                expected,
                "auth refuses before repository resolution"
            );
        }
    }

    #[test]
    fn git_http_read_only_bearer_cannot_reach_receive_pack() {
        let config = secret_config();
        let token = scoped_token(&config, "core:read", Some(&principal()));
        assert!(
            authenticate(
                &bearer(&token),
                &config,
                &NoRevocations,
                GitService::ReceivePack,
            )
            .is_err(),
            "a read scope never becomes a write scope"
        );
    }

    #[test]
    fn git_http_route_shapes_are_closed() {
        assert_eq!(repo_name("demo.git"), "demo");
        assert_eq!(repo_name("demo"), "demo");
        assert_eq!(
            advertised_service("service=git-upload-pack"),
            Ok(GitService::UploadPack)
        );
        assert_eq!(
            advertised_service("service=git-receive-pack&extra=1"),
            Ok(GitService::ReceivePack)
        );
        assert_eq!(
            advertised_service(""),
            Err(ServiceRefusal::Missing),
            "the dumb protocol is not served"
        );
        assert_eq!(
            advertised_service("service=git-daemon"),
            Err(ServiceRefusal::Unsupported)
        );
    }

    /// The gate and `git http-backend` must decide about the same service.
    ///
    /// The backend keeps the LAST `service=`; reading the first here would let
    /// a read-scoped bearer be authorized for `git-upload-pack` and then handed
    /// the `git-receive-pack` advertisement. Neither value wins: the request is
    /// refused before the gate runs.
    #[test]
    fn git_http_info_refs_refuses_a_query_that_names_two_services() {
        assert_eq!(
            advertised_service("service=git-upload-pack&service=git-receive-pack"),
            Err(ServiceRefusal::Ambiguous),
            "first-wins and last-wins cannot disagree if neither is used"
        );
        assert_eq!(
            advertised_service("service=git-receive-pack&service=git-upload-pack"),
            Err(ServiceRefusal::Ambiguous)
        );
        assert_eq!(
            advertised_service("service=git-upload-pack&service=git-upload-pack"),
            Err(ServiceRefusal::Ambiguous),
            "one service= parameter means one, even when the values agree"
        );
        assert_eq!(
            ServiceRefusal::Ambiguous.response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ServiceRefusal::Missing.response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ServiceRefusal::Unsupported.response().status(),
            StatusCode::FORBIDDEN
        );
    }

    // -- the publication-gated push and advertisement ----------------------

    fn receive_pack_head() -> ResponseHead {
        (
            200,
            vec![(
                CONTENT_TYPE.as_str().to_owned(),
                "application/x-git-receive-pack-result".to_owned(),
            )],
        )
    }

    /// The status report `git receive-pack` produces for a push it accepted.
    fn receive_pack_report() -> Vec<Bytes> {
        vec![Bytes::from_static(
            b"000eunpack ok\n0019ok refs/heads/main\n0000",
        )]
    }

    fn landed_report() -> smart_http::ServeReport {
        smart_http::ServeReport {
            status: 200,
            admission: None,
            door: smart_http::DoorWindowReport {
                verdict: smart_http::DoorWindowVerdict::Clean,
                ref_updates: Vec::new(),
                lfs_pointers: Vec::new(),
                quarantine_path: None,
            },
            outcome: None,
            landing: None,
        }
    }

    /// A push whose publication was refused is a refused push, never an `ok`.
    ///
    /// `git receive-pack` reports on what it did; the publication protocol runs
    /// after it and can still refuse. Handing the backend's `ok` to the client
    /// in that case is the one failure mode this route must not have: the
    /// client would record a push the origin will never advertise.
    #[test]
    fn git_http_rejects_publication_failure() {
        let refused = landed_response(
            Some(receive_pack_head()),
            receive_pack_report(),
            Ok(Err(oneiron::Error::ReceivePackLandingRefused {
                reason: "publication conflicted".to_owned(),
            })),
        );
        assert_eq!(
            refused.status(),
            StatusCode::CONFLICT,
            "a refused publication is not a successful push"
        );
        assert_ne!(
            refused
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-git-receive-pack-result"),
            "the backend's own success report never reaches the client"
        );

        let uncertain = landed_response(
            Some(receive_pack_head()),
            receive_pack_report(),
            Ok(Err(oneiron::Error::ConcurrentWrite(
                "origin CAS effect is uncertain",
            ))),
        );
        assert_eq!(uncertain.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            uncertain.headers().get("retry-after").expect("retry hint"),
            "1"
        );

        let landed = landed_response(
            Some(receive_pack_head()),
            receive_pack_report(),
            Ok(Ok(landed_report())),
        );
        assert_eq!(
            landed.status(),
            StatusCode::OK,
            "a push whose publication landed answers exactly as the backend did"
        );
        assert_eq!(
            landed
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-git-receive-pack-result")
        );
    }

    /// A push that produced no response at all is not silently successful.
    #[test]
    fn git_http_push_without_a_backend_response_is_a_failure() {
        let orphaned = landed_response(None, Vec::new(), Ok(Ok(landed_report())));
        assert_eq!(orphaned.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// The advertisement this route asks for is the one the projection gates.
    #[test]
    fn git_http_advertisement_is_projection_gated() {
        let request = advertisement_request("demo", GitService::UploadPack, None);
        assert!(
            request.is_ref_advertisement(),
            "the serving plane must recognize this as the ref advertisement, \
             because that recognition is what engages the publication projection"
        );
        assert_eq!(request.query_string, "service=git-upload-pack");
        assert!(
            request.git_protocol.is_none(),
            "protocol v2 would move the ref list where the projection cannot reach it"
        );

        let push = advertisement_request("demo", GitService::ReceivePack, Some("actor".to_owned()));
        assert!(
            push.is_ref_advertisement(),
            "a push's advertisement is gated exactly as a fetch's is"
        );
        assert_eq!(push.query_string, "service=git-receive-pack");
        assert_eq!(push.remote_user.as_deref(), Some("actor"));
    }

    /// A held push is the only held response.
    #[test]
    fn git_http_only_a_push_is_held_for_its_landing() {
        assert!(
            !advertisement_request("demo", GitService::UploadPack, None).is_receive_pack(),
            "an advertisement streams"
        );
        let push = smart_http::ServeRequest {
            method: "POST".to_owned(),
            path_info: "/demo.git/git-receive-pack".to_owned(),
            query_string: String::new(),
            content_type: None,
            content_length: None,
            content_encoding: None,
            git_protocol: None,
            remote_user: Some("actor".to_owned()),
            remote_addr: None,
        };
        assert!(push.is_receive_pack(), "a push is held for its landing");
        let fetch = smart_http::ServeRequest {
            path_info: "/demo.git/git-upload-pack".to_owned(),
            ..push
        };
        assert!(
            !fetch.is_receive_pack(),
            "a pack is never buffered to be inspected"
        );
    }
}
