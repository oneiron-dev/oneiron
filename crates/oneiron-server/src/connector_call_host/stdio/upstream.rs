//! A stdio connector's upstream door (B2; RULING L8-27-B2-STDIO = A;
//! ARCH-0069 `#door-reads-action`, `#door-sign-loopback`): an `mcp_stdio`
//! connector that names an `upstream` API calls it through this server's
//! loopback door, and never holds the credential its call presents.
//!
//! Each child started for such a connector gets two variables: the door's
//! URL for the connector, `{origin}/v1/connector/upstream/{name}`, as the
//! API's base URL, and a fresh reference to the door,
//! [`UPSTREAM_REFERENCE_PREFIX`] and 64 hex, as its API key. The door keeps
//! only the reference's digest, and forgets it when the child stops. While
//! a call is in flight on the child, the door holds what that call presents:
//! the `Authorization` header its credential door built, and the value to
//! clear from what the API says, as an HTTP connector's live session holds
//! its header for the call's span. One connector injection path, and no
//! broker wire change (FIX [CONNECTOR-CREDENTIALS-VIA-BROKER] is the later
//! row that moves every connector credential into the broker).
//!
//! A request at the door must come from this device and present the child's
//! reference, as a bearer (or `token`) credential or in `x-api-key`. The door
//! sends it on to the upstream origin with the same method, path, query,
//! body and headers, less the hop-by-hop ones, `Host`, the codings the child
//! asks for and every credential header, adding the held `Authorization`. It
//! sends with the connector client's policy: no proxy, no redirect, the
//! connect and call bounds. The call's issuer binding is read again before
//! each send, the last point before the credential leaves: while a change
//! the owner has not accepted holds it, or it cannot be read, nothing is sent
//! (FIX 9303). The answer goes back whole (its status, headers and a body
//! within 16 MiB), cleared of the presented value, and `no-store`; an answer
//! still in a content coding, which the clearing cannot read, is refused. A
//! request with an unknown reference reads as unauthorized; one outside a
//! call, as a conflict. Each request is traced by connector, method, path and
//! status; it lands on no receipt yet (FIX [STDIO-UPSTREAM-SENDS-RECEIPT]).
//!
//! A request is admitted only while a call is in flight, and lives no longer
//! than that call's hold: ending the hold aborts each request the door
//! admitted under it that is still running, while it reads the child's body
//! (so it is never sent), waits on the upstream or reads its answer (which
//! never reaches the child), and waits for each to end.
//!
//! Loopback is not process identity: any process on this device that holds
//! a child's reference can send through its door while one of that child's
//! calls is in flight, as with the seat model door.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, mpsc};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use oneiron::claim::CallerLocality;
use oneiron::secret_custody::{KeptSentValue, SentValue};
use oneiron::{EntityId, Vault};
use rand_core::RngCore as _;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::config::connectors::{StdioUpstream, normalize_name};
use crate::connector_call_host::{CALL_TIMEOUT, CONNECT_TIMEOUT};

/// The path the door's routes sit under, `/v1/connector/upstream/{name}/…`.
pub const UPSTREAM_DOOR_PATH: &str = "/v1/connector/upstream";

/// The prefix of a reference to an upstream door, so it is never read as a
/// slip, a seat model reference or an API key.
pub const UPSTREAM_REFERENCE_PREFIX: &str = "oneiron-connector.";

/// The largest request body the door takes, and the largest answer body it
/// gives back.
const MAX_BODY: usize = 16 * 1024 * 1024;

/// How long the end of a call's hold waits for the requests it aborts to
/// end.
const DRAIN_BOUND: Duration = Duration::from_secs(2);

/// The headers that never pass the door either way: the hop-by-hop ones,
/// the target's `Host`, the length the sender sets again, the codings the
/// child asks for (the door's client asks for those it decodes), and every
/// credential header.
const DROPPED_HEADERS: [&str; 14] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
    "authorization",
    "x-api-key",
];

/// What one call presents to its connector's upstream, held at the door
/// for the call's span: the `Authorization` header its credential door
/// built, the value to clear from what the upstream says, and the issuer
/// binding that governs its sends. The first two are `None` for a call that
/// presents nothing; its requests go on with no credential.
#[derive(Default)]
pub struct UpstreamHeld {
    auth: Option<HeaderValue>,
    kept: Option<KeptSentValue>,
    issuer: Option<UpstreamIssuer>,
}

impl UpstreamHeld {
    /// The header a call presents, the value it was built from, and the
    /// issuer binding read again before each of its sends.
    #[must_use]
    pub fn new(
        auth: Option<HeaderValue>,
        kept: Option<KeptSentValue>,
        issuer: Option<UpstreamIssuer>,
    ) -> Self {
        Self { auth, kept, issuer }
    }

    /// The hold on the call's issuer binding, read now: `None` while none
    /// holds it, or when no binding governs the call.
    ///
    /// # Errors
    ///
    /// When the binding cannot be read.
    pub fn issuer_hold(&self) -> oneiron::Result<Option<&'static str>> {
        self.issuer.as_ref().map_or(Ok(None), UpstreamIssuer::read)
    }
}

/// The issuer binding that governs a call's sends, read again before each
/// one (FIX 9303).
pub enum UpstreamIssuer {
    /// A call's governing connector key and tool.
    Row {
        vault: Arc<Vault>,
        key_ref: EntityId,
        tool: String,
    },
    /// Every binding of the catalog connector `connector`, as its listing
    /// reads them.
    Connector {
        vault: Arc<Vault>,
        connector: String,
    },
}

impl UpstreamIssuer {
    /// The hold on the binding, read now.
    fn read(&self) -> oneiron::Result<Option<&'static str>> {
        match self {
            Self::Row {
                vault,
                key_ref,
                tool,
            } => vault.connector_issuer_hold(key_ref, tool),
            Self::Connector { vault, connector } => {
                vault.connector_issuer_hold_for_connector(connector)
            }
        }
    }
}

/// The upstream doors of one server's stdio connector children, each found
/// by the digest of the reference its child holds.
#[derive(Default)]
pub struct UpstreamDoors {
    doors: Mutex<HashMap<[u8; 32], UpstreamDoor>>,
    /// The door's client, built at its first send; `None` when it could
    /// not be built.
    client: OnceLock<Option<reqwest::Client>>,
}

/// One child's door.
struct UpstreamDoor {
    /// The connector's normalized catalog name, as the door's URL names it.
    name: String,
    /// The upstream origin, with no trailing `/`.
    origin: String,
    /// The call in flight on the child; `None` between calls.
    call: Option<InFlight>,
}

/// What a door keeps of the call in flight on its child.
struct InFlight {
    /// What the call presents.
    held: Arc<UpstreamHeld>,
    /// Dropped when the call's hold ends, which aborts each request the
    /// door admitted under it.
    ended: watch::Sender<()>,
    /// Each admitted request keeps a clone until it ends; the hold's end
    /// waits for the last one.
    lease: mpsc::Sender<()>,
}

/// One request the door admitted: its upstream origin, what its call
/// presents, and its lease on that call.
struct Admitted {
    origin: String,
    held: Arc<UpstreamHeld>,
    _lease: mpsc::Sender<()>,
}

/// A child's place at its door; dropping it closes the door, and aborts
/// each request of a call still held there.
pub struct UpstreamTicket {
    doors: Arc<UpstreamDoors>,
    reference: [u8; 32],
}

/// A call's hold at its child's door. Dropping it ends the hold: each
/// request the door admitted under it is aborted, and the drop waits up to
/// two seconds for them to end, so drop it off the async runtime.
pub struct UpstreamHold {
    doors: Arc<UpstreamDoors>,
    reference: [u8; 32],
    /// Disconnected once the hold's last admitted request has ended.
    drained: mpsc::Receiver<()>,
}

/// The variables that point a child's upstream API at its door: the base
/// URL, and the child's reference to the door as its API key.
pub struct UpstreamEnv {
    vars: [(String, Zeroizing<String>); 2],
}

impl UpstreamEnv {
    /// Sets its variables on the child's process.
    pub(super) fn apply(&self, command: &mut std::process::Command) {
        for (name, value) in &self.vars {
            command.env(name, value.as_str());
        }
    }
}

impl UpstreamDoors {
    /// Opens a door for one child of the connector `name`, which calls
    /// `upstream`, reached on this server's loopback `door_origin`: the
    /// child's ticket, and the variables its environment gets.
    #[must_use]
    pub fn open(
        self: &Arc<Self>,
        name: &str,
        upstream: &StdioUpstream,
        door_origin: &str,
    ) -> (UpstreamTicket, UpstreamEnv) {
        let name = normalize_name(name);
        let reference = mint_reference();
        let digest = digest(&reference);
        let base_url = Zeroizing::new(format!(
            "{}{UPSTREAM_DOOR_PATH}/{name}",
            door_origin.trim_end_matches('/')
        ));
        lock(&self.doors).insert(
            digest,
            UpstreamDoor {
                name,
                origin: upstream.origin.trim_end_matches('/').to_owned(),
                call: None,
            },
        );
        let ticket = UpstreamTicket {
            doors: Arc::clone(self),
            reference: digest,
        };
        let env = UpstreamEnv {
            vars: [
                (upstream.base_url_env.clone(), base_url),
                (upstream.token_env.clone(), reference),
            ],
        };
        (ticket, env)
    }

    /// A request the door the reference `presented` opens for the connector
    /// `name` admits, and the signal of its call's end.
    fn admit(
        &self,
        name: &str,
        presented: &str,
    ) -> Result<(Admitted, watch::Receiver<()>), Refusal> {
        let doors = lock(&self.doors);
        let door = doors
            .get(&digest(presented))
            .filter(|door| door.name == name)
            .ok_or(Refusal::Unknown)?;
        let call = door.call.as_ref().ok_or(Refusal::NotInCall)?;
        let admitted = Admitted {
            origin: door.origin.clone(),
            held: Arc::clone(&call.held),
            _lease: call.lease.clone(),
        };
        Ok((admitted, call.ended.subscribe()))
    }

    /// The connector client's policy: no proxy, no redirect, its connect
    /// and call bounds.
    fn client(&self) -> Option<&reqwest::Client> {
        self.client
            .get_or_init(|| {
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .connect_timeout(CONNECT_TIMEOUT)
                    .timeout(CALL_TIMEOUT)
                    .build()
                    .ok()
            })
            .as_ref()
    }
}

impl UpstreamTicket {
    /// Holds what a call presents at this door until the returned hold is
    /// dropped.
    #[must_use]
    pub fn hold(&self, held: UpstreamHeld) -> UpstreamHold {
        let (lease, drained) = mpsc::channel();
        if let Some(door) = lock(&self.doors.doors).get_mut(&self.reference) {
            door.call = Some(InFlight {
                held: Arc::new(held),
                ended: watch::channel(()).0,
                lease,
            });
        }
        UpstreamHold {
            doors: Arc::clone(&self.doors),
            reference: self.reference,
            drained,
        }
    }
}

impl Drop for UpstreamHold {
    fn drop(&mut self) {
        // Taken off its door, the call admits no more requests, and those it
        // admitted are aborted.
        let call = lock(&self.doors.doors)
            .get_mut(&self.reference)
            .and_then(|door| door.call.take());
        drop(call);
        let _ = self.drained.recv_timeout(DRAIN_BOUND);
    }
}

impl Drop for UpstreamTicket {
    fn drop(&mut self) {
        lock(&self.doors.doors).remove(&self.reference);
    }
}

/// A fresh reference: 32 random bytes from the OS, as hex, under
/// [`UPSTREAM_REFERENCE_PREFIX`].
fn mint_reference() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    rand_core::OsRng.fill_bytes(&mut bytes[..]);
    let mut text = Zeroizing::new(String::with_capacity(UPSTREAM_REFERENCE_PREFIX.len() + 64));
    text.push_str(UPSTREAM_REFERENCE_PREFIX);
    for byte in bytes.iter() {
        // Written in place: no unwiped copy of the hex is made.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn digest(reference: &str) -> [u8; 32] {
    *blake3::hash(reference.as_bytes()).as_bytes()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The door's routes, on `doors`: any method, at the connector's base URL
/// and every path below it.
pub fn upstream_door_routes<S>(doors: Arc<UpstreamDoors>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(&format!("{UPSTREAM_DOOR_PATH}/{{name}}"), any(door))
        .route(
            &format!("{UPSTREAM_DOOR_PATH}/{{name}}/{{*path}}"),
            any(door),
        )
        .with_state(doors)
}

/// Why the door sent nothing on, or had no answer to give back.
enum Refusal {
    /// The request is not from this device, or presents no open door's
    /// reference for the connector its path names.
    Unknown,
    /// The door is open, and no call is in flight on its child.
    NotInCall,
    /// The request's body is not one readable body within 16 MiB.
    TooLarge,
    /// The call's issuer binding meets a change the owner has not accepted,
    /// or cannot be read (FIX 9303).
    Held,
    /// The upstream did not answer within the call bound.
    TimedOut,
    /// The upstream could not be reached, or its answer was not one
    /// readable body within 16 MiB.
    NoAnswer,
    /// The answer is still in a content coding, so the presented value
    /// could not be cleared from it.
    Encoded,
}

impl Refusal {
    /// Its status and a code, naming no connector, origin or reference.
    fn response(&self) -> Response {
        let (status, code) = match self {
            Self::Unknown => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotInCall => (StatusCode::CONFLICT, "no_call_in_flight"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"),
            Self::Held => (StatusCode::FORBIDDEN, "issuer_held"),
            Self::TimedOut => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            Self::NoAnswer => (StatusCode::BAD_GATEWAY, "no_answer"),
            Self::Encoded => (StatusCode::BAD_GATEWAY, "encoded_answer"),
        };
        (
            status,
            axum::Json(serde_json::json!({ "error": { "code": code } })),
        )
            .into_response()
    }
}

async fn door(State(doors): State<Arc<UpstreamDoors>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let mut response = forward(&doors, parts, body)
        .await
        .unwrap_or_else(|refusal| refusal.response());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Admits one request at the door, and sends it on to its connector's
/// upstream for as long as its call's hold lasts.
async fn forward(
    doors: &UpstreamDoors,
    parts: axum::http::request::Parts,
    body: Body,
) -> Result<Response, Refusal> {
    if crate::auth::caller_locality(&parts.headers, &parts.extensions) != CallerLocality::OnDevice {
        return Err(Refusal::Unknown);
    }
    let (name, path) = door_target(parts.uri.path()).ok_or(Refusal::Unknown)?;
    let reference = presented_reference(&parts.headers).ok_or(Refusal::Unknown)?;
    let (admitted, mut ended) = doors.admit(name, &reference)?;
    drop(reference);
    // The hold's end aborts the request wherever it is.
    tokio::select! {
        biased;
        _ = ended.changed() => Err(Refusal::NotInCall),
        answer = send_on(doors, &admitted, name, path, &parts, body) => answer,
    }
}

/// Sends one admitted request on to its connector's upstream, presenting
/// what its call holds, and its answer back cleared of it.
async fn send_on(
    doors: &UpstreamDoors,
    admitted: &Admitted,
    name: &str,
    path: &str,
    parts: &axum::http::request::Parts,
    body: Body,
) -> Result<Response, Refusal> {
    let body = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| Refusal::TooLarge)?;
    let client = doors.client().ok_or(Refusal::NoAnswer)?;
    let held = &admitted.held;
    let mut url = format!("{}{path}", admitted.origin);
    if let Some(query) = parts.uri.query() {
        url.push('?');
        url.push_str(query);
    }
    let mut headers = passed_headers(&parts.headers);
    // The last point before the credential leaves.
    match held.issuer_hold() {
        Ok(None) => {}
        Ok(Some(_)) => return Err(Refusal::Held),
        Err(error) => {
            tracing::warn!(%error, "connector issuer binding not read");
            return Err(Refusal::Held);
        }
    }
    if let Some(auth) = &held.auth {
        headers.insert(header::AUTHORIZATION, auth.clone());
    }
    let mut answer = client
        .request(parts.method.clone(), url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                Refusal::TimedOut
            } else {
                Refusal::NoAnswer
            }
        })?;
    let status = answer.status();
    tracing::info!(
        connector = name,
        method = %parts.method,
        path,
        status = status.as_u16(),
        "a stdio connector's upstream request went through its door"
    );
    // The client decodes the codings it asks for and takes their header
    // off; a body still coded is not what the clearing reads.
    if held.kept.is_some() && coded(answer.headers()) {
        return Err(Refusal::Encoded);
    }
    let mut reply_headers = passed_headers(answer.headers());
    let mut bytes = Vec::new();
    while let Some(chunk) = answer.chunk().await.map_err(|_| Refusal::NoAnswer)? {
        if bytes.len() + chunk.len() > MAX_BODY {
            return Err(Refusal::NoAnswer);
        }
        bytes.extend_from_slice(&chunk);
    }
    if let Some(kept) = &held.kept {
        let value = kept.sent();
        value.clear_bytes(&mut bytes);
        clear_headers(&mut reply_headers, &value);
    }
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = reply_headers;
    Ok(response)
}

/// Whether an answer's body is still coded once the client has read it: a
/// content coding other than `identity`, or a transfer coding other than
/// `chunked`, named in any form.
fn coded(headers: &HeaderMap) -> bool {
    names_a_coding(headers, header::CONTENT_ENCODING, &["identity"])
        || names_a_coding(headers, header::TRANSFER_ENCODING, &["identity", "chunked"])
}

/// Whether any value of the header `name` names a coding outside `plain`;
/// a value that is not text names one.
fn names_a_coding(headers: &HeaderMap, name: header::HeaderName, plain: &[&str]) -> bool {
    headers.get_all(name).iter().any(|value| {
        let Ok(text) = value.to_str() else {
            return true;
        };
        text.split(',').map(str::trim).any(|coding| {
            !coding.is_empty() && !plain.iter().any(|plain| coding.eq_ignore_ascii_case(plain))
        })
    })
}

/// The connector name and the upstream path of a door request's path: the
/// segment after [`UPSTREAM_DOOR_PATH`], and the rest from its `/` on (`/`
/// at the base URL itself).
fn door_target(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix(UPSTREAM_DOOR_PATH)?.strip_prefix('/')?;
    Some(match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, "/"),
    })
}

/// The reference a request presents: as a bearer or `token` credential in
/// `Authorization`, or in `x-api-key`. Two that disagree present none.
fn presented_reference(headers: &HeaderMap) -> Option<Zeroizing<String>> {
    let api_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().split_once(' '))
        .filter(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("token")
        })
        .map(|(_, token)| token.trim());
    let reference = match (api_key, authorization) {
        (Some(api_key), Some(authorization)) if api_key != authorization => return None,
        (Some(reference), _) | (None, Some(reference)) => reference,
        (None, None) => return None,
    };
    reference
        .starts_with(UPSTREAM_REFERENCE_PREFIX)
        .then(|| Zeroizing::new(reference.to_owned()))
}

/// `headers` less [`DROPPED_HEADERS`].
fn passed_headers(headers: &HeaderMap) -> HeaderMap {
    let mut passed = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if !DROPPED_HEADERS.contains(&name.as_str()) {
            passed.append(name, value.clone());
        }
    }
    passed
}

/// Each header value cleared of `value`; one that is not text is dropped,
/// since it cannot be cleared.
fn clear_headers(headers: &mut HeaderMap, value: &SentValue<'_>) {
    let mut cleared = HeaderMap::with_capacity(headers.len());
    for (name, header_value) in headers.iter() {
        let Ok(text) = header_value.to_str() else {
            continue;
        };
        let mut text = text.to_owned();
        value.clear_string(&mut text);
        if let Ok(header_value) = HeaderValue::from_str(&text) {
            cleared.append(name, header_value);
        }
    }
    *headers = cleared;
}
