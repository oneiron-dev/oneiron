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
//! body and headers, less the hop-by-hop ones, `Host` and every credential
//! header, adding the held `Authorization`. It sends with the connector
//! client's policy: no proxy, no redirect, the connect and call bounds. The
//! answer goes back whole (its status, headers and a body within 16 MiB),
//! cleared of the presented value, and `no-store`. A request with an unknown
//! reference reads as unauthorized; one outside a call, as a conflict. Each
//! request is traced by connector, method, path and status; it lands on no
//! receipt yet (FIX [STDIO-UPSTREAM-SENDS-RECEIPT]).
//!
//! Loopback is not process identity: any process on this device that holds
//! a child's reference can send through its door while one of that child's
//! calls is in flight, as with the seat model door.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use oneiron::claim::CallerLocality;
use oneiron::secret_custody::{KeptSentValue, SentValue};
use rand_core::RngCore as _;
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

/// The headers that never pass the door either way: the hop-by-hop ones,
/// the target's `Host`, the length the sender sets again, and every
/// credential header.
const DROPPED_HEADERS: [&str; 13] = [
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
    "authorization",
    "x-api-key",
];

/// What one call presents to its connector's upstream, held at the door
/// for the call's span: the `Authorization` header its credential door
/// built, and the value to clear from what the upstream says. Both are
/// `None` for a call that presents nothing; its requests go on with no
/// credential.
#[derive(Default)]
pub struct UpstreamHeld {
    auth: Option<HeaderValue>,
    kept: Option<KeptSentValue>,
}

impl UpstreamHeld {
    /// The header a call presents, and the value it was built from.
    #[must_use]
    pub fn new(auth: Option<HeaderValue>, kept: Option<KeptSentValue>) -> Self {
        Self { auth, kept }
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
    /// What the call in flight on the child presents; `None` between calls.
    held: Option<Arc<UpstreamHeld>>,
}

/// A child's place at its door; dropping it closes the door.
pub struct UpstreamTicket {
    doors: Arc<UpstreamDoors>,
    reference: [u8; 32],
}

/// A call's hold at its child's door; dropping it ends the hold.
pub struct UpstreamHold {
    doors: Arc<UpstreamDoors>,
    reference: [u8; 32],
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
                held: None,
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

    /// The origin and the hold of the door the reference `presented` opens
    /// for the connector `name`.
    fn admit(&self, name: &str, presented: &str) -> Result<(String, Arc<UpstreamHeld>), Refusal> {
        let doors = lock(&self.doors);
        let door = doors
            .get(&digest(presented))
            .filter(|door| door.name == name)
            .ok_or(Refusal::Unknown)?;
        let held = door.held.clone().ok_or(Refusal::NotInCall)?;
        Ok((door.origin.clone(), held))
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
        if let Some(door) = lock(&self.doors.doors).get_mut(&self.reference) {
            door.held = Some(Arc::new(held));
        }
        UpstreamHold {
            doors: Arc::clone(&self.doors),
            reference: self.reference,
        }
    }
}

impl Drop for UpstreamHold {
    fn drop(&mut self) {
        if let Some(door) = lock(&self.doors.doors).get_mut(&self.reference) {
            door.held = None;
        }
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
    /// The upstream did not answer within the call bound.
    TimedOut,
    /// The upstream could not be reached, or its answer was not one
    /// readable body within 16 MiB.
    NoAnswer,
}

impl Refusal {
    /// Its status and a code, naming no connector, origin or reference.
    fn response(&self) -> Response {
        let (status, code) = match self {
            Self::Unknown => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotInCall => (StatusCode::CONFLICT, "no_call_in_flight"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"),
            Self::TimedOut => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            Self::NoAnswer => (StatusCode::BAD_GATEWAY, "no_answer"),
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

/// Sends one admitted request on to its connector's upstream, and its
/// answer back cleared of what the call presents.
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
    let (origin, held) = doors.admit(name, &reference)?;
    drop(reference);
    let body = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| Refusal::TooLarge)?;
    let client = doors.client().ok_or(Refusal::NoAnswer)?;
    let mut url = format!("{origin}{path}");
    if let Some(query) = parts.uri.query() {
        url.push('?');
        url.push_str(query);
    }
    let mut headers = passed_headers(&parts.headers);
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
