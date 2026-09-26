//! The remote backend: the ONE HTTP stack the SDK owns (ONE-1441 I13, D2).
//!
//! Neither language binding contains an HTTP client. JavaScript has no
//! `fetch`, Python has no `requests`, and both reach `oneiron-server` through
//! this file, so there is one place where a timeout, a body ceiling, or an
//! error envelope is decided.
//!
//! The client holds its credential and never believes it. A slip crosses
//! verbatim after `Authorization: Bearer `, and every request carries a fresh
//! holder proof signed with the connection key. The slip is parsed once, at
//! connect, only to hash it into that proof; its claims are never read:
//! authority is the server's to decide, and a client that inspected claims
//! would eventually start believing them. A host secret crosses as a bare
//! bearer.

use std::io::Read;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use oneiron::authority::CapabilitySlip;
use oneiron::memory::MemoryError;
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::caps::{MAX_REMOTE_REQUEST_BYTES, MAX_REMOTE_RESPONSE_BYTES};
use crate::error::{bad_request, forbidden, transport_error};

/// Path prefix every facade verb hangs off.
const FACADE_PREFIX: &str = "v1/core/facade";

/// The header a slip holder's per-request proof crosses in.
const BINDING_HEADER: &str = "x-oneiron-binding";

/// Maximum bytes read from a FAILING response before parsing is attempted.
///
/// Far smaller than the success ceiling and for a different reason: an error
/// body is a small JSON envelope, and anything large arriving on an error
/// status is a proxy's HTML apology. Reading 64 KiB is enough to parse the
/// envelope and little enough that a hostile endpoint cannot make the client
/// buffer a response it will refuse anyway.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Connect timeout: finite, so a black-holed address fails instead of hanging.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total request timeout, sized for a 32 MiB blob round trip.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The server's error envelope, exactly as `api/facade.rs` serializes it.
#[derive(serde::Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorBody,
    /// The receipt of the read that answered, beside the error it explains.
    #[serde(default)]
    narrowing: Option<oneiron::claim::ScopedReadReceipt>,
}

/// `{code, message, requestId, suggestions}`.
///
/// `code` is a `String` and stays one: collapsing an unrecognized future
/// engine code into a local enum is precisely the lossy step the raw-string
/// envelope exists to avoid. `requestId` is accepted and dropped — it is
/// diagnostic metadata, not a public field of the error contract.
#[derive(serde::Deserialize)]
struct ApiErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    suggestions: Vec<String>,
}

/// The remote half of [`crate::OneironClient`].
pub(crate) struct RemoteClient {
    base_url: Url,
    authorization: HeaderValue,
    holder: Option<Box<(CapabilitySlip, SigningKey)>>,
    agent: Client,
    stream_agent: reqwest::Client,
}

/// Hand-written so the bearer cannot reach a log through a derive.
///
/// `HeaderValue` already redacts itself once marked sensitive, so this impl is
/// belt-and-braces: the field is omitted entirely rather than trusted to print
/// as `Sensitive`.
impl std::fmt::Debug for RemoteClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteClient")
            .field("base_url", &self.base_url.as_str())
            .finish_non_exhaustive()
    }
}

impl Clone for RemoteClient {
    fn clone(&self) -> Self {
        Self {
            base_url: self.base_url.clone(),
            authorization: self.authorization.clone(),
            holder: self.holder.clone(),
            agent: self.agent.clone(),
            stream_agent: self.stream_agent.clone(),
        }
    }
}

impl RemoteClient {
    /// Validates the URL and credential shape, and builds the agent.
    ///
    /// This is ALL `connect` does. It claims no authority, mints no actor and
    /// makes no request: the first verb is the first round trip, and until
    /// then the server has not been asked to agree to anything.
    pub(crate) fn connect(
        url: &str,
        bearer: &str,
        holder: Option<SigningKey>,
    ) -> Result<Self, MemoryError> {
        let base_url = normalize_origin(url)?;
        let authorization = bearer_header(bearer)?;
        let agent = blocking_agent()?;
        let holder = match holder {
            Some(key) => {
                let slip = CapabilitySlip::from_token(bearer).map_err(|_| {
                    bad_request(
                        "the credential's slip is not a v2 slip token",
                        &["Pair again and pass the credential exactly as pair returned it."],
                    )
                })?;
                Some(Box::new((slip, key)))
            }
            None => None,
        };
        let stream_agent = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| {
                transport_error(format!("could not build streaming client: {error}"))
            })?;
        Ok(Self {
            stream_agent,
            base_url,
            authorization,
            holder,
            agent,
        })
    }

    /// The bearer, and for a slip holder a fresh holder proof: one per
    /// request, never reused.
    fn credential_headers(&self) -> Result<HeaderMap, MemoryError> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.authorization.clone());
        if let Some((slip, key)) = self.holder.as_deref() {
            let unsigned = || transport_error("could not sign this request's holder proof");
            let proof = oneiron::authority::holder_proof(slip, key, crate::unix_seconds_now())
                .map_err(|_| unsigned())?;
            let mut binding = HeaderValue::from_str(&proof.to_string()).map_err(|_| unsigned())?;
            binding.set_sensitive(true);
            headers.insert(BINDING_HEADER, binding);
        }
        Ok(headers)
    }

    /// The origin this client talks to, for diagnostics.
    pub(crate) fn base_url(&self) -> &str {
        self.base_url.as_str()
    }

    /// POSTs one facade verb and decodes its typed response.
    pub(crate) fn call<Q: Serialize, R: DeserializeOwned>(
        &self,
        verb: &str,
        request: &Q,
    ) -> Result<R, MemoryError> {
        let url = self.verb_url(verb)?;
        let body = serialize_request(request)?;
        let credential = self.credential_headers()?;
        let response = self
            .agent
            .post(url)
            .headers(credential)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(body)
            .send()
            .map_err(|error| transport_error(describe_send_failure(&error)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(read_error_envelope(response, status));
        }
        let bytes = read_capped(response, MAX_REMOTE_RESPONSE_BYTES).map_err(|failure| {
            match failure {
                ReadFailure::TooLarge => transport_error(format!(
                    "the server's response exceeded the {MAX_REMOTE_RESPONSE_BYTES}-byte read ceiling"
                )),
                ReadFailure::Io(message) => {
                    transport_error(format!("the server's response was truncated: {message}"))
                }
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            // A 2xx whose body is not the DTO is NOT a success. Saying so is
            // the difference between a caller seeing a typed failure and a
            // caller seeing a default-constructed result they will trust.
            transport_error(format!(
                "the server answered {status} with a body this verb could not decode: {error}"
            ))
        })
    }

    pub(crate) async fn llm_post(
        &self,
        request: &oneiron::LlmRequest,
        lease: &oneiron::BudgetLease,
    ) -> Result<reqwest::Response, oneiron::LlmError> {
        let path = "v1/llm/generate";
        let url = self
            .base_url
            .join(path)
            .map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        let bytes =
            serialize_request(request).map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        let credential = self
            .credential_headers()
            .map_err(|_| oneiron::FatalLlmError::Auth)?;
        self.stream_agent
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .headers(credential)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header("x-oneiron-budget-lease", lease.id())
            .body(bytes)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    oneiron::RetryableLlmError::Timeout.into()
                } else {
                    oneiron::RetryableLlmError::StreamCut.into()
                }
            })
    }

    pub(crate) async fn llm_stream(
        &self,
        request: &oneiron::LlmRequest,
        lease: &oneiron::BudgetLease,
    ) -> Result<reqwest::Response, oneiron::LlmError> {
        let url = self
            .base_url
            .join("v1/llm/stream")
            .map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        let bytes =
            serialize_request(request).map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        let credential = self
            .credential_headers()
            .map_err(|_| oneiron::FatalLlmError::Auth)?;
        self.stream_agent
            .post(url)
            .headers(credential)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/x-ndjson")
            .header("x-oneiron-budget-lease", lease.id())
            .body(bytes)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    oneiron::RetryableLlmError::Timeout.into()
                } else {
                    oneiron::RetryableLlmError::StreamCut.into()
                }
            })
    }

    /// Joins the canonical verb path onto the normalized origin.
    ///
    /// Built through `Url::join` against a base whose path always ends in `/`,
    /// so there is no string concatenation to get an ambiguous number of
    /// slashes wrong.
    fn verb_url(&self, verb: &str) -> Result<Url, MemoryError> {
        self.base_url
            .join(&format!("{FACADE_PREFIX}/{verb}"))
            .map_err(|error| transport_error(format!("could not build the {verb} URL: {error}")))
    }
}

/// The blocking client every facade verb and `pair` share.
fn blocking_agent() -> Result<Client, MemoryError> {
    Client::builder()
        // A redirect must not move a bearer request outside the validated
        // origin or downgrade HTTPS to cleartext HTTP.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|error| transport_error(format!("could not build the HTTP client: {error}")))
}

/// What a paired client stores, in one string:
/// `v2.cred.{slip hex}.{seed hex}`.
///
/// `{slip hex}` is the slip token after `v2.slip.`; `{seed hex}` is the
/// connection key's 32-byte Ed25519 seed as 64 lowercase hex. A key that
/// starts `v2.cred.` and does not parse is refused without being echoed. Any
/// other key — the host secret, or a bare slip the server will refuse —
/// crosses as a bare bearer.
const CREDENTIAL_PREFIX: &str = "v2.cred.";

/// Splits a key into the bearer it sends and the connection key it signs with.
pub(crate) fn parse_credential(key: &str) -> Result<(String, Option<SigningKey>), MemoryError> {
    let Some(credential) = key.strip_prefix(CREDENTIAL_PREFIX) else {
        return Ok((key.to_owned(), None));
    };
    let (slip, seed) = credential
        .rsplit_once('.')
        .and_then(|(slip, seed)| Some((slip, seed_from_hex(seed)?)))
        .ok_or_else(|| {
            bad_request(
                "the key is not a paired credential",
                &["Pass the credential exactly as pair returned it, or pair again."],
            )
        })?;
    Ok((
        format!("v2.slip.{slip}"),
        Some(SigningKey::from_bytes(&seed)),
    ))
}

fn seed_from_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut seed = [0; 32];
    for (slot, pair) in seed.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(seed)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The redeem route's success body.
#[derive(serde::Deserialize)]
struct Paired {
    token: String,
}

/// Redeems a pairing link once and returns `(origin, credential)`.
///
/// A fresh connection key signs the link's code and holder; the request
/// carries no `Authorization` header, because the link is the enrollment. It
/// builds no handle: the caller connects with what it returns.
pub(crate) fn pair(link: &str) -> Result<(String, String), MemoryError> {
    use ed25519_dalek::Signer;
    // The link and its code are never echoed: the code is the enrollment grant
    // until it is spent.
    let malformed = || {
        bad_request(
            "the pairing link does not parse",
            &["Pass the one-line link the server owner created, exactly as printed."],
        )
    };
    let (origin, code, holder_ref) =
        oneiron::authority::parse_pairing_link(link).map_err(|_| malformed())?;
    let base_url = normalize_origin(&origin)?;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let binding_key = key.verifying_key().to_bytes();
    let transcript =
        oneiron::authority::pairing_binding_transcript(&code, &binding_key, &holder_ref)
            .map_err(|_| malformed())?;
    let body = serialize_request(&serde_json::json!({
        "code": code,
        "holder_ref": holder_ref,
        "binding_key": lower_hex(&binding_key),
        "signature": lower_hex(&key.sign(&transcript).to_bytes()),
    }))?;
    let url = base_url
        .join("v1/core/pairing/redeem")
        .map_err(|error| transport_error(format!("could not build the pairing URL: {error}")))?;
    let response = blocking_agent()?
        .post(url)
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(body)
        .send()
        .map_err(|error| transport_error(describe_send_failure(&error)))?;
    let status = response.status();
    if !status.is_success() {
        return Err(read_error_envelope(response, status));
    }
    let bytes = read_capped(response, MAX_REMOTE_RESPONSE_BYTES)
        .map_err(|_| transport_error("the server's pairing reply was truncated or oversized"))?;
    let slip = serde_json::from_slice::<Paired>(&bytes)
        .ok()
        .and_then(|paired| paired.token.strip_prefix("v2.slip.").map(str::to_owned))
        .ok_or_else(|| transport_error(format!("the server answered {status} with no slip")))?;
    Ok((
        origin,
        format!("{CREDENTIAL_PREFIX}{slip}.{}", lower_hex(key.as_bytes())),
    ))
}

/// Normalizes the caller's origin exactly once (I13).
///
/// Everything a caller might append to an origin is refused rather than
/// silently dropped. A query string or fragment on a base URL means the caller
/// believes it carries meaning, and it does not: the facade path would replace
/// it. Userinfo is refused because a credential in a URL is a credential in
/// logs, shell history and error messages, and this SDK already has exactly
/// one place to put one.
fn normalize_origin(url: &str) -> Result<Url, MemoryError> {
    let mut parsed = Url::parse(url).map_err(|error| {
        // The raw origin is NEVER echoed here. A malformed URL can still carry
        // `user:password@`, and a syntax failure such as a bad port fires
        // before the userinfo arm below could refuse it, so repeating the input
        // would put the credential in exactly the logs this function exists to
        // keep it out of. The parse error names the syntax fault, not the
        // credential.
        bad_request(
            format!("the Oneiron URL is not a valid URL: {error}"),
            &["Pass an absolute origin such as http://127.0.0.1:8080."],
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(bad_request(
            "the Oneiron URL has an unsupported scheme",
            &["Use HTTPS, or HTTP only for loopback development."],
        ));
    }
    if !parsed.has_host() {
        return Err(bad_request(
            "the Oneiron URL names no host",
            &["Pass an absolute origin such as http://127.0.0.1:8080."],
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad_request(
            "the Oneiron URL must not carry userinfo",
            &["Remove user:password@ from the URL; pass the credential as the key argument."],
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(bad_request(
            "the Oneiron URL must not carry a query string or fragment",
            &["Pass only the origin; the SDK appends the facade path itself."],
        ));
    }
    if parsed.scheme() == "http" && !is_loopback_origin(&parsed) {
        return Err(bad_request(
            "the Oneiron URL requires HTTPS outside loopback development",
            &["Use an https:// origin; cleartext HTTP is allowed only on loopback."],
        ));
    }
    // A trailing slash is what makes `Url::join` treat the path as a directory
    // to append to rather than a file to replace.
    if !parsed.path().ends_with('/') {
        let path = format!("{}/", parsed.path());
        parsed.set_path(&path);
    }
    Ok(parsed)
}

/// Allows only literal loopback addresses and the exact localhost name.
/// No DNS lookup can turn a caller-chosen remote hostname into an exemption.
fn is_loopback_origin(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

/// Builds the `Authorization` header and marks it sensitive (D3).
///
/// The slip crosses VERBATIM. This function measures it and refuses an empty
/// or non-ASCII value — both of which cannot be a minted `v2` token — and does
/// not otherwise look at it. In particular it does not check for the `v2.`
/// prefix: the wire form is the server's contract to enforce, and a client
/// that validated it would have to be re-released to accept the next one.
fn bearer_header(key: &str) -> Result<HeaderValue, MemoryError> {
    if key.trim().is_empty() {
        return Err(forbidden(
            "connect() requires a paired credential",
            &[
                "Pair once with Oneiron.pair(link); the owner creates the link with: \
               oneiron-server token pair --scope core:read,core:write \
               --principal-ref <32hex> --actor-class human",
            ],
        ));
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| {
        forbidden(
            "the supplied key is not a valid HTTP header value",
            &["Pass the credential exactly as pair returned it."],
        )
    })?;
    // Marks the value redacted in this header map's own Debug output, so a
    // transport-level dump cannot print the credential.
    header.set_sensitive(true);
    Ok(header)
}

/// Serializes a request body and enforces the 64 MiB request ceiling.
///
/// Measured BEFORE the request is sent, so an oversized body costs one
/// serialization rather than an upload the server's `DefaultBodyLimit` would
/// reject at the far end after the bytes crossed the network.
fn serialize_request<Q: Serialize>(request: &Q) -> Result<Vec<u8>, MemoryError> {
    let body = serde_json::to_vec(request).map_err(|error| {
        bad_request(
            format!("this request could not be serialized: {error}"),
            &["Check the request for non-finite numbers or non-serializable values."],
        )
    })?;
    if body.len() > MAX_REMOTE_REQUEST_BYTES {
        return Err(bad_request(
            format!("the request body exceeds the {MAX_REMOTE_REQUEST_BYTES}-byte ceiling"),
            &["Send less in one call; blob versions cap at 32 MiB of raw content."],
        ));
    }
    Ok(body)
}

/// Why a read stopped short.
enum ReadFailure {
    /// The body was still going at the ceiling.
    TooLarge,
    /// The connection failed mid-body.
    Io(String),
}

/// Reads at most `limit` bytes, and reports overrun rather than truncating.
///
/// `take(limit + 1)` is the whole trick: reading one byte past the ceiling
/// distinguishes "exactly at the limit" from "over it" without ever buffering
/// the excess, so the refusal happens BEFORE any JSON or base64 decode
/// allocates against an attacker-chosen length.
fn read_capped(
    response: reqwest::blocking::Response,
    limit: usize,
) -> Result<Vec<u8>, ReadFailure> {
    let mut buffer = Vec::new();
    let mut reader = response.take(limit as u64 + 1);
    reader
        .read_to_end(&mut buffer)
        .map_err(|error| ReadFailure::Io(error.to_string()))?;
    if buffer.len() > limit {
        return Err(ReadFailure::TooLarge);
    }
    Ok(buffer)
}

/// Rebuilds the engine's refusal from a failing response, losslessly.
///
/// A body that does not parse as the envelope becomes a transport error whose
/// message names the status and nothing else. The foreign bytes are dropped on
/// purpose: an HTML error page rendered into a `message` or a `suggestion`
/// becomes text a caller displays, logs, or — in the worst case — executes.
fn read_error_envelope(
    response: reqwest::blocking::Response,
    status: reqwest::StatusCode,
) -> MemoryError {
    let Ok(bytes) = read_capped(response, MAX_ERROR_BODY_BYTES) else {
        return transport_error(format!(
            "the server answered {status} with an unreadable or oversized error body"
        ));
    };
    parse_error_envelope(&bytes).unwrap_or_else(|| {
        transport_error(format!(
            "the server answered {status} with a body that is not an Oneiron error envelope"
        ))
    })
}

/// Rebuilds a [`MemoryError`] from envelope bytes, or `None` if they are not
/// one.
///
/// Split out from the response handling so the lossless-mapping property can
/// be tested against bytes rather than against a live server.
fn parse_error_envelope(bytes: &[u8]) -> Option<MemoryError> {
    let envelope = serde_json::from_slice::<ApiErrorEnvelope>(bytes).ok()?;
    if envelope.error.code.is_empty() {
        // An envelope-shaped body with no code is not an Oneiron refusal; it
        // is something else that happened to have an `error` key.
        return None;
    }
    let suggestions = if envelope.error.suggestions.is_empty() {
        // The contract says `suggestions` is never empty. A server that sent
        // none is answered with the one suggestion that is always true rather
        // than with an empty array the caller has to special-case.
        vec!["Retry the call, and check the server logs for this request.".to_owned()]
    } else {
        envelope.error.suggestions
    };
    Some(MemoryError {
        code: envelope.error.code,
        message: envelope.error.message,
        suggestions,
        successor_short_id: None,
        gate_denial: None,
        read_receipt: envelope.narrowing.map(Box::new),
    })
}

/// Describes a send failure without leaking the URL's credentials or body.
fn describe_send_failure(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "the request to the Oneiron server timed out".to_owned();
    }
    if error.is_connect() {
        return "could not connect to the Oneiron server".to_owned();
    }
    "the request to the Oneiron server failed".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{RemoteClient, normalize_origin, parse_error_envelope};
    use ed25519_dalek::SigningKey;
    use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// A loopback peer that answers `count` requests with an empty 200 and
    /// hands back each request's header lines.
    fn peer(count: usize) -> (String, std::thread::JoinHandle<Vec<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let captured = std::thread::spawn(move || {
            (0..count)
                .map(|_| {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut reader = BufReader::new(&mut stream);
                    let mut headers = Vec::new();
                    let mut content_length = 0;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            content_length = value.trim().parse::<usize>().unwrap();
                        }
                        headers.push(line.trim_end().to_owned());
                    }
                    reader.read_exact(&mut vec![0; content_length]).unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .unwrap();
                    headers
                })
                .collect()
        });
        (origin, captured)
    }

    fn binding(headers: &[String]) -> Option<serde_json::Value> {
        headers.iter().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-oneiron-binding")
                .then(|| serde_json::from_str(value.trim()).unwrap())
        })
    }

    /// A slip minted on a temp vault, bound to its own connection key.
    fn paired() -> (
        tempfile::TempDir,
        oneiron::Vault,
        HostSlipIssuer,
        CapabilitySlip,
        SigningKey,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap();
        let issuer = HostSlipIssuer::from_secret(b"remote-holder-host").unwrap();
        let key = SigningKey::from_bytes(&[5; 32]);
        let mut claims = vault.ensure_host_root_slip(&issuer).unwrap().claims;
        claims.slip_id = [4; 32];
        claims.parent_id = None;
        claims.holder_ref = "remote-holder".to_owned();
        claims.binding_key = key.verifying_key().to_bytes();
        let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
        (dir, vault, issuer, slip, key)
    }

    fn call(client: &RemoteClient) {
        client
            .call::<_, serde_json::Value>("receipts", &serde_json::json!({}))
            .unwrap();
    }

    #[test]
    fn a_slip_holder_signs_each_request_with_a_proof_the_vault_accepts() {
        let (_dir, vault, issuer, slip, key) = paired();
        let (origin, captured) = peer(1);
        let client = RemoteClient::connect(&origin, &slip.to_token().unwrap(), Some(key)).unwrap();
        call(&client);
        let proof = binding(&captured.join().unwrap()[0]).unwrap();
        let signature: Vec<u8> = (0..128)
            .step_by(2)
            .map(|at| {
                u8::from_str_radix(&proof["signature"].as_str().unwrap()[at..at + 2], 16).unwrap()
            })
            .collect();
        assert!(
            vault
                .authenticate_capability_slip(
                    &issuer,
                    &slip,
                    proof["timestamp"].as_u64().unwrap(),
                    &signature,
                    proof["nonce"].as_str().unwrap().as_bytes(),
                )
                .is_ok()
        );
    }

    #[test]
    fn back_to_back_requests_carry_distinct_nonces() {
        let (_dir, _vault, _issuer, slip, key) = paired();
        let (origin, captured) = peer(2);
        let client = RemoteClient::connect(&origin, &slip.to_token().unwrap(), Some(key)).unwrap();
        call(&client);
        call(&client);
        let nonces: Vec<_> = captured
            .join()
            .unwrap()
            .iter()
            .map(|headers| binding(headers).unwrap()["nonce"].clone())
            .collect();
        assert_ne!(nonces[0], nonces[1]);
    }

    #[test]
    fn a_host_secret_crosses_as_a_bare_bearer() {
        let (origin, captured) = peer(1);
        let client = RemoteClient::connect(&origin, "host-secret", None).unwrap();
        call(&client);
        assert!(binding(&captured.join().unwrap()[0]).is_none());
    }

    #[test]
    fn the_streaming_request_carries_a_holder_proof() {
        use oneiron::{
            BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, LlmRequest,
            ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
        };
        let (_dir, _vault, _issuer, slip, key) = paired();
        let (origin, captured) = peer(1);
        let client = RemoteClient::connect(&origin, &slip.to_token().unwrap(), Some(key)).unwrap();
        let request = LlmRequest {
            model: ModelId::new("own/model@1").unwrap(),
            envelope: CallEnvelope {
                scope: Default::default(),
                purpose: CallPurpose::AnswerGen,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::AnswerGen,
                    ModelTierRef("default".into()),
                ),
                response_format: ResponseFormat::Text,
                locality: ModelLocality::OwnServer,
            },
            messages: vec![],
            tools: vec![],
            params: Default::default(),
            provider_options: Default::default(),
        };
        let guard =
            BudgetGuard::with_reserve_units("client", 100, 10, BudgetExhaustionPolicy::Suspend);
        let lease = guard.admit_for_request(&request).unwrap().lease;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(client.llm_stream(&request, &lease))
            .unwrap();
        assert!(binding(&captured.join().unwrap()[0]).is_some());
    }

    /// §Test/Shared #5 — an engine code the SDK has never heard of survives.
    #[test]
    fn remote_maps_api_error_envelope_losslessly() {
        let body = br#"{"error":{"code":"LEASE_REQUIRED","message":"deep recall needs a lease",
            "requestId":"facade-req-0000000000000001","suggestions":["Use effort standard."]}}"#;
        let error = parse_error_envelope(body).expect("a well-formed envelope parses");
        assert_eq!(error.code, "LEASE_REQUIRED");
        assert_eq!(error.message, "deep recall needs a lease");
        assert_eq!(error.suggestions, vec!["Use effort standard.".to_owned()]);
    }

    /// An unknown FUTURE code is carried as a string, never collapsed.
    #[test]
    fn unknown_future_codes_pass_through() {
        let body = br#"{"error":{"code":"SOME_FUTURE_CODE","message":"m","suggestions":["s"]}}"#;
        let error = parse_error_envelope(body).expect("parses");
        assert_eq!(error.code, "SOME_FUTURE_CODE");
    }

    /// The contract's non-empty `suggestions` guarantee is restored, not
    /// forwarded as an empty array.
    #[test]
    fn empty_suggestions_are_backfilled() {
        let body = br#"{"error":{"code":"BAD_REQUEST","message":"m","suggestions":[]}}"#;
        let error = parse_error_envelope(body).expect("parses");
        assert!(!error.suggestions.is_empty());
    }

    /// §Test/Shared #6 — foreign bodies are not envelopes and never become
    /// one.
    #[test]
    fn remote_rejects_non_oneiron_error_bodies() {
        for body in [
            &b"<html><body>502 Bad Gateway</body></html>"[..],
            &b"{\"error\":{\"code\":\"\",\"message\":\"\"}}"[..],
            &b"{\"message\":\"nope\"}"[..],
            &b"{\"error\":{\"code\":\"TRUNC\""[..],
            &b""[..],
        ] {
            assert!(
                parse_error_envelope(body).is_none(),
                "a non-envelope body must not become a typed refusal"
            );
        }
    }

    /// The origin is normalized once, into a joinable base.
    #[test]
    fn origin_normalization_produces_a_joinable_base() {
        let base = normalize_origin("http://127.0.0.1:8080").expect("normalizes");
        assert!(base.as_str().ends_with('/'));
        let joined = base.join("v1/core/facade/witness").expect("joins");
        assert_eq!(
            joined.as_str(),
            "http://127.0.0.1:8080/v1/core/facade/witness"
        );
    }

    /// A base carrying a path prefix keeps it, and the verb hangs off it.
    #[test]
    fn origin_normalization_preserves_a_path_prefix() {
        let base = normalize_origin("https://example.invalid/oneiron").expect("normalizes");
        let joined = base.join("v1/core/facade/recall").expect("joins");
        assert_eq!(
            joined.as_str(),
            "https://example.invalid/oneiron/v1/core/facade/recall"
        );
    }
}
