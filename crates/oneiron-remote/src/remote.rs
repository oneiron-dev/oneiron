//! The remote backend: the ONE HTTP stack the SDK owns (ONE-1441 I13, D2).
//!
//! Neither language binding contains an HTTP client. JavaScript has no
//! `fetch`, Python has no `requests`, and both reach `oneiron-server` through
//! this file, so there is one place where a timeout, a body ceiling, or an
//! error envelope is decided.
//!
//! The client is deliberately incurious about its credential. The minted slip
//! is placed verbatim after `Authorization: Bearer ` and never parsed, split,
//! reordered, or validated: authority is the server's to decide, and a client
//! that inspected claims would eventually start believing them.

use std::io::Read;
use std::time::Duration;

use oneiron::memory::MemoryError;
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::caps::{MAX_REMOTE_REQUEST_BYTES, MAX_REMOTE_RESPONSE_BYTES};
use crate::error::{bad_request, forbidden, transport_error};

/// Path prefix every facade verb hangs off.
const FACADE_PREFIX: &str = "v1/core/facade";

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
    agent: Client,
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
            agent: self.agent.clone(),
        }
    }
}

impl RemoteClient {
    /// Validates the URL and credential shape, and builds the agent.
    ///
    /// This is ALL `connect` does. It claims no authority, mints no actor and
    /// makes no request: the first verb is the first round trip, and until
    /// then the server has not been asked to agree to anything.
    pub(crate) fn connect(url: &str, key: &str) -> Result<Self, MemoryError> {
        let base_url = normalize_origin(url)?;
        let authorization = bearer_header(key)?;
        let agent = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| {
                transport_error(format!("could not build the HTTP client: {error}"))
            })?;
        Ok(Self {
            base_url,
            authorization,
            agent,
        })
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
        let response = self
            .agent
            .post(url)
            .header(AUTHORIZATION, self.authorization.clone())
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
        bad_request(
            format!("{url:?} is not a valid URL: {error}"),
            &["Pass an absolute origin such as http://127.0.0.1:8080."],
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(bad_request(
            format!("unsupported URL scheme {:?}", parsed.scheme()),
            &["Use an http:// or https:// origin."],
        ));
    }
    if !parsed.has_host() {
        return Err(bad_request(
            format!("{url:?} names no host"),
            &["Pass an absolute origin such as http://127.0.0.1:8080."],
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad_request(
            "the Oneiron URL must not carry userinfo",
            &["Remove user:password@ from the URL; pass the slip as the key argument."],
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(bad_request(
            "the Oneiron URL must not carry a query string or fragment",
            &["Pass only the origin; the SDK appends the facade path itself."],
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
            "connect() requires a minted slip",
            &[
                "Mint one with: oneiron-server token mint --scope core:read,core:write \
               --principal-ref <32hex> --actor-class human",
            ],
        ));
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| {
        forbidden(
            "the supplied key is not a valid HTTP header value",
            &["Pass the minted v2.<claims>.<mac-hex> slip exactly as the server printed it."],
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
    format!("the request to the Oneiron server failed: {error}")
}

#[cfg(test)]
mod tests {
    use super::{normalize_origin, parse_error_envelope};

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
