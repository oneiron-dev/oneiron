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

mod origin;
mod pairing;
mod response;

use self::origin::{bearer_header, normalize_origin};
pub(crate) use self::pairing::{pair, parse_credential};
use self::response::{
    ReadFailure, describe_send_failure, read_capped, read_error_envelope, serialize_request,
};

/// Path prefix every facade verb hangs off.
const FACADE_PREFIX: &str = "v1/core/facade";

/// The header a slip holder's per-request proof crosses in.
const BINDING_HEADER: &str = "x-oneiron-binding";

/// Connect timeout: finite, so a black-holed address fails instead of hanging.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total request timeout, sized for a 32 MiB blob round trip.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Full-vault exports can be much larger than one ordinary verb response.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The remote half of [`crate::OneironClient`].
pub(crate) struct RemoteClient {
    base_url: Url,
    authorization: HeaderValue,
    holder: Option<Box<(CapabilitySlip, SigningKey)>>,
    agent: Client,
    // Export is a single large document. Keep an export-specific total timeout,
    // not the ordinary verbs' response-byte ceiling or short timeout.
    export_agent: Client,
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
            export_agent: self.export_agent.clone(),
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
        let export_agent = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(EXPORT_TIMEOUT)
            .build()
            .map_err(|error| transport_error(format!("could not build export client: {error}")))?;
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
            export_agent,
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
        let response = (if verb == "export" {
            &self.export_agent
        } else {
            &self.agent
        })
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
        // The ordinary facade has a strict success-body ceiling. Export alone
        // streams JSON directly into its required result: there is no second
        // whole-body buffer, and the response size is the archive's own size.
        // The export-specific total timeout still refuses a stalled peer.
        if verb == "export" {
            serde_json::from_reader(response).map_err(|error| {
                transport_error(format!(
                    "the server answered {status} for {verb} with an incomplete or invalid export: {error}"
                ))
            })
        } else {
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
                transport_error(format!(
                    "the server answered {status} for {verb} with a body this verb could not decode: {error}"
                ))
            })
        }
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

#[cfg(test)]
mod tests;
