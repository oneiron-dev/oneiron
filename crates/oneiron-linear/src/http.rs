//! Host-owned GraphQL transport; credentials never enter the engine.
//!
//! A response is kept whole however large it is (FIX 8610): it streams to an
//! unnamed spool file first, and a decode takes its bytes on the host's fair
//! memory line ([`LinearBodyLine`]) before it allocates them. A decode that
//! waits out its turn is [`GraphQlTransportError::Waiting`], never a size
//! refusal; transport timeouts are the host's request policy, unchanged.

use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::time::Duration;

use oneiron::LinearSyncError;
use oneiron::linear_sync::LinearWait;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde_json::{Value, json};

use crate::invalid;

/// One exact GraphQL call for the source or outbound door.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphQlCall {
    pub query: &'static str,
    pub variables: Value,
}

impl GraphQlCall {
    pub(crate) fn body(&self) -> Value {
        json!({"query": self.query, "variables": self.variables})
    }
}

/// Host transport. Mutations must be invoked by an authorized outbound door,
/// not directly by the mirror's egress adapter.
/// Typed delivery certainty. Only a failure before any request bytes could
/// leave the host, or the authenticated endpoint's refusal of the
/// credential, is safe to send again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphQlTransportError {
    NotSent,
    Uncertain,
    /// The authenticated endpoint answered `status` (401): it refused the
    /// credential and ran nothing (FIX 8611). A governed retry of the same
    /// operation may send it again once the credential is repaired.
    Rejected {
        status: u16,
    },
    /// The response arrived and is kept; the host's memory line had no room
    /// to decode it before its wait ran out (FIX 8610).
    Waiting,
}

impl From<GraphQlTransportError> for LinearSyncError {
    fn from(error: GraphQlTransportError) -> Self {
        match error {
            GraphQlTransportError::NotSent => crate::invalid("Linear request was not sent"),
            GraphQlTransportError::Uncertain => {
                crate::invalid("Linear request delivery is uncertain")
            }
            GraphQlTransportError::Rejected { status } => crate::invalid(&format!(
                "Linear endpoint refused the credential ({status}); nothing ran"
            )),
            GraphQlTransportError::Waiting => Self::Waiting(LinearWait::BodyMemory),
        }
    }
}

/// A tracker response as the transport hands it over.
#[derive(Debug)]
pub enum GraphQlBody {
    /// The response, decoded.
    Decoded(Value),
    /// The response's whole bytes, undecoded, in an unnamed file read from
    /// its start.
    Spooled(std::fs::File),
}

pub trait GraphQlExecutor {
    fn execute(&mut self, call: &GraphQlCall) -> Result<Value, GraphQlTransportError>;

    /// The response before it is decoded, for a caller that keeps it first
    /// (the outbound journal). By default the decoded response.
    ///
    /// # Errors
    ///
    /// As [`Self::execute`].
    fn execute_body(&mut self, call: &GraphQlCall) -> Result<GraphQlBody, GraphQlTransportError> {
        self.execute(call).map(GraphQlBody::Decoded)
    }
}

/// The host's fair line for the memory a decoded tracker body takes (FIX
/// 8610): a decode takes its bytes before it allocates them and holds them
/// until it ends, at once while the line has room, else at its turn. A
/// decode larger than the whole line waits to run alone; none is refused for
/// its size.
pub trait LinearBodyLine: Send + Sync {
    /// Holds `bytes` until the returned hold drops; `None` when the host's
    /// wait ran out first.
    fn hold(&self, bytes: u64) -> Option<Box<dyn Send>>;
}

/// Decodes the whole of `reader`, `len` bytes, holding them on `line` first.
pub(crate) fn decode_held(
    line: Option<&dyn LinearBodyLine>,
    len: u64,
    reader: impl Read,
) -> Result<Value, GraphQlTransportError> {
    let _held = match line {
        Some(line) => Some(line.hold(len).ok_or(GraphQlTransportError::Waiting)?),
        None => None,
    };
    serde_json::from_reader(std::io::BufReader::new(reader))
        .map_err(|_| GraphQlTransportError::Uncertain)
}

/// Linear's own GraphQL API, the endpoint unless the host names another.
pub const LINEAR_GRAPHQL_ENDPOINT: &str = "https://api.linear.app/graphql";

/// Production Linear API transport. Keep this on the credential-bearing host.
#[derive(Clone)]
pub struct HttpLinearClient {
    client: reqwest::blocking::Client,
    endpoint: reqwest::Url,
    body_line: Option<Arc<dyn LinearBodyLine>>,
}

impl HttpLinearClient {
    /// Constructs a client for Linear's fixed HTTPS API, with redirects disabled.
    /// The token lives only in the host HTTP client's sensitive header value.
    ///
    /// # Errors
    /// Returns a transport error for an empty/invalid token or TLS client setup.
    pub fn new(api_key: &str) -> Result<Self, LinearSyncError> {
        Self::with_timeout(api_key, Duration::from_secs(30))
    }

    /// Constructs the same transport with the host's resolved request policy.
    pub fn with_timeout(api_key: &str, timeout: Duration) -> Result<Self, LinearSyncError> {
        let endpoint = reqwest::Url::parse(LINEAR_GRAPHQL_ENDPOINT)
            .map_err(|_| invalid("Linear GraphQL endpoint is invalid"))?;
        Self::with_endpoint(api_key, endpoint, timeout)
    }

    /// The same transport against `endpoint`, a GraphQL endpoint the host
    /// configured and validated (OF-427 C10). Redirects stay off.
    pub fn with_endpoint(
        api_key: &str,
        endpoint: reqwest::Url,
        timeout: Duration,
    ) -> Result<Self, LinearSyncError> {
        if timeout.is_zero() {
            return Err(invalid("Linear request timeout is zero"));
        }
        if api_key.trim().is_empty() {
            return Err(invalid("Linear API key is empty"));
        }
        let mut value = HeaderValue::from_str(api_key)
            .map_err(|_| invalid("Linear API key is not a valid header"))?;
        value.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value);
        let client = reqwest::blocking::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| invalid("Linear HTTP client setup failed"))?;
        Ok(Self {
            client,
            endpoint,
            body_line: None,
        })
    }

    /// This transport, decoding each response on the host's memory `line`.
    #[must_use]
    pub fn with_body_line(mut self, line: Arc<dyn LinearBodyLine>) -> Self {
        self.body_line = Some(line);
        self
    }

    /// Sends `call` and spools the whole response, undecoded: the file read
    /// from its start, and its length.
    fn spool(&self, call: &GraphQlCall) -> Result<(std::fs::File, u64), GraphQlTransportError> {
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .json(&call.body())
            .send()
            .map_err(|error| {
                if error.is_connect() {
                    GraphQlTransportError::NotSent
                } else {
                    GraphQlTransportError::Uncertain
                }
            })?;
        // Every request carries the credential, so a 401 is the endpoint's
        // refusal of it: nothing ran. Any other failure may have run.
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(GraphQlTransportError::Rejected {
                status: reqwest::StatusCode::UNAUTHORIZED.as_u16(),
            });
        }
        if !response.status().is_success() {
            return Err(GraphQlTransportError::Uncertain);
        }
        let mut file = tempfile::tempfile().map_err(|_| GraphQlTransportError::Uncertain)?;
        let len = std::io::copy(&mut response, &mut file)
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        Ok((file, len))
    }
}

impl GraphQlExecutor for HttpLinearClient {
    fn execute(&mut self, call: &GraphQlCall) -> Result<Value, GraphQlTransportError> {
        let (file, len) = self.spool(call)?;
        decode_held(self.body_line.as_deref(), len, file)
    }

    fn execute_body(&mut self, call: &GraphQlCall) -> Result<GraphQlBody, GraphQlTransportError> {
        self.spool(call).map(|(file, _)| GraphQlBody::Spooled(file))
    }
}
