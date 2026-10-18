//! Bounded host-owned GraphQL transport; credentials never enter the engine.

use std::io::Read;
use std::time::Duration;

use oneiron::LinearSyncError;
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
/// leave the host is safe to retry automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphQlTransportError {
    NotSent,
    Uncertain,
}

impl From<GraphQlTransportError> for LinearSyncError {
    fn from(error: GraphQlTransportError) -> Self {
        match error {
            GraphQlTransportError::NotSent => crate::invalid("Linear request was not sent"),
            GraphQlTransportError::Uncertain => {
                crate::invalid("Linear request delivery is uncertain")
            }
        }
    }
}

pub trait GraphQlExecutor {
    fn execute(&mut self, call: &GraphQlCall) -> Result<Value, GraphQlTransportError>;
}

/// Linear's own GraphQL API, the endpoint unless the host names another.
pub const LINEAR_GRAPHQL_ENDPOINT: &str = "https://api.linear.app/graphql";

/// Production Linear API transport. Keep this on the credential-bearing host.
#[derive(Clone)]
pub struct HttpLinearClient {
    client: reqwest::blocking::Client,
    endpoint: reqwest::Url,
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
        Ok(Self { client, endpoint })
    }
}

impl GraphQlExecutor for HttpLinearClient {
    fn execute(&mut self, call: &GraphQlCall) -> Result<Value, GraphQlTransportError> {
        let response = self
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
        if !response.status().is_success() {
            return Err(GraphQlTransportError::Uncertain);
        }
        let mut bytes = Vec::new();
        response
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| GraphQlTransportError::Uncertain)?;
        if bytes.len() > 1_048_576 {
            return Err(GraphQlTransportError::Uncertain);
        }
        serde_json::from_slice(&bytes).map_err(|_| GraphQlTransportError::Uncertain)
    }
}
