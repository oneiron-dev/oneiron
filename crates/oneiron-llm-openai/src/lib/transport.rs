//! Host-owned execution seam: future/stream aliases, HTTP envelope types, stream frame, transport trait, error mapping.

use futures_core::Stream;
use oneiron::{BudgetLease, LlmError, LlmUsage, RetryableLlmError};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

pub type OpenAiCompatFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<OpenAiCompatHttpResponse, OpenAiCompatTransportError>>
            + Send
            + 'a,
    >,
>;

pub type OpenAiCompatProviderStream<'a> = Pin<
    Box<dyn Stream<Item = Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>> + Send + 'a>,
>;

#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiCompatHttpRequest {
    pub method: &'static str,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiCompatHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OpenAiCompatStreamFrame {
    Chunk(JsonValue),
    Abort { usage: LlmUsage },
    Status(OpenAiCompatHttpResponse),
}

pub trait OpenAiCompatTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        lease: &'a BudgetLease,
    ) -> OpenAiCompatFuture<'a>;

    fn stream<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        lease: &'a BudgetLease,
    ) -> Result<OpenAiCompatProviderStream<'a>, OpenAiCompatTransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenAiCompatTransportError {
    #[error("OpenAI-compatible transport timed out")]
    Timeout,
    #[error("OpenAI-compatible transport stream was cut")]
    StreamCut,
    #[error("OpenAI-compatible transport server error")]
    Server,
    #[error("OpenAI-compatible transport connection failed")]
    Connection,
}

impl From<OpenAiCompatTransportError> for LlmError {
    fn from(error: OpenAiCompatTransportError) -> Self {
        match error {
            OpenAiCompatTransportError::Timeout => RetryableLlmError::Timeout.into(),
            OpenAiCompatTransportError::StreamCut | OpenAiCompatTransportError::Connection => {
                RetryableLlmError::StreamCut.into()
            }
            OpenAiCompatTransportError::Server => RetryableLlmError::ServerError.into(),
        }
    }
}
