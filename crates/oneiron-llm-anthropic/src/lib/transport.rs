//! Host-owned execution seam: future/stream aliases, HTTP envelope types, stream frame, transport trait, error mapping.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use futures_core::Stream;
use oneiron::{BudgetLease, LlmError, LlmUsage, RetryableLlmError};
use serde_json::Value as JsonValue;

pub type AnthropicMessagesFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<AnthropicMessagesHttpResponse, AnthropicMessagesTransportError>>
            + Send
            + 'a,
    >,
>;

pub type AnthropicMessagesProviderStream<'a> = Pin<
    Box<
        dyn Stream<Item = Result<AnthropicMessagesStreamFrame, AnthropicMessagesTransportError>>
            + Send
            + 'a,
    >,
>;

#[derive(Debug, Clone, PartialEq)]
pub struct AnthropicMessagesHttpRequest {
    pub method: &'static str,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnthropicMessagesHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnthropicMessagesStreamFrame {
    Event(JsonValue),
    Abort { usage: LlmUsage },
    Status(AnthropicMessagesHttpResponse),
}

pub trait AnthropicMessagesTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: AnthropicMessagesHttpRequest,
        lease: &'a BudgetLease,
    ) -> AnthropicMessagesFuture<'a>;

    fn stream<'a>(
        &'a self,
        request: AnthropicMessagesHttpRequest,
        lease: &'a BudgetLease,
    ) -> Result<AnthropicMessagesProviderStream<'a>, AnthropicMessagesTransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnthropicMessagesTransportError {
    #[error("Anthropic Messages transport timed out")]
    Timeout,
    #[error("Anthropic Messages transport stream was cut")]
    StreamCut,
    #[error("Anthropic Messages transport server error")]
    Server,
    #[error("Anthropic Messages transport connection failed")]
    Connection,
}

impl From<AnthropicMessagesTransportError> for LlmError {
    fn from(error: AnthropicMessagesTransportError) -> Self {
        match error {
            AnthropicMessagesTransportError::Timeout => RetryableLlmError::Timeout.into(),
            AnthropicMessagesTransportError::StreamCut
            | AnthropicMessagesTransportError::Connection => RetryableLlmError::StreamCut.into(),
            AnthropicMessagesTransportError::Server => RetryableLlmError::ServerError.into(),
        }
    }
}
