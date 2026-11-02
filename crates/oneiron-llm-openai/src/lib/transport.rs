//! Host-owned execution seam: future/stream aliases, HTTP envelope types, stream frame, transport trait, error mapping.

use futures_core::Stream;
use oneiron::{BudgetLease, LlmError, LlmUsage, RetryableLlmError};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

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
    /// The call's segment manifest, as the host set it on the request
    /// (DESIGN-V2 R2); only the native EXL3 transport reads it.
    pub host_segments: Option<Arc<oneiron::llm::SegmentManifest>>,
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
    /// A socket transport's call never left this side: `stage` failed.
    #[error("OpenAI-compatible transport did not send the call ({stage}): {detail}")]
    NotSent { stage: &'static str, detail: String },
    /// A socket transport's I/O failed after the call went out: it may have run.
    #[error("OpenAI-compatible transport I/O failed after send ({stage}): {detail}")]
    Io { stage: &'static str, detail: String },
    /// The far end refused the call before anything ran.
    #[error("OpenAI-compatible transport call was refused ({code}): {message}")]
    Refused { code: String, message: String },
    /// The far end sent a frame the call cannot take where it came.
    #[error("OpenAI-compatible transport got an unexpected frame: {0}")]
    UnexpectedFrame(String),
    /// The far end ended the call with this error where no error reply fits.
    #[error("OpenAI-compatible transport call ended with an error: {0}")]
    EndedWithError(String),
}

impl From<OpenAiCompatTransportError> for LlmError {
    /// The typed socket faults are the retryable cut they always were, now
    /// carrying their cause (FIX 10403), so a result row or receipt names it.
    fn from(error: OpenAiCompatTransportError) -> Self {
        match error {
            OpenAiCompatTransportError::Timeout => RetryableLlmError::Timeout.into(),
            OpenAiCompatTransportError::StreamCut | OpenAiCompatTransportError::Connection => {
                RetryableLlmError::StreamCut.into()
            }
            OpenAiCompatTransportError::NotSent { stage, detail } => {
                RetryableLlmError::not_sent(stage, detail).into()
            }
            OpenAiCompatTransportError::Io { stage, detail } => {
                RetryableLlmError::io_after_send(stage, detail).into()
            }
            OpenAiCompatTransportError::Refused { code, message } => {
                RetryableLlmError::refused(&code, &message).into()
            }
            OpenAiCompatTransportError::UnexpectedFrame(detail) => {
                RetryableLlmError::unexpected_frame(detail).into()
            }
            OpenAiCompatTransportError::EndedWithError(detail) => {
                RetryableLlmError::ended_with_error(detail).into()
            }
            OpenAiCompatTransportError::Server => RetryableLlmError::ServerError.into(),
        }
    }
}
