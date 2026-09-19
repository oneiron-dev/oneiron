//! Own-server raw LLM transport over the SDK's single authenticated HTTP client.
use crate::remote::RemoteClient;
use futures_core::Stream;
use oneiron::llm::BudgetDenied;
use oneiron::{
    BudgetLease, FatalLlmError, LlmError, LlmGenerateFuture, LlmRequest, LlmStream, LlmStreamEvent,
    LlmStreamResult, RetryableLlmError,
};
use std::io::Read;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

pub trait OwnServerTransport: Send + Sync {
    fn generate<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease)
    -> LlmGenerateFuture<'a>;
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a>;
}
#[derive(Debug, Clone)]
pub struct RemoteLlmClient {
    remote: RemoteClient,
}
impl RemoteLlmClient {
    pub fn connect(origin: &str, credential: &str) -> Result<Self, oneiron::memory::MemoryError> {
        Ok(Self {
            remote: RemoteClient::connect(origin, credential)?,
        })
    }
}
/// Typed server failures; no retries or budget policy live in this transport.
pub fn classify_status(status: u16, body: &serde_json::Value) -> LlmError {
    if body
        .pointer("/error/code")
        .and_then(serde_json::Value::as_str)
        == Some("budget_denied")
        || status == 402
    {
        return BudgetDenied::AdmissionDenied.into();
    }
    match status {
        401 | 403 => FatalLlmError::Auth.into(),
        408 | 504 => RetryableLlmError::Timeout.into(),
        429 => RetryableLlmError::RateLimited { retry_after: None }.into(),
        500..=599 => RetryableLlmError::ServerError.into(),
        _ => FatalLlmError::InvalidRequest.into(),
    }
}
fn check_status(
    mut response: reqwest::blocking::Response,
) -> oneiron::LlmResult<reqwest::blocking::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    let _ = response.by_ref().take(65_536).read_to_end(&mut bytes);
    Err(classify_status(
        status,
        &serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    ))
}
impl OwnServerTransport for RemoteLlmClient {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let remote = self.remote.clone();
        let lease = lease.clone();
        let (send, receive) = futures_channel::oneshot::channel();
        std::thread::spawn(move || {
            let result = (|| {
                let response = check_status(remote.llm_post(&request, &lease)?)?;
                let mut bytes = Vec::new();
                response
                    .take(32 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| RetryableLlmError::StreamCut)?;
                if bytes.len() > 32 * 1024 * 1024 {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
                serde_json::from_slice(&bytes).map_err(|_| FatalLlmError::InvalidRequest.into())
            })();
            let _ = send.send(result);
        });
        Box::pin(async move {
            receive
                .await
                .map_err(|_| LlmError::from(RetryableLlmError::StreamCut))?
        })
    }
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let remote = self.remote.clone();
        let lease = lease.clone();
        let (send, receive) = futures_channel::mpsc::unbounded();
        let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => {
                    let _ = send.unbounded_send(Err(RetryableLlmError::StreamCut.into()));
                    return;
                }
            };
            runtime.block_on(async {
                tokio::select! {
                    _ = cancelled => {},
                    result = read_stream(&remote, &request, &lease, &send) => {
                        if let Err(error) = result { let _ = send.unbounded_send(Err(error)); }
                    }
                }
            });
        });
        Ok(LlmStream::new(CancellableStream {
            receive,
            _cancel: cancel,
        }))
    }
}

struct CancellableStream {
    receive: futures_channel::mpsc::UnboundedReceiver<oneiron::LlmResult<LlmStreamEvent>>,
    _cancel: tokio::sync::oneshot::Sender<()>,
}
impl Stream for CancellableStream {
    type Item = oneiron::LlmResult<LlmStreamEvent>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receive).poll_next(cx)
    }
}
async fn read_stream(
    remote: &RemoteClient,
    request: &LlmRequest,
    lease: &BudgetLease,
    send: &futures_channel::mpsc::UnboundedSender<oneiron::LlmResult<LlmStreamEvent>>,
) -> oneiron::LlmResult<()> {
    let mut response = remote.llm_stream(request, lease).await?;
    let status = response.status();
    let limit = if status.is_success() {
        32 * 1024 * 1024
    } else {
        65_536
    };
    let mut total = 0;
    let mut buffer = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        if e.is_timeout() {
            RetryableLlmError::Timeout
        } else {
            RetryableLlmError::StreamCut
        }
    })? {
        total += chunk.len();
        if total > limit {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        buffer.extend_from_slice(&chunk);
        if !status.is_success() {
            continue;
        }
        while let Some(end) = buffer.iter().position(|b| *b == b'\n') {
            let line: Vec<_> = buffer.drain(..=end).collect();
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_slice(&line).map_err(|_| FatalLlmError::InvalidRequest)?;
            if let Some(error) = value.pointer("/error/llm") {
                return Err(serde_json::from_value(error.clone())
                    .map_err(|_| FatalLlmError::InvalidRequest)?);
            }
            let event: LlmStreamEvent =
                serde_json::from_value(value).map_err(|_| FatalLlmError::InvalidRequest)?;
            let done = matches!(event, LlmStreamEvent::Done { .. });
            if send.unbounded_send(Ok(event)).is_err() || done {
                return Ok(());
            }
        }
    }
    if !status.is_success() {
        return Err(classify_status(
            status.as_u16(),
            &serde_json::from_slice(&buffer).unwrap_or_default(),
        ));
    }
    Err(RetryableLlmError::StreamCut.into())
}
