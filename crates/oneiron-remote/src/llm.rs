//! Own-server raw LLM transport over the SDK's single authenticated HTTP client.
use crate::remote::RemoteClient;
use oneiron::llm::BudgetDenied;
use oneiron::{
    BudgetLease, FatalLlmError, LlmError, LlmGenerateFuture, LlmRequest, LlmStream, LlmStreamEvent,
    LlmStreamResult, RetryableLlmError,
};
use std::io::{BufRead, BufReader, Read};

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
                let response = check_status(remote.llm_post(false, &request, &lease)?)?;
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
        std::thread::spawn(move || {
            let result = (|| {
                let response = check_status(remote.llm_post(true, &request, &lease)?)?;
                let mut reader = BufReader::new(response.take(32 * 1024 * 1024 + 1));
                let mut total = 0;
                loop {
                    let mut line = Vec::new();
                    let read = reader
                        .read_until(b'\n', &mut line)
                        .map_err(|_| RetryableLlmError::StreamCut)?;
                    if read == 0 {
                        return Err(RetryableLlmError::StreamCut.into());
                    }
                    total += read;
                    if total > 32 * 1024 * 1024 {
                        return Err(FatalLlmError::InvalidRequest.into());
                    }
                    if line.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    let event: LlmStreamEvent =
                        serde_json::from_slice(&line).map_err(|_| FatalLlmError::InvalidRequest)?;
                    let done = matches!(event, LlmStreamEvent::Done { .. });
                    if send.unbounded_send(Ok(event)).is_err() || done {
                        return Ok(());
                    }
                }
            })();
            if let Err(error) = result {
                let _ = send.unbounded_send(Err(error));
            }
        });
        Ok(LlmStream::new(receive))
    }
}
