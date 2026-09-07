//! One private, pre-admitted UDS connection on the existing Tokio runtime.
//! No accept loop or tasks are spawned. The owner enforces listener privacy and
//! its connection budget before calling serve. Pipecat still schedules turns.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;

use oneiron::speculative::SpeculativeFireDecision;
use oneiron::voice_cascade::uds::MAX_FRAME_BYTES;
use oneiron::voice_cascade::{
    AsrUpdate, Brain, CascadeControl, RetrievalContext, TtsSeamClient,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedReadHalf;
use tokio::time::{Instant, timeout, timeout_at};

use super::{HostError, VoiceHost, VoiceOutputs};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Open { utterance_id: String },
    Partial { handle: String, revision: u64, text: String },
    Final { handle: String, revision: u64, text: String },
    Close { handle: String },
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Response {
    Opened { handle: String },
    Partial { handle: String, revision: u64, decision: &'static str, context: Option<RetrievalContext> },
    Final { handle: String, revision: u64, context: RetrievalContext },
    Closed,
    Error { code: &'static str },
}

type Pending<'a> = Pin<Box<dyn Future<Output = (String, u64, Result<AsrUpdate, HostError>)> + Send + 'a>>;

impl VoiceHost {
    /// Serve only a stream admitted by the existing lifecycle owner from its
    /// 0600 socket below the active owner-only vault runtime directory. No TCP.
    /// EOF/shutdown/errors cancel extraction and end the engine session. The
    /// owner must still deliver/ack remote stops if this whole future is aborted.
    pub(crate) async fn serve<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        stream: UnixStream,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) -> io::Result<()> {
        self.serve_until(stream, outputs, std::future::pending()).await
    }

    pub(super) async fn serve_until<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        stream: UnixStream,
        outputs: &mut VoiceOutputs<B, T, C>,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let end_on_drop = EndOnDrop(self);
        let result = self.serve_inner(stream, &mut outputs.brain, stop).await;
        let stop = self.end().map_err(|_| io::Error::other("voice teardown failed"))?;
        let errors = stop.dispatch(&mut outputs.brain, &mut outputs.tts, &mut outputs.control);
        drop(end_on_drop);
        result?;
        if !errors.is_empty() {
            return Err(io::Error::other("voice stop dispatch failed"));
        }
        Ok(())
    }

    async fn serve_inner(
        &self,
        stream: UnixStream,
        brain: &mut impl Brain,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        tokio::pin!(stop);
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut frame = FrameReader::new();
        let mut pending: Option<Pending<'_>> = None;
        let mut requests = 0;
        let mut errors = 0;
        let shutdown = self.shutdown.triggered();
        tokio::pin!(shutdown);
        loop {
            let response = tokio::select! {
                biased;
                () = &mut shutdown => break,
                () = &mut stop => break,
                bytes = frame.read(&mut reader) => {
                    let Some(bytes) = bytes? else { break };
                    requests += 1;
                    if requests > 4096 { break; }
                    match serde_json::from_slice::<Request>(&bytes) {
                        Ok(Request::Open { utterance_id }) => match self.open(utterance_id) {
                            Ok(handle) => Response::Opened { handle },
                            Err(error) => response_error(&error),
                        },
                        Ok(Request::Close { handle }) => match self.close(&handle) {
                            Ok(()) => {
                                pending = None;
                                Response::Closed
                            }
                            Err(error) => response_error(&error),
                        },
                        Ok(Request::Partial { handle, revision, text }) => {
                            match self.prepare(&handle, revision, text, false) {
                                Ok(work) => {
                                    // Prepare invalidates old work first. Dropping its
                                    // future then releases only its own reservation.
                                    pending = Some(Box::pin(async move { (handle, revision, work.run().await) }));
                                    continue;
                                }
                                Err(error) => response_error(&error),
                            }
                        }
                        Ok(Request::Final { handle, revision, text }) => {
                            match self.prepare(&handle, revision, text, true) {
                                Ok(work) => {
                                    pending = Some(Box::pin(async move { (handle, revision, work.run().await) }));
                                    continue;
                                }
                                Err(error) => response_error(&error),
                            }
                        }
                        Err(_) => Response::Error { code: "invalid_request" },
                    }
                }
                result = async { pending.as_mut().expect("guarded pending work").await }, if pending.is_some() => {
                    pending = None;
                    let (handle, revision, result) = result;
                    match result {
                        Ok(AsrUpdate::Partial(partial)) => Response::Partial {
                            handle,
                            revision,
                            decision: match partial.decision {
                                SpeculativeFireDecision::Fired { .. } => "fired",
                                SpeculativeFireDecision::SkippedUnchanged => "skipped_unchanged",
                                SpeculativeFireDecision::SkippedEmptySignature => "skipped_empty_signature",
                                SpeculativeFireDecision::SkippedCapExhausted => "skipped_cap_exhausted",
                            },
                            context: partial.context,
                        },
                        Ok(AsrUpdate::Final(request)) => {
                            // Refs remain non-authoritative. The existing brain must
                            // use ordinary disclosure/tool gates when resolving them.
                            // Submission is synchronous, outside the session lock.
                            brain.start(&request).map_err(|_| io::Error::other("brain submission failed"))?;
                            Response::Final { handle, revision, context: request.retrieval }
                        }
                        Ok(_) => Response::Error { code: "stale_request" },
                        Err(error) => response_error(&error),
                    }
                }
            };
            if matches!(response, Response::Error { .. }) {
                errors += 1;
            }
            let mut bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
            if bytes.len() > MAX_FRAME_BYTES {
                return Err(io::Error::other("voice response exceeds limit"));
            }
            bytes.push(b'\n');
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                () = &mut stop => break,
                result = timeout(Duration::from_secs(1), write.write_all(&bytes)) => {
                    result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "voice write timeout"))??;
                }
            }
            if errors >= 8 { break; }
        }
        Ok(())
    }
}

fn response_error(error: &HostError) -> Response {
    // Never reflect provider, parser, vault or transcript content to the wire.
    Response::Error { code: match error {
        HostError::InvalidRequest => "invalid_request",
        HostError::Stale => "stale_request",
        HostError::Stopped => "stopped",
        HostError::InvalidResponse => "invalid_enrichment",
        HostError::Llm(oneiron::llm::LlmError::BudgetDenied(_)) => "budget_denied",
        HostError::Llm(_) => "provider_error",
        HostError::Core(_) => "bridge_error",
    } }
}

struct EndOnDrop<'a>(&'a VoiceHost);

impl Drop for EndOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.end();
    }
}

/// State survives select cancellation: partial frame bytes and the absolute
/// deadline cannot reset each time an enrichment response becomes ready.
struct FrameReader {
    bytes: Vec<u8>,
    deadline: Instant,
}

impl FrameReader {
    fn new() -> Self {
        Self { bytes: Vec::new(), deadline: Instant::now() + Duration::from_secs(30) }
    }

    async fn read(&mut self, reader: &mut BufReader<OwnedReadHalf>) -> io::Result<Option<Vec<u8>>> {
        loop {
            let available = timeout_at(self.deadline, reader.fill_buf()).await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "voice read timeout"))??;
            if available.is_empty() {
                return if self.bytes.is_empty() { Ok(None) } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated voice frame"))
                };
            }
            if self.bytes.is_empty() {
                self.deadline = Instant::now() + Duration::from_secs(5);
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.unwrap_or(available.len());
            if count > MAX_FRAME_BYTES - self.bytes.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "voice frame exceeds limit"));
            }
            self.bytes.extend_from_slice(&available[..count]);
            reader.consume(count + usize::from(newline.is_some()));
            if newline.is_some() {
                self.deadline = Instant::now() + Duration::from_secs(30);
                return Ok(Some(std::mem::take(&mut self.bytes)));
            }
        }
    }
}
