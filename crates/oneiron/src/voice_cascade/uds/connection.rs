use std::io::{self, BufReader};
use std::net::Shutdown as SocketShutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::codec::{self, Frame, Request, Response};
use super::{BridgeLimits, MAX_TEXT_BYTES};
use crate::Vault;
use crate::speculative::SpeculativeFireDecision;
use crate::voice_cascade::{PartialEnricher, SpeculativeRetrievalBridge, UtteranceHandle};

const MAX_REQUESTS: usize = 4096;
const MAX_ERRORS: usize = 8;
const IO_TICK: Duration = Duration::from_millis(200);

/// Shared stop signal. Each socket checks it at bounded read intervals.
#[derive(Clone, Default)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// A synchronous connection boundary. The host schedules one worker per socket
/// within its worker budget; this object never acquires a global session lock.
pub struct Connection {
    stream: UnixStream,
    shutdown: Shutdown,
}

impl Connection {
    /// For a host that already owns a private Unix listener. The host is
    /// responsible for that listener's filesystem privacy and accept budget.
    #[must_use]
    pub fn from_stream(stream: UnixStream, shutdown: Shutdown) -> Self {
        Self { stream, shutdown }
    }

    /// Requires actual host enrichment. No default or fake production enricher
    /// exists. Returns on EOF, shutdown, framing failure or connection budget.
    /// Dropping the local bridge releases every open utterance on every exit,
    /// including I/O errors and unwinding. This does not dispatch audio stops.
    pub fn serve(
        self,
        vault: Arc<Vault>,
        enricher: &mut impl PartialEnricher,
        limits: BridgeLimits,
    ) -> io::Result<()> {
        let limits = limits.validate()?;
        self.stream.set_nonblocking(false)?;
        self.stream.set_read_timeout(Some(IO_TICK))?;
        self.stream
            .set_write_timeout(Some(Duration::from_secs(1)))?;
        let mut reader = BufReader::with_capacity(1024, &self.stream);
        let mut writer = &self.stream;
        let mut session = WireSession::new(vault, limits);
        let mut errors = 0;
        for _ in 0..MAX_REQUESTS {
            let bytes = match codec::read_frame(&mut reader, &self.shutdown)? {
                Frame::Data(bytes) => bytes,
                Frame::End => break,
                Frame::Fatal(code) => {
                    codec::write_response(&mut writer, &Response::error(code))?;
                    break;
                }
            };
            if self.shutdown.is_requested() {
                break;
            }
            let response = match serde_json::from_slice::<Request>(&bytes) {
                Ok(request) => session.handle(request, enricher),
                Err(_) => Response::error("invalid_request"),
            };
            if matches!(&response, Response::Error { .. }) {
                errors += 1;
            }
            codec::write_response(&mut writer, &response)?;
            if errors >= MAX_ERRORS {
                break;
            }
        }
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(SocketShutdown::Both);
    }
}

struct WireSession {
    bridge: SpeculativeRetrievalBridge,
    open: Option<(String, UtteranceHandle)>,
    limits: BridgeLimits,
}

impl WireSession {
    fn new(vault: Arc<Vault>, limits: BridgeLimits) -> Self {
        Self {
            bridge: SpeculativeRetrievalBridge::new(vault),
            open: None,
            limits,
        }
    }

    fn handle(&mut self, request: Request, enricher: &mut impl PartialEnricher) -> Response {
        match request {
            Request::Open { utterance_id } => self.open(utterance_id),
            Request::Partial {
                handle,
                revision,
                text,
            } => self.observe(&handle, revision, &text, false, enricher),
            Request::Final {
                handle,
                revision,
                text,
            } => self.observe(&handle, revision, &text, true, enricher),
            Request::Close { handle } => {
                let Some((token, core_handle)) = self.open.as_ref() else {
                    return Response::error("stale_handle");
                };
                if token != &handle {
                    return Response::error("stale_handle");
                }
                self.bridge.close_utterance(core_handle);
                self.open = None;
                Response::Closed
            }
        }
    }

    fn open(&mut self, utterance_id: String) -> Response {
        if utterance_id.len() > 128 || utterance_id.trim().is_empty() {
            return Response::error("invalid_request");
        }
        if self.open.is_some() {
            return Response::error("already_open");
        }
        match self
            .bridge
            .open_utterance(utterance_id, self.limits.session_config())
        {
            Ok(handle) => {
                let token = uuid::Uuid::new_v4().to_string();
                self.open = Some((token.clone(), handle));
                Response::Opened { handle: token }
            }
            Err(_) => Response::error("bridge_error"),
        }
    }

    fn observe(
        &mut self,
        token: &str,
        revision: u64,
        text: &str,
        final_text: bool,
        enricher: &mut impl PartialEnricher,
    ) -> Response {
        let Some((current, handle)) = self.open.as_ref() else {
            return Response::error("stale_handle");
        };
        if current != token {
            return Response::error("stale_handle");
        }
        if text.len() > MAX_TEXT_BYTES || text.trim().is_empty() {
            return Response::error("invalid_request");
        }
        if final_text {
            let result = self.bridge.finalize(handle, revision, text, enricher);
            // Enrichment errors retain the handle. Core retrieval errors consume
            // it. Mirror that lifecycle instead of inventing another session.
            if !self.bridge.is_open(handle) {
                self.open = None;
            }
            return match result {
                Ok(context) => Response::Final { context },
                Err(_) => Response::error("bridge_error"),
            };
        }
        match self
            .bridge
            .observe_partial(handle, revision, text, enricher)
        {
            Ok(result) => Response::Partial {
                decision: match result.decision {
                    SpeculativeFireDecision::Fired { .. } => "fired",
                    SpeculativeFireDecision::SkippedUnchanged => "skipped_unchanged",
                    SpeculativeFireDecision::SkippedEmptySignature => "skipped_empty_signature",
                    SpeculativeFireDecision::SkippedCapExhausted => "skipped_cap_exhausted",
                },
                context: result.context,
            },
            Err(_) => Response::error("bridge_error"),
        }
    }
}

impl Drop for WireSession {
    fn drop(&mut self) {
        self.bridge.close();
        self.open = None;
    }
}
