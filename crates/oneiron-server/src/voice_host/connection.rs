//! One private, pre-admitted UDS connection on the existing Tokio runtime.
//! No accept loop or tasks are spawned; sentence safeguards run beside the
//! connection and end with it. The owner enforces listener privacy and its
//! connection budget before calling serve. Pipecat still schedules turns.
//! Over the wire's media ops (`wire`) the same stream also carries the
//! sibling's audio side.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;

use oneiron::policy_model::PolicyEnforcementAction;
use oneiron::speculative::SpeculativeFireDecision;
use oneiron::store::GateSystemNoticeRecord;
use oneiron::voice_cascade::uds::MAX_FRAME_BYTES;
use oneiron::voice_cascade::{
    AsrUpdate, Brain, CascadeControl, ControlEvent, RetrievalContext, TtsSeamClient,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{Instant, timeout, timeout_at};

use oneiron::voice_cascade::media::VoiceMediaOutput;

use super::media_bridge::{
    HEARD_REVISION, HeardWork, LIVE_ASR_FAILURE, LiveAsrFailure, MediaBridge, MediaEvent,
};
use super::wire::{self, ControlOut, WireMedia, WireOut};
use super::{HostError, VoiceHost, VoiceMediaIn, VoiceOutputs, VoicePlayout};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Open {
        utterance_id: String,
    },
    Partial {
        handle: String,
        revision: u64,
        text: String,
    },
    Final {
        handle: String,
        revision: u64,
        text: String,
    },
    Close {
        handle: String,
    },
    /// Microphone audio: STANDARD base64 of whole PCM16LE samples.
    Pcm {
        data: String,
    },
    Cut,
    Speaking {
        speaking: bool,
    },
    RosterChanged,
    /// All of a generation's audio, up to its `generation_end`, played.
    Drained {
        generation: u64,
    },
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Response {
    Opened {
        handle: String,
    },
    Partial {
        handle: String,
        revision: u64,
        decision: &'static str,
        context: Option<RetrievalContext>,
    },
    Final {
        handle: String,
        revision: u64,
        context: RetrievalContext,
    },
    Closed,
    Error {
        code: &'static str,
    },
    /// Spoken mono PCM16LE, STANDARD base64.
    Pcm {
        generation: u64,
        sample_rate: u32,
        data: String,
    },
    GenerationEnd {
        generation: u64,
    },
    /// Drop whatever of this generation's audio is still queued or playing.
    Flush {
        generation: u64,
    },
    PlayoutStop {
        generation: u64,
        reason: &'static str,
    },
    Safeguard {
        generation: u64,
        action: PolicyEnforcementAction,
        receipt_ref: Option<String>,
        custom_tier_skipped: bool,
    },
    Notice {
        generation: u64,
        notice: GateSystemNoticeRecord,
    },
    SessionEnded,
}

type Pending<'a> =
    Pin<Box<dyn Future<Output = (String, u64, Result<AsrUpdate, HostError>)> + Send + 'a>>;

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
        self.serve_until(stream, outputs, std::future::pending())
            .await
    }

    pub(super) async fn serve_until<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        stream: UnixStream,
        outputs: &mut VoiceOutputs<B, T, C>,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        self.serve_with(stream, outputs, None, None, stop).await
    }

    /// [`Self::serve_until`], hearing the owner's audio and speaking through
    /// `bridge` beside the stream.
    pub(super) async fn serve_media_until<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        stream: UnixStream,
        outputs: &mut VoiceOutputs<B, T, C>,
        bridge: &mut MediaBridge,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        self.serve_with(stream, outputs, Some(bridge), None, stop)
            .await
    }

    /// [`Self::serve_media_until`] with the audio side on the stream itself.
    pub(super) async fn serve_wire_until<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        stream: UnixStream,
        outputs: &mut VoiceOutputs<B, T, C>,
        bridge: &mut MediaBridge,
        wire: WireMedia,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        self.serve_with(stream, outputs, Some(bridge), Some(wire), stop)
            .await
    }

    async fn serve_with<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        stream: UnixStream,
        outputs: &mut VoiceOutputs<B, T, C>,
        mut bridge: Option<&mut MediaBridge>,
        mut wire: Option<WireMedia>,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let end_on_drop = EndOnDrop(self);
        // The write half and the wire outlive the loop, so the end stop's
        // `session_ended` still goes out on them.
        let (read, mut write) = stream.into_split();
        let result = self
            .serve_inner(read, &mut write, outputs, bridge.as_deref_mut(), &mut wire, stop)
            .await;
        if let Some(bridge) = bridge {
            bridge.stop_hearing();
        }
        let stop = self
            .end()
            .map_err(|_| io::Error::other("voice teardown failed"))?;
        let errors = stop.dispatch(&mut outputs.brain, &mut outputs.tts, &mut outputs.control);
        if let Some(wire) = wire.as_mut() {
            farewell(wire, &mut write).await;
        }
        drop(end_on_drop);
        result?;
        if !errors.is_empty() {
            return Err(io::Error::other("voice stop dispatch failed"));
        }
        Ok(())
    }

    async fn serve_inner<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        read: OwnedReadHalf,
        write: &mut OwnedWriteHalf,
        outputs: &mut VoiceOutputs<B, T, C>,
        mut bridge: Option<&mut MediaBridge>,
        wire: &mut Option<WireMedia>,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        tokio::pin!(stop);
        let mut reader = BufReader::new(read);
        let mut frame = FrameReader::new();
        let mut pending: Option<Pending<'_>> = None;
        // Whether `pending` enriches a final: words heard live after it wait.
        let mut pending_final = false;
        // Frames still to write; a sentence's audio goes out in several.
        let mut outbox = VecDeque::new();
        let mut requests = 0;
        let mut errors = 0;
        let shutdown = self.shutdown.triggered();
        tokio::pin!(shutdown);
        loop {
            let response = if let Some(queued) = outbox.pop_front() {
                queued
            } else {
                tokio::select! {
                    biased;
                    () = &mut shutdown => break,
                    () = &mut stop => break,
                    // Output first: the loop also fills the wire's queue, and
                    // steady microphone frames must not starve it.
                    out = WireMedia::next(wire) => match out {
                        WireOut::Playout(Some(VoicePlayout::Pcm(spoken))) => {
                            // Checked again at dequeue: a stopped generation's audio never goes out.
                            let Some(spoken) = spoken.current() else { continue };
                            let generation = spoken.generation.value();
                            let mut chunks = wire::pcm_chunks(&spoken).into_iter().map(|data| Response::Pcm {
                                generation,
                                sample_rate: spoken.sample_rate,
                                data,
                            });
                            let Some(first) = chunks.next() else { continue };
                            outbox.extend(chunks);
                            first
                        }
                        WireOut::Playout(Some(VoicePlayout::End(generation))) => {
                            if let Some(wire) = wire.as_mut() {
                                wire.ended(generation);
                            }
                            Response::GenerationEnd { generation: generation.value() }
                        }
                        WireOut::Control(Some(out)) => control_out(out),
                        WireOut::Playout(None) | WireOut::Control(None) => continue,
                    },
                    // The bridge before wire input: it drives the live hearing's
                    // socket, and steady microphone frames must not starve it.
                    event = async {
                        match bridge.as_deref_mut() {
                            Some(bridge) => bridge.next().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        let Some(bridge) = bridge.as_deref_mut() else { continue };
                        match event {
                            MediaEvent::Stopped => break,
                            MediaEvent::PlayoutClosed => return Err(io::Error::other("voice playout closed")),
                            MediaEvent::In(input) => self.media_in(input, bridge, outputs),
                            MediaEvent::Brain(out) => self.brain_out(out, bridge, outputs)?,
                            MediaEvent::Verdict(verdict) => self.verdict(verdict, bridge, outputs),
                            MediaEvent::Tick => self.speech_tick(bridge, outputs)?,
                            // Spoken audio plays only for the session's current generation.
                            MediaEvent::Out(VoiceMediaOutput::Pcm { frame, .. }) => {
                                self.spoken(frame, bridge)?;
                            }
                            // A sentence that was not spoken stops its generation.
                            MediaEvent::Out(VoiceMediaOutput::SpeechFailed { generation, .. }) => {
                                tracing::warn!("voice media: a sentence was not spoken");
                                self.output_failed(generation, bridge, outputs);
                            }
                            MediaEvent::Out(VoiceMediaOutput::Heard { event, .. }) => {
                                // A heard final replaces any enrichment in flight, as a wire final does.
                                if let Some((handle, work)) = self.heard(bridge, event) {
                                    pending = Some(Box::pin(async move { (handle, HEARD_REVISION, work.run().await) }));
                                    pending_final = true;
                                }
                            }
                            MediaEvent::Live(Ok(updates)) => {
                                // A live hypothesis replaces partial work in flight, never a final's.
                                if let Some(heard) = self.live_heard(bridge, updates, pending_final) {
                                    pending_final = heard.final_text;
                                    pending = Some(heard_pending(heard));
                                }
                            }
                            MediaEvent::Live(Err(error)) => {
                                tracing::warn!(%error, "voice media: the live hearing failed");
                                self.live_failed(bridge);
                                match LIVE_ASR_FAILURE {
                                    LiveAsrFailure::EndCall => return Err(io::Error::other("voice live hearing failed")),
                                }
                            }
                        }
                        continue;
                    }
                    bytes = frame.read(&mut reader) => {
                        let Some(bytes) = bytes? else { break };
                        let request = serde_json::from_slice::<Request>(&bytes);
                        // Media ops stream for the whole call; only transcript ops
                        // spend the request budget.
                        if !matches!(request, Ok(Request::Pcm { .. } | Request::Cut | Request::Speaking { .. } | Request::RosterChanged | Request::Drained { .. })) {
                            requests += 1;
                            if requests > 4096 { break; }
                        }
                        match request {
                            Ok(Request::Open { utterance_id }) => match self.open(utterance_id) {
                                Ok(handle) => Response::Opened { handle },
                                Err(error) => response_error(&error),
                            },
                            Ok(Request::Close { handle }) => match self.close(&handle) {
                                Ok(()) => {
                                    pending = None;
                                    pending_final = false;
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
                                        pending_final = false;
                                        continue;
                                    }
                                    Err(error) => response_error(&error),
                                }
                            }
                            Ok(Request::Final { handle, revision, text }) => {
                                match self.prepare(&handle, revision, text, true) {
                                    Ok(work) => {
                                        pending = Some(Box::pin(async move { (handle, revision, work.run().await) }));
                                        pending_final = true;
                                        continue;
                                    }
                                    Err(error) => response_error(&error),
                                }
                            }
                            // An early or stale acknowledgement changes nothing.
                            Ok(Request::Drained { generation }) => {
                                let generation = wire.as_ref().and_then(|wire| wire.drained(generation));
                                if let (Some(bridge), Some(generation)) = (bridge.as_deref_mut(), generation) {
                                    self.media_in(VoiceMediaIn::Drained(generation), bridge, outputs);
                                }
                                continue;
                            }
                            Ok(media) => match (bridge.as_deref_mut(), wire.is_some(), media_input(media)) {
                                (Some(bridge), true, Some(input)) => {
                                    self.media_in(input, bridge, outputs);
                                    continue;
                                }
                                _ => Response::Error { code: "invalid_request" },
                            },
                            Err(_) => Response::Error { code: "invalid_request" },
                        }
                    }
                    result = async { pending.as_mut().expect("guarded pending work").await }, if pending.is_some() => {
                        pending = None;
                        let was_final = std::mem::take(&mut pending_final);
                        let (handle, revision, result) = result;
                        let response = match result {
                            Ok(AsrUpdate::Partial(partial)) => Response::Partial {
                                handle,
                                revision,
                                decision: match partial.decision {
                                    SpeculativeFireDecision::Fired { .. } => "fired",
                                    SpeculativeFireDecision::SkippedUnchanged => "skipped_unchanged",
                                    SpeculativeFireDecision::SkippedEmptySignature => "skipped_empty_signature",
                                    SpeculativeFireDecision::SkippedCapExhausted => "skipped_cap_exhausted",
                                    SpeculativeFireDecision::MissedDeadline => "missed_deadline",
                                },
                                context: partial.context,
                            },
                            Ok(AsrUpdate::Final(request)) => {
                                // With the media seats, speech opens before the brain starts.
                                let speaking = bridge
                                    .as_deref_mut()
                                    .is_none_or(|bridge| self.start_speech(request.generation, bridge, outputs));
                                if speaking {
                                    // Refs remain non-authoritative. The existing brain must
                                    // use ordinary disclosure/tool gates when resolving them.
                                    // Submission is synchronous, outside the session lock.
                                    outputs.brain.start(&request).map_err(|_| io::Error::other("brain submission failed"))?;
                                    Response::Final { handle, revision, context: request.retrieval }
                                } else {
                                    Response::Error { code: "stopped" }
                                }
                            }
                            Ok(_) => Response::Error { code: "stale_request" },
                            Err(error) => response_error(&error),
                        };
                        // The final consumed its handle: what was heard live after it goes next.
                        if was_final
                            && let Some(bridge) = bridge.as_deref_mut()
                            && let Some(heard) = self.live_resume(bridge)
                        {
                            pending_final = heard.final_text;
                            pending = Some(heard_pending(heard));
                        }
                        response
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
            if errors >= 8 {
                break;
            }
        }
        Ok(())
    }
}

/// Heard words' enrichment, as the connection's pending work.
fn heard_pending(heard: HeardWork<'_>) -> Pending<'_> {
    let HeardWork {
        handle,
        revision,
        work,
        ..
    } = heard;
    Box::pin(async move { (handle, revision, work.run().await) })
}

/// A media op as the bridge's input; `None` for bad audio or a
/// transcript op.
fn media_input(request: Request) -> Option<VoiceMediaIn> {
    Some(match request {
        Request::Pcm { data } => VoiceMediaIn::Pcm(wire::decode_pcm(&data)?),
        Request::Cut => VoiceMediaIn::Cut,
        Request::Speaking { speaking } => VoiceMediaIn::Speaking(speaking),
        Request::RosterChanged => VoiceMediaIn::RosterChanged,
        _ => return None,
    })
}

/// How long the wire's last frames may take: the sibling may be gone.
const FAREWELL: Duration = Duration::from_secs(1);

/// The controls still queued for the wire, the end stop's `session_ended`
/// last, as the connection's final frames. Best effort within [`FAREWELL`];
/// audio still queued is dropped with the session.
async fn farewell(wire: &mut WireMedia, write: &mut OwnedWriteHalf) {
    let frames = async {
        while let Some(out) = wire.queued_control() {
            let mut bytes = serde_json::to_vec(&control_out(out)).map_err(io::Error::other)?;
            if bytes.len() > MAX_FRAME_BYTES {
                continue;
            }
            bytes.push(b'\n');
            write.write_all(&bytes).await?;
        }
        Ok::<_, io::Error>(())
    };
    if !matches!(timeout(FAREWELL, frames).await, Ok(Ok(()))) {
        tracing::debug!("voice wire: the session's end did not reach the sibling");
    }
}

fn control_out(out: ControlOut) -> Response {
    match out {
        ControlOut::Flush(generation) => Response::Flush {
            generation: generation.value(),
        },
        ControlOut::Event(event) => control_response(event),
    }
}

fn control_response(event: ControlEvent) -> Response {
    match event {
        ControlEvent::PlayoutStop { generation, reason } => Response::PlayoutStop {
            generation: generation.value(),
            reason: wire::stop_reason(reason),
        },
        ControlEvent::SessionEnded => Response::SessionEnded,
        ControlEvent::Safeguard {
            generation,
            action,
            receipt_ref,
            custom_tier_skipped,
        } => Response::Safeguard {
            generation: generation.value(),
            action,
            receipt_ref,
            custom_tier_skipped,
        },
        ControlEvent::Notice { generation, notice } => Response::Notice {
            generation: generation.value(),
            notice,
        },
    }
}

fn response_error(error: &HostError) -> Response {
    // Never reflect provider, parser, vault or transcript content to the wire.
    Response::Error {
        code: match error {
            HostError::InvalidRequest => "invalid_request",
            HostError::Stale => "stale_request",
            HostError::Stopped => "stopped",
            HostError::InvalidResponse => "invalid_enrichment",
            HostError::Llm(oneiron::llm::LlmError::BudgetDenied(_)) => "budget_denied",
            HostError::Llm(_) => "provider_error",
            HostError::Core(_) => "bridge_error",
        },
    }
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
        Self {
            bytes: Vec::new(),
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    async fn read(&mut self, reader: &mut BufReader<OwnedReadHalf>) -> io::Result<Option<Vec<u8>>> {
        loop {
            let available = timeout_at(self.deadline, reader.fill_buf())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "voice read timeout"))??;
            if available.is_empty() {
                return if self.bytes.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated voice frame",
                    ))
                };
            }
            if self.bytes.is_empty() {
                self.deadline = Instant::now() + Duration::from_secs(5);
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.unwrap_or(available.len());
            if count > MAX_FRAME_BYTES - self.bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "voice frame exceeds limit",
                ));
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
