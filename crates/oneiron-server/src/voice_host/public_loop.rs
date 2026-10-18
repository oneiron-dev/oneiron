//! The public transport drives the existing voice host and media worker.
//! ASR, sentence dispatch, safeguards, cancellation and settlement stay in
//! their existing engine/host implementations.
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::*;
use oneiron::voice_cascade::media::VoiceMediaOutput;
use oneiron::voice_cascade::{AsrUpdate, Brain, ControlEvent, StopReason};
use tokio::sync::mpsc;

use super::media_bridge::{HeardWork, MediaBridge, MediaEvent, MediaTts};
use super::public::{Command, invalid, unavailable};
use super::public_events::Journal;
use super::wire::{ControlOut, WireControl, WireMedia, WireOut};
use super::{ChatBrain, VoiceHost, VoiceMediaIn, VoiceOutputs, VoicePlayout};
use crate::managed::ManagedShutdown;
use crate::server::SyncServer;

type Pending<'a> = Pin<Box<dyn Future<Output = (String, MemoryResult<AsrUpdate>)> + Send + 'a>>;

pub(super) struct PublicLoop {
    pub(super) host: VoiceHost,
    pub(super) bridge: MediaBridge,
    pub(super) wire: Option<WireMedia>,
    pub(super) outputs: VoiceOutputs<ChatBrain, MediaTts, WireControl>,
    pub(super) journal: Arc<Mutex<Journal>>,
    pub(super) session_ref: String,
    pub(super) live: Option<oneiron::conversation::LiveSpeakerCall>,
}

impl PublicLoop {
    pub(super) async fn run(
        mut self,
        server: &Arc<SyncServer>,
        mut commands: mpsc::Receiver<Command>,
        shutdown: &ManagedShutdown,
    ) -> MemoryResult<()> {
        let result = self.serve(server, &mut commands, shutdown).await;
        self.bridge.stop_hearing();
        if let Ok(stop) = self.host.end() {
            super::speech::stopped(&stop, &mut self.bridge, &mut self.outputs);
        }
        self.outputs.brain.settle_retired().await;
        controls(&mut self.wire, &self.journal)?;
        let mut journal = self.journal.lock().map_err(|_| unavailable())?;
        journal.finished(&self.host);
        if let Err(error) = &result {
            journal.push(
                None,
                LiveVoiceEventKind::Error {
                    code: error.code.clone(),
                },
            );
        }
        if !journal.ended {
            journal.ended = true;
            journal.push(None, LiveVoiceEventKind::SessionEnded);
        }
        result
    }

    async fn serve(
        &mut self,
        server: &Arc<SyncServer>,
        commands: &mut mpsc::Receiver<Command>,
        shutdown: &ManagedShutdown,
    ) -> MemoryResult<()> {
        let mut pending: Option<Pending<'_>> = None;
        let mut pending_final = false;
        let mut microphone: Option<String> = None;
        let mut cuts = VecDeque::new();
        let mut entries = self.host.entry_wakes();
        loop {
            // Flushes and stops are published before another PCM dequeue or
            // input ACK. Old packets retain their own weak epoch fence.
            controls(&mut self.wire, &self.journal)?;
            self.journal
                .lock()
                .map_err(|_| unavailable())?
                .finished(&self.host);
            tokio::select! {
                () = shutdown.triggered() => break,
                woke = super::next_entry_wake(&mut entries) => {
                    self.host.entry_woke(woke, &mut entries, Some(&mut self.bridge), &mut self.outputs);
                }
                command = commands.recv() => {
                    let Some(command) = command else { break };
                    match command {
                        Command::Audio(input, reply) => {
                            let outcome = (|| {
                                if self.journal.lock().map_err(|_| unavailable())?.ended {
                                    return Err(invalid("voice session ended"));
                                }
                                if input.utterance_id.trim().is_empty() || microphone.as_ref().is_some_and(|id| id != &input.utterance_id) {
                                    return Err(invalid("audio must continue the current utterance until its cut"));
                                }
                                let pcm = super::wire::decode_pcm(&input.pcm_base64).ok_or_else(|| invalid("audio must contain whole PCM16LE samples"))?;
                                microphone = Some(input.utterance_id.clone());
                                self.host.apply_media_input(VoiceMediaIn::Speaking(input.speaking), &mut self.bridge, &mut self.outputs).map_err(|_| invalid("voice media input refused"))?;
                                self.host.apply_media_input(VoiceMediaIn::Pcm(pcm), &mut self.bridge, &mut self.outputs).map_err(|_| invalid("voice media input refused"))?;
                                if input.end_utterance {
                                    cuts.push_back(input.utterance_id);
                                    microphone = None;
                                    self.host.apply_media_input(VoiceMediaIn::Cut, &mut self.bridge, &mut self.outputs).map_err(|_| invalid("voice media input refused"))?;
                                }
                                controls(&mut self.wire, &self.journal)?;
                                self.journal.lock().map_err(|_| unavailable())?.finished(&self.host);
                                Ok(self.journal.lock().map_err(|_| unavailable())?.processed())
                            })();
                            let _ = reply.send(outcome);
                        }
                        Command::Ack(input, reply) => {
                            let outcome = (|| {
                                let token = self.journal.lock().map_err(|_| unavailable())?.ack(&input)?;
                                if matches!(input.kind, LiveVoiceAckKind::Drained) {
                                    self.host.drained(token, &mut self.bridge);
                                }
                                self.journal.lock().map_err(|_| unavailable())?.finished(&self.host);
                                Ok(self.journal.lock().map_err(|_| unavailable())?.processed())
                            })();
                            let _ = reply.send(outcome);
                        }
                        Command::Tool(result, reply) => {
                            let outcome = (|| {
                                let mut journal = self.journal.lock().map_err(|_| unavailable())?;
                                if journal.ended || pending.is_some() || microphone.is_some() || !cuts.is_empty() || journal.epochs.values().any(|epoch| !epoch.finished) {
                                    return Err(invalid("tool context enters before the next voice utterance"));
                                }
                                let source = result.source.clone();
                                self.outputs.brain.add_foreign(result);
                                journal.context_sources.push(source.clone());
                                journal.push(None, LiveVoiceEventKind::ToolContext { source });
                                Ok(journal.processed())
                            })();
                            let _ = reply.send(outcome);
                        }
                        Command::Usage(generation, reply) => {
                            self.outputs.brain.settle_retired().await;
                            let snapshot = (|| {
                                let journal = self.journal.lock().map_err(|_| unavailable())?;
                                let epoch = journal.epochs.get(&generation).ok_or_else(|| invalid("unknown voice generation"))?;
                                Ok((epoch.utterance_id.clone(), epoch.finished && epoch.ack
                                    && (epoch.stop.is_none() || epoch.media_cancelled)
                                    && !self.outputs.brain.producer_pending(epoch.token)))
                            })();
                            let outcome = match snapshot {
                                Ok((utterance_id, terminal)) => {
                                    let run = format!("voice:{}:{generation}", self.session_ref);
                                    let server = Arc::clone(server);
                                    let session_ref = self.session_ref.clone();
                                    tokio::task::spawn_blocking(move || {
                                        let usage = server.vault_usage();
                                        let settlements = usage.as_ref().map(|usage| server.usage_ledger.run_settlements(
                                            usage.owner(), usage.vault_id(), &run,
                                        )).transpose().map_err(|_| invalid("voice usage ledger unavailable"))?.unwrap_or_default();
                                        Ok(LiveVoiceUsage { session_ref, utterance_id, generation, run,
                                            terminal, metering_enabled: usage.is_some(), settlements })
                                    }).await.map_err(|_| unavailable())?
                                }
                                Err(error) => Err(error),
                            };
                            let _ = reply.send(outcome);
                        }
                        Command::End(reply) => {
                            pending = None;
                            pending_final = false;
                            self.bridge.stop_hearing();
                            self.live.take();
                            let outcome = match self.host.end() {
                                Ok(stop) => {
                                    super::speech::stopped(&stop, &mut self.bridge, &mut self.outputs);
                                    self.outputs.brain.settle_retired().await;
                                    controls(&mut self.wire, &self.journal)?;
                                    let mut journal = self.journal.lock().map_err(|_| unavailable())?;
                                    journal.finished(&self.host);
                                    Ok(journal.processed())
                                }
                                Err(_) => Err(unavailable()),
                            };
                            let _ = reply.send(outcome);
                        }
                    }
                }
                output = WireMedia::next(&mut self.wire) => {
                    let mut journal = self.journal.lock().map_err(|_| unavailable())?;
                    match output {
                        WireOut::Playout(Some(VoicePlayout::Pcm(frame))) => journal.pcm(frame),
                        WireOut::Playout(Some(VoicePlayout::End(generation))) => {
                            if self.host.lock().is_ok_and(|state| state.core.accepts_pcm(generation)) {
                                journal.end_playout(generation);
                            }
                        }
                        WireOut::Control(Some(control)) => record_control(&mut journal, control),
                        _ => {}
                    }
                }
                event = self.bridge.next() => {
                    match event {
                        MediaEvent::Stopped | MediaEvent::PlayoutClosed => return Err(unavailable()),
                        MediaEvent::In(input) => self.host.media_in(input, &mut self.bridge, &mut self.outputs),
                        MediaEvent::Brain(out) => self.host.brain_out(out, &mut self.bridge, &mut self.outputs).map_err(|_| unavailable())?,
                        MediaEvent::Verdict(verdict) => self.host.verdict(verdict, &mut self.bridge, &mut self.outputs),
                        MediaEvent::Tick => self.host.speech_tick(&mut self.bridge, &mut self.outputs).map_err(|_| unavailable())?,
                        MediaEvent::Out(VoiceMediaOutput::Pcm { frame, .. }) => self.host.spoken(frame, &mut self.bridge).map_err(|_| unavailable())?,
                        MediaEvent::Out(VoiceMediaOutput::SpeechFailed { generation, .. }) => self.host.output_failed(generation, &mut self.bridge, &mut self.outputs),
                        MediaEvent::Out(VoiceMediaOutput::Cancelled { generation }) => {
                            let mut journal = self.journal.lock().map_err(|_| unavailable())?;
                            if let Some(epoch) = journal.epochs.get_mut(&generation.value()) { epoch.media_cancelled = true; }
                            journal.push(Some(generation), LiveVoiceEventKind::MediaCancelled);
                        }
                        MediaEvent::Out(VoiceMediaOutput::Heard { event, .. }) => {
                            let utterance = cuts.pop_front().or_else(|| microphone.clone()).unwrap_or_default();
                            if let Some((_, work)) = self.host.heard(&mut self.bridge, event) {
                                pending = Some(Box::pin(async move { (utterance, work.run().await.map_err(|_| invalid("voice final refused"))) }));
                                pending_final = true;
                            }
                        }
                        MediaEvent::Live(Ok(updates)) => {
                            if let Some(work) = self.host.live_heard(&mut self.bridge, updates, pending_final) {
                                pending_final = work.final_text;
                                let utterance = if work.final_text { cuts.pop_front() } else { None }
                                    .or_else(|| microphone.clone()).unwrap_or_default();
                                pending = Some(enrich(utterance, work));
                            }
                        }
                        MediaEvent::Live(Err(_)) => { self.host.live_failed(&mut self.bridge); return Err(unavailable()); }
                    }
                }
                result = async { pending.as_mut().expect("guarded voice work").await }, if pending.is_some() => {
                    pending = None;
                    let was_final = std::mem::take(&mut pending_final);
                    let (utterance, result) = result;
                    match result {
                        Ok(AsrUpdate::Final(request)) => {
                            self.journal.lock().map_err(|_| unavailable())?.start(request.generation, utterance);
                            if self.host.start_speech(request.generation, &mut self.bridge, &mut self.outputs)
                                && self.outputs.brain.start(&request).is_err() {
                                self.host.output_failed(request.generation, &mut self.bridge, &mut self.outputs);
                            }
                        }
                        Ok(_) => {}
                        Err(_) => { self.journal.lock().map_err(|_| unavailable())?.push(None, LiveVoiceEventKind::Error { code: "voice_transcription_refused".into() }); }
                    }
                    if was_final && let Some(work) = self.host.live_resume(&mut self.bridge) {
                        pending_final = work.final_text;
                        let utterance = if work.final_text { cuts.pop_front() } else { None }
                            .or_else(|| microphone.clone()).unwrap_or_default();
                        pending = Some(enrich(utterance, work));
                    }
                }
            }
        }
        Ok(())
    }
}

fn enrich(utterance: String, heard: HeardWork<'_>) -> Pending<'_> {
    Box::pin(async move {
        (
            utterance,
            heard
                .work
                .run()
                .await
                .map_err(|_| invalid("voice hypothesis refused")),
        )
    })
}

fn controls(wire: &mut Option<WireMedia>, journal: &Mutex<Journal>) -> MemoryResult<()> {
    let Some(wire) = wire else { return Ok(()) };
    while let Some(control) = wire.queued_control() {
        let mut held = journal.lock().map_err(|_| unavailable())?;
        record_control(&mut held, control);
    }
    Ok(())
}

fn record_control(journal: &mut Journal, control: ControlOut) {
    match control {
        ControlOut::Flush(generation) => {
            journal.push(Some(generation), LiveVoiceEventKind::Flush);
        }
        ControlOut::Event(ControlEvent::PlayoutStop { generation, reason }) => {
            let reason = match reason {
                StopReason::UserBargeIn => LiveVoiceStopReason::UserBargeIn,
                StopReason::Safeguard => LiveVoiceStopReason::Safeguard,
                StopReason::RosterChanged => LiveVoiceStopReason::RosterChanged,
                StopReason::OutputFailed => LiveVoiceStopReason::OutputFailed,
                StopReason::SessionEnd => LiveVoiceStopReason::SessionEnd,
            };
            journal.stopped(generation, reason);
        }
        ControlOut::Event(ControlEvent::Safeguard {
            generation,
            action,
            receipt_ref,
            custom_tier_skipped,
        }) => {
            journal.push(
                Some(generation),
                LiveVoiceEventKind::Safeguard {
                    action,
                    receipt_ref,
                    custom_tier_skipped,
                },
            );
        }
        ControlOut::Event(ControlEvent::Notice { generation, notice }) => {
            journal.push(Some(generation), LiveVoiceEventKind::Notice { notice });
        }
        ControlOut::Event(ControlEvent::Memories {
            generation,
            memories,
        }) => {
            journal.push(
                Some(generation),
                LiveVoiceEventKind::Memories {
                    found: memories.found,
                    heard: memories.heard,
                    receipts: memories.receipts,
                },
            );
        }
        ControlOut::Event(ControlEvent::SessionEnded) => {
            if !journal.ended {
                let tokens: Vec<_> = journal
                    .epochs
                    .values()
                    .filter(|epoch| !epoch.finished)
                    .map(|epoch| epoch.token)
                    .collect();
                for token in tokens {
                    journal.stopped(token, LiveVoiceStopReason::SessionEnd);
                }
                journal.ended = true;
                journal.push(None, LiveVoiceEventKind::SessionEnded);
            }
        }
    }
}
