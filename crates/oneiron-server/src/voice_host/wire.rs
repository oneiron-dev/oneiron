//! The voice wire's media ops (OF-410). One admitted UDS connection carries
//! the sibling's audio side beside the transcript ops. In: microphone audio
//! (`pcm`, STANDARD base64 of whole PCM16LE samples, at most ~12 KiB raw per
//! frame), `cut`, `speaking`, `roster_changed` and `drained`. Out: spoken
//! audio (`pcm`, mono PCM16LE in frames under the wire's limit),
//! `generation_end`, `flush`, `playout_stop`, `safeguard`, `notice` and
//! `session_ended`. Generations go by their epoch value. Spoken audio is
//! checked against the session again when it is dequeued for the wire, so a
//! stopped generation's audio never goes out; `flush` tells the sibling to
//! drop what it still holds. `drained` acknowledges a `generation_end` once
//! all of that generation's audio has played on the client.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::Vault;
use oneiron::llm::VoiceChunkPolicy;
use oneiron::voice_cascade::media::VoiceRender;
use oneiron::voice_cascade::{CascadeControl, ControlEvent, GenerationEpoch, PcmFrame, StopReason};
use tokio::sync::mpsc;

use super::media_bridge::{MediaBridge, MediaTts, MediaWorker};
use super::{VoiceBrainOut, VoiceMediaBindings, VoicePlayout};
use crate::models::ModelRuntime;

/// Spoken audio and ends the host holds for the wire. The serve loop
/// drains it before it reads again, so a few suffice.
const PLAYOUT_QUEUE: usize = 64;

/// Raw PCM bytes per outgoing frame: whole samples, and with the frame's
/// fields its base64 stays under the wire's 16 KiB frame limit.
const PCM_CHUNK_BYTES: usize = 11 * 1024;

fn invalid(message: &str) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("voice wire: {message}"))
}

/// [`VoiceMediaBindings`] for a connection whose own stream carries the
/// audio side: no separate microphone, playout or control channels.
pub struct VoiceWireBindings {
    /// The media door: `Arc::clone(server.ai.models())`.
    pub door: Arc<ModelRuntime>,
    /// The vault the host serves; its live voice rows pick both routes.
    pub vault: Arc<Vault>,
    /// The voice the assistant speaks in.
    pub render: VoiceRender,
    /// The rate and channels of the sibling's PCM16LE.
    pub sample_rate: u32,
    pub channels: u16,
    /// The brain's events, sent by the brain the connection starts.
    pub brain_out: mpsc::Receiver<VoiceBrainOut>,
    /// The session's cadence for cutting the brain's text into sentences.
    pub chunking: VoiceChunkPolicy,
    /// How many calls the media queue holds.
    pub queue_capacity: usize,
}

impl VoiceWireBindings {
    /// The media bindings over the wire, and the wire's control seam.
    pub(super) fn build(
        self,
    ) -> oneiron::Result<(MediaTts, MediaBridge, MediaWorker, WireMedia, WireControl)> {
        let (playout, playout_out) = mpsc::channel(PLAYOUT_QUEUE);
        // The wire carries the sibling's audio: no separate audio side.
        let (_, audio_in) = mpsc::channel(1);
        let (control, control_out) = mpsc::unbounded_channel();
        let (tts, bridge, worker) = VoiceMediaBindings {
            door: self.door,
            vault: self.vault,
            render: self.render,
            sample_rate: self.sample_rate,
            channels: self.channels,
            audio_in,
            brain_out: self.brain_out,
            chunking: self.chunking,
            playout,
            queue_capacity: self.queue_capacity,
        }
        .build()?;
        let wire = WireMedia {
            playout: playout_out,
            control: control_out,
            ended: None,
        };
        Ok((tts, bridge, worker, wire, WireControl(control)))
    }
}

/// What the host has for the wire, beside the transcript replies.
pub(super) struct WireMedia {
    playout: mpsc::Receiver<VoicePlayout>,
    control: mpsc::UnboundedReceiver<ControlOut>,
    /// The generation whose end last went out: the only one `drained` names.
    ended: Option<GenerationEpoch>,
}

pub(super) enum WireOut {
    Playout(Option<VoicePlayout>),
    Control(Option<ControlOut>),
}

impl WireMedia {
    /// The next spoken frame or end, or the next control; forever without
    /// a wire.
    pub(super) async fn next(wire: &mut Option<Self>) -> WireOut {
        let Some(wire) = wire else {
            return std::future::pending().await;
        };
        tokio::select! {
            playout = wire.playout.recv() => WireOut::Playout(playout),
            control = wire.control.recv() => WireOut::Control(control),
        }
    }

    /// The next control already queued, without waiting.
    pub(super) fn queued_control(&mut self) -> Option<ControlOut> {
        self.control.try_recv().ok()
    }

    pub(super) fn ended(&mut self, generation: GenerationEpoch) {
        self.ended = Some(generation);
    }

    /// The generation a `drained` names, if its end went out.
    pub(super) fn drained(&self, generation: u64) -> Option<GenerationEpoch> {
        self.ended.filter(|ended| ended.value() == generation)
    }
}

/// One control for the wire.
pub(super) enum ControlOut {
    Flush(GenerationEpoch),
    Event(ControlEvent),
}

/// The connection's `CascadeControl`: each stop's flush and control goes
/// out on the wire. Audio the host still queues for a stopped generation
/// fails its gate at dequeue, before the flush can be overtaken.
pub(super) struct WireControl(mpsc::UnboundedSender<ControlOut>);

impl CascadeControl for WireControl {
    fn flush_queued_pcm(&mut self, generation: GenerationEpoch) -> oneiron::Result<()> {
        self.0
            .send(ControlOut::Flush(generation))
            .map_err(|_| invalid("connection closed"))
    }

    fn submit(&mut self, event: ControlEvent) -> oneiron::Result<()> {
        self.0
            .send(ControlOut::Event(event))
            .map_err(|_| invalid("connection closed"))
    }
}

/// Spoken audio as base64 frame payloads, each under the frame limit.
pub(super) fn pcm_chunks(frame: &PcmFrame) -> Vec<String> {
    let bytes: Vec<u8> = frame
        .samples
        .iter()
        .flat_map(|sample| sample.to_le_bytes())
        .collect();
    bytes
        .chunks(PCM_CHUNK_BYTES)
        .map(|chunk| STANDARD.encode(chunk))
        .collect()
}

/// The sibling's microphone audio: STANDARD base64 of whole PCM16LE
/// samples.
pub(super) fn decode_pcm(data: &str) -> Option<Vec<u8>> {
    let bytes = STANDARD.decode(data).ok()?;
    (!bytes.is_empty() && bytes.len() % 2 == 0).then_some(bytes)
}

pub(super) fn stop_reason(reason: StopReason) -> &'static str {
    match reason {
        StopReason::UserBargeIn => "user_barge_in",
        StopReason::Safeguard => "safeguard",
        StopReason::RosterChanged => "roster_changed",
        StopReason::OutputFailed => "output_failed",
        StopReason::SessionEnd => "session_end",
    }
}
