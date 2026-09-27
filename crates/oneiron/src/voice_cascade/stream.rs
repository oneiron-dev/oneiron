//! Live, ephemeral LLM-stream fanout to TTS. The host supplies timer ticks and
//! owns budget settlement, generation admission, and any sentence safeguards.

use futures_core::Stream;

use crate::llm::{
    LlmError, LlmEventBus, LlmStream, LlmStreamEvent, ProgressSnapshot, ProgressSubscriber,
    VoiceChunkPolicy, VoiceChunker,
};

use super::{GenerationEpoch, TtsCommand};

#[derive(Debug, thiserror::Error)]
pub enum VoiceStreamFailure {
    #[error(transparent)]
    Stream(#[from] LlmError),
    #[error(transparent)]
    Tts(#[from] crate::Error),
    #[error("invalid voice chunk policy")]
    InvalidPolicy,
}

/// Selected voice generation and resident-selected session cadence.
#[derive(Debug, Clone)]
pub struct VoiceStreamConfig {
    pub generation: GenerationEpoch,
    pub policy: VoiceChunkPolicy,
}

/// Connect a live backend stream to TTS while the bus retains raw, unmodified
/// events for all other subscribers. The host supplies monotonic milliseconds
/// and a stream of timer ticks; ticks must continue during model silence.
/// This is a transport stage, not a replacement for sentence safeguards. A
/// voice host must enforce its existing output policy before audio playback.
/// The submission callback must return promptly. It can borrow a host-owned
/// adapter for one command and release it, so provider callbacks can drain
/// buffered responses before the next stream item.
/// Only a committed terminal reaches TTS; cancellation never speaks the tail.
/// On failure TTS is cancelled; before a committed Done, raw listeners close
/// without a synthetic terminal.
pub async fn drive_voice_stream<T, C, P>(
    bus: &mut LlmEventBus,
    stream: LlmStream<'_>,
    ticks: T,
    mut now_ms: C,
    config: VoiceStreamConfig,
    mut submit: impl FnMut(TtsCommand) -> crate::Result<()>,
    mut on_progress: P,
) -> Result<(), VoiceStreamFailure>
where
    T: Stream<Item = u64> + Unpin,
    C: FnMut() -> u64,
    P: FnMut(ProgressSnapshot),
{
    let VoiceStreamConfig { generation, policy } = config;
    let mut chunker = VoiceChunker::with_policy(policy).ok_or(VoiceStreamFailure::InvalidPolicy)?;
    let mut progress = ProgressSubscriber::default();
    progress.start(now_ms());
    if let Err(error) = submit(TtsCommand::Start { generation }) {
        bus.close_without_terminal();
        let _ = submit(TtsCommand::Cancel { generation });
        return Err(error.into());
    }
    let result = bus
        .drive_with(stream, ticks, &mut now_ms, |event, now| {
            if let Some(event) = event {
                if let Some(snapshot) = progress.observe(event, now) {
                    on_progress(snapshot);
                }
                if matches!(
                    event,
                    LlmStreamEvent::Done {
                        finish_reason: crate::llm::FinishReason::Cancelled,
                        ..
                    }
                ) {
                    submit(TtsCommand::Cancel { generation })?;
                    return Ok(());
                }
                for chunk in chunker.observe(event, now) {
                    submit_chunk(&mut submit, generation, chunk)?;
                }
                if matches!(event, LlmStreamEvent::Done { .. }) {
                    submit(TtsCommand::End { generation })?;
                }
            } else {
                if let Some(snapshot) = progress.tick(now) {
                    on_progress(snapshot);
                }
                if let Some(chunk) = chunker.tick(now) {
                    submit_chunk(&mut submit, generation, chunk)?;
                }
            }
            Ok(())
        })
        .await;
    if result.is_err() {
        let _ = submit(TtsCommand::Cancel { generation });
    }
    result
}

fn submit_chunk(
    submit: &mut impl FnMut(TtsCommand) -> crate::Result<()>,
    generation: GenerationEpoch,
    text: String,
) -> crate::Result<()> {
    submit(TtsCommand::Text { generation, text })?;
    submit(TtsCommand::Flush { generation })
}
