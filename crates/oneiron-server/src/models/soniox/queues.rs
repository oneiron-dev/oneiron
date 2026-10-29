use std::collections::VecDeque;
use std::sync::Arc;

use oneiron::Vault;
use oneiron::voice_cascade::soniox::{SonioxTransport, SonioxUpdate};
use oneiron::voice_cascade::spilled_audio::{AudioSpool, SpilledAudio};

use super::FINALIZE;

/// One frame waiting for the socket: audio, held inline or spilled past
/// the queue's bound (FIX 3728), or a control text. It becomes a socket
/// frame only as it goes out.
pub(super) enum OutFrame {
    Audio(SpilledAudio),
    Text(String),
}

impl OutFrame {
    fn inline_bytes(&self) -> u64 {
        match self {
            Self::Audio(audio) => audio.inline_bytes(),
            Self::Text(_) => 0,
        }
    }
}

/// The Soniox client's transport: frames queue here, in order, and the
/// live hearing sends them as the socket takes them. A slow socket is waited
/// on, never refused (Rule 5); what it stalls spills past the inline bound
/// instead of growing in memory (FIX 3728).
pub(super) struct Outbox {
    pub(super) frames: VecDeque<OutFrame>,
    spool: Arc<AudioSpool>,
    vault: Arc<Vault>,
    /// Audio bytes still held in memory, against the spool's bound.
    inline_bytes: u64,
}

impl Outbox {
    pub(super) fn new(spool: Arc<AudioSpool>, vault: Arc<Vault>) -> Self {
        Self {
            frames: VecDeque::new(),
            spool,
            vault,
            inline_bytes: 0,
        }
    }

    fn push(&mut self, frame: OutFrame) -> oneiron::Result<()> {
        self.inline_bytes = self.inline_bytes.saturating_add(frame.inline_bytes());
        self.frames.push_back(frame);
        Ok(())
    }

    pub(super) fn push_text(&mut self, text: String) -> oneiron::Result<()> {
        self.push(OutFrame::Text(text))
    }

    /// Takes a frame back that could not be read for the socket: it waits
    /// for the next segment as everything unsent does.
    pub(super) fn push_front(&mut self, frame: OutFrame) {
        self.inline_bytes = self.inline_bytes.saturating_add(frame.inline_bytes());
        self.frames.push_front(frame);
    }

    pub(super) fn pop(&mut self) -> Option<OutFrame> {
        let frame = self.frames.pop_front()?;
        self.inline_bytes = self.inline_bytes.saturating_sub(frame.inline_bytes());
        Some(frame)
    }
}

impl SonioxTransport for Outbox {
    fn submit_audio(&mut self, bytes: &[u8]) -> oneiron::Result<()> {
        let spill =
            self.inline_bytes.saturating_add(bytes.len() as u64) > self.spool.inline_limit();
        let audio = self.spool.take(&self.vault, bytes.to_vec(), spill);
        self.push(OutFrame::Audio(audio))
    }

    fn submit_finalize(&mut self) -> oneiron::Result<()> {
        self.push_text(FINALIZE.to_owned())
    }

    fn submit_end(&mut self) -> oneiron::Result<()> {
        self.push(OutFrame::Audio(SpilledAudio::inline(Vec::new())))
    }
}

/// What a segment sent that Soniox has not made final yet, in order: its
/// audio, and each cut whose `<fin>` has not come. A dropped socket's next
/// segment hears it again.
pub(super) struct Journal {
    /// Each item sent, at the byte of the segment's audio it follows.
    sent: VecDeque<(u64, Held)>,
    /// Audio bytes the segment has sent.
    end: u64,
    /// Bytes per sample frame (every channel), and per second.
    frame_bytes: u64,
    per_second: u64,
    spool: Arc<AudioSpool>,
    vault: Arc<Vault>,
    /// Audio bytes still held in memory, against the spool's bound.
    inline_bytes: u64,
}

impl Journal {
    pub(super) fn new(
        sample_rate: u32,
        channels: u16,
        spool: Arc<AudioSpool>,
        vault: Arc<Vault>,
    ) -> Self {
        let frame_bytes = u64::from(channels.max(1)) * 2;
        Self {
            sent: VecDeque::new(),
            end: 0,
            frame_bytes,
            per_second: u64::from(sample_rate) * frame_bytes,
            spool,
            vault,
            inline_bytes: 0,
        }
    }

    /// Audio the socket took. It stays until Soniox makes it final,
    /// however long that takes: none is dropped by size (Rule 5), and past
    /// the inline bound it rests spilled (FIX 3728).
    pub(super) fn record_audio(&mut self, pcm: &[u8]) {
        if pcm.is_empty() {
            return;
        }
        let spill = self.inline_bytes.saturating_add(pcm.len() as u64) > self.spool.inline_limit();
        let audio = self.spool.take(&self.vault, pcm.to_vec(), spill);
        self.inline_bytes = self.inline_bytes.saturating_add(audio.inline_bytes());
        self.sent.push_back((self.end, Held::Audio(audio)));
        self.end = self.end.saturating_add(pcm.len() as u64);
    }

    /// A text frame the socket took: only a finalize is the journal's.
    pub(super) fn record_text(&mut self, text: &str) {
        if text == FINALIZE {
            self.sent.push_back((self.end, Held::Cut));
        }
    }

    /// What one frame said: each `<fin>` answers the oldest cut, and the
    /// audio Soniox made final (its `final_audio_proc_ms`, or the end of the
    /// last final word) leaves.
    pub(super) fn heard(&mut self, frame: &serde_json::Value, updates: &[SonioxUpdate]) {
        for _ in updates
            .iter()
            .filter(|update| matches!(update, SonioxUpdate::Finalized))
        {
            if let Some(at) = self
                .sent
                .iter()
                .position(|(_, held)| matches!(held, Held::Cut))
            {
                self.sent.remove(at);
            }
        }
        let words = updates
            .iter()
            .filter_map(|update| match update {
                SonioxUpdate::Asr(event) => Some(event.tokens.iter()),
                SonioxUpdate::Finalized => None,
            })
            .flatten()
            .filter(|token| token.is_final)
            .filter_map(|token| token.end_ms);
        let processed = frame
            .get("final_audio_proc_ms")
            .and_then(serde_json::Value::as_f64);
        let Some(ms) = words.chain(processed).reduce(f64::max) else {
            return;
        };
        if !ms.is_finite() || ms <= 0.0 {
            return;
        }
        let byte = (ms / 1_000.0 * self.per_second as f64) as u64;
        self.confirm(byte / self.frame_bytes * self.frame_bytes);
    }

    /// Drops the audio before byte `upto`; cuts stay until their `<fin>`.
    /// A straddler's made-final front leaves unread, spilled or not.
    fn confirm(&mut self, upto: u64) {
        let Journal {
            sent, inline_bytes, ..
        } = self;
        sent.retain_mut(|(at, held)| {
            let Held::Audio(audio) = held else {
                return true;
            };
            let end = at.saturating_add(audio.len());
            if end <= upto {
                *inline_bytes = inline_bytes.saturating_sub(audio.inline_bytes());
                return false;
            }
            if *at < upto {
                let held_inline = audio.inline_bytes();
                audio.trim_front(upto - *at);
                *inline_bytes = inline_bytes.saturating_sub(held_inline - audio.inline_bytes());
                *at = upto;
            }
            true
        });
    }

    /// What the next segment hears again, in order.
    pub(super) fn replay(self) -> VecDeque<Held> {
        self.sent.into_iter().map(|(_, held)| held).collect()
    }
}

/// What waits for the next segment, in the order the owner said it.
pub(super) enum Held {
    Audio(SpilledAudio),
    Cut,
}
