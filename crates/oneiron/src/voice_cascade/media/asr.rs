//! Voice media ASR adapter.
//! Entry: MediaAsrAdapter.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    AiOperation, AsrStream, MAX_UTTERANCE_SECONDS, MediaAsrAdapter, MediaPart, MediaVoiceRoute,
    Result, VoiceMediaQueue, VoiceMediaWork, invalid, pcm16_wav,
};

impl<Q: VoiceMediaQueue> MediaAsrAdapter<Q> {
    /// `sample_rate` and `channels` describe the PCM16LE the host hands to
    /// `accept_audio`.
    pub fn new(route: MediaVoiceRoute, sample_rate: u32, channels: u16, queue: Q) -> Result<Self> {
        if route.operation() != AiOperation::Transcribe {
            return Err(invalid("an ASR adapter hears on a transcription route"));
        }
        if !(8_000..=192_000).contains(&sample_rate) || !(1..=2).contains(&channels) {
            return Err(invalid("unsupported PCM rate or channels"));
        }
        Ok(Self {
            route,
            queue,
            sample_rate,
            channels,
            buffer: Vec::new(),
            next_submission: 0,
            ended: false,
        })
    }

    fn max_bytes(&self) -> usize {
        let per_second = u64::from(self.sample_rate) * u64::from(self.channels) * 2;
        usize::try_from(per_second * u64::from(MAX_UTTERANCE_SECONDS)).unwrap_or(usize::MAX)
    }

    /// Sends what was heard since the last cut as one transcription call:
    /// the host's VAD or turn detector marks an utterance's end here. The
    /// answer comes back as [`VoiceMediaOutput::Heard`](super::VoiceMediaOutput::Heard) with the returned
    /// submission; an empty cut sends nothing. A refused queue keeps the
    /// audio for retry.
    pub fn cut(&mut self) -> Result<Option<u64>> {
        let block = usize::from(self.channels) * 2;
        let whole = self.buffer.len() - self.buffer.len() % block;
        if whole == 0 {
            return Ok(None);
        }
        let next = self
            .next_submission
            .checked_add(1)
            .ok_or_else(|| invalid("submission exhausted"))?;
        let wav = pcm16_wav(self.sample_rate, self.channels, &self.buffer[..whole])
            .ok_or_else(|| invalid("utterance too long"))?;
        let request = self.route.request(
            MediaPart::Audio {
                media_type: "audio/wav".into(),
                bytes: wav,
            },
            None,
        );
        let submission = self.next_submission;
        self.queue.try_submit(VoiceMediaWork::Transcribe {
            submission,
            request,
        })?;
        self.next_submission = next;
        // A trailing half-sample waits for the bytes that complete it.
        self.buffer.drain(..whole);
        Ok(Some(submission))
    }
}

impl<Q: VoiceMediaQueue> AsrStream for MediaAsrAdapter<Q> {
    /// Audio past one call's [`MAX_UTTERANCE_SECONDS`] is not refused: the
    /// utterance is cut at that length, on a whole frame, and the rest
    /// starts the next.
    fn accept_audio(&mut self, mut pcm: &[u8]) -> Result<()> {
        if self.ended {
            return Err(invalid("audio after end"));
        }
        let block = usize::from(self.channels) * 2;
        let max = self.max_bytes();
        while self.buffer.len() + pcm.len() > max {
            let room = max.saturating_sub(self.buffer.len());
            let (head, rest) = pcm.split_at(room - room % block);
            self.buffer.extend_from_slice(head);
            self.cut()?;
            pcm = rest;
        }
        self.buffer.extend_from_slice(pcm);
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        self.cut()?;
        self.ended = true;
        self.buffer.clear();
        Ok(())
    }
}
