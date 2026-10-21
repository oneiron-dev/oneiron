//! Voice media leased live ASR stream.
//! Entry: LeasedAsrStream.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    AsrStream, Error, LeasedAsrStream, MAX_STREAM_AUDIO_MS, MediaStreamLease, MediaVoiceRoute,
    Result, VoiceStreamDoor, invalid, settlement,
};

impl<S: AsrStream> LeasedAsrStream<S> {
    /// `sample_rate` and `channels` describe the PCM16LE the host hands to
    /// `accept_audio`, as the stream's request named them.
    pub fn new(inner: S, lease: MediaStreamLease, sample_rate: u32, channels: u16) -> Result<Self> {
        if !(8_000..=192_000).contains(&sample_rate) || !(1..=2).contains(&channels) {
            return Err(invalid("unsupported PCM rate or channels"));
        }
        Ok(Self {
            inner,
            lease: Some(lease),
            sample_rate,
            channels,
            bytes: 0,
        })
    }

    /// Opens one bounded stream on `route` through `door`, and wraps
    /// `inner`, the provider's stream, in its lease.
    pub async fn open(
        door: &dyn VoiceStreamDoor,
        route: &MediaVoiceRoute,
        sample_rate: u32,
        channels: u16,
        inner: S,
    ) -> Result<Self> {
        let request = route.stream_request(sample_rate, channels)?;
        let lease = door
            .open_stream(request, MAX_STREAM_AUDIO_MS)
            .await
            .map_err(|error| Error::InvalidConfig(format!("voice media: {error}")))?;
        Self::new(inner, lease, sample_rate, channels)
    }

    /// The provider's stream, for the frames it hands back.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// The audio the stream may still carry, in milliseconds; 0 once it
    /// ended.
    #[must_use]
    pub fn remaining_ms(&self) -> u64 {
        self.lease
            .as_ref()
            .map_or(0, MediaStreamLease::remaining_ms)
    }

    /// Stops the stream: the audio it sent is paid for, and no more leaves.
    pub fn cancel(&mut self) -> Result<()> {
        match self.lease.take() {
            Some(lease) => lease.cancel().map(drop).map_err(settlement),
            None => Ok(()),
        }
    }

    /// The whole milliseconds `bytes` of the stream's PCM16LE play for,
    /// rounded up.
    fn played_ms(&self, bytes: u64) -> u64 {
        let per_second = u64::from(self.sample_rate) * u64::from(self.channels) * 2;
        bytes.saturating_mul(1_000).div_ceil(per_second.max(1))
    }
}

impl<S: AsrStream> AsrStream for LeasedAsrStream<S> {
    fn accept_audio(&mut self, pcm: &[u8]) -> Result<()> {
        let bytes = self
            .bytes
            .checked_add(pcm.len() as u64)
            .ok_or_else(|| invalid("stream exhausted"))?;
        let played = self.played_ms(bytes);
        let lease = self
            .lease
            .as_mut()
            .ok_or_else(|| invalid("audio after end"))?;
        // Metered before it leaves: audio the lease refuses is never sent.
        lease
            .admit_audio(played.saturating_sub(lease.admitted_ms()))
            .map_err(|_| invalid("stream bound reached; end it and open the next"))?;
        self.bytes = bytes;
        self.inner.accept_audio(pcm)
    }

    fn end(&mut self) -> Result<()> {
        let Some(lease) = self.lease.take() else {
            return Ok(());
        };
        match self.inner.end() {
            Ok(()) => lease.end(None).map(drop).map_err(settlement),
            Err(error) => {
                // The refusal, if any, is on the Settled receipt.
                lease.cancel().ok();
                Err(error)
            }
        }
    }
}
