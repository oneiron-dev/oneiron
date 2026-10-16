//! RIFF/WAVE clips: the container a voice call's PCM rides in both ways. A
//! cut utterance is sent as one, and a spoken sentence is asked for as one,
//! so its own header says its rate and channels.

/// One WAV clip's format and its sample bytes, borrowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WavClip<'a> {
    /// 1 for integer PCM, 3 for float, 0xFFFE for an extensible header.
    pub format: u16,
    pub channels: u16,
    pub sample_rate: u32,
    pub byte_rate: u32,
    pub bits_per_sample: u16,
    pub data: &'a [u8],
}

impl<'a> WavClip<'a> {
    /// Reads `bytes` as a RIFF/WAVE clip; `None` for anything else. A
    /// streamed clip's unknown `data` length runs to the end of the bytes.
    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
            return None;
        }
        let half = |at: usize| -> Option<u16> {
            Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
        };
        let word = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
        };
        let mut at = 12;
        let mut format = None;
        while at + 8 <= bytes.len() {
            let size = usize::try_from(word(at + 4)?).ok()?;
            let body = at + 8;
            match &bytes[at..at + 4] {
                b"fmt " => {
                    format = Some((
                        half(body)?,
                        half(body + 2)?,
                        word(body + 4)?,
                        word(body + 8)?,
                        half(body + 14)?,
                    ));
                }
                b"data" => {
                    let (format, channels, sample_rate, byte_rate, bits_per_sample) = format?;
                    if channels == 0 || sample_rate == 0 || byte_rate == 0 {
                        return None;
                    }
                    let end = body.saturating_add(size).min(bytes.len());
                    return Some(Self {
                        format,
                        channels,
                        sample_rate,
                        byte_rate,
                        bits_per_sample,
                        data: &bytes[body..end],
                    });
                }
                _ => {}
            }
            at = body.checked_add(size)?.checked_add(size % 2)?;
        }
        None
    }

    /// How long the clip plays, in milliseconds, rounded up.
    #[must_use]
    pub fn duration_ms(&self) -> u64 {
        (self.data.len() as u64 * 1_000).div_ceil(u64::from(self.byte_rate))
    }

    /// Whether its samples are 16-bit integer PCM.
    #[must_use]
    pub fn is_pcm16(&self) -> bool {
        matches!(self.format, 1 | 0xFFFE) && self.bits_per_sample == 16
    }
}

/// Little-endian 16-bit PCM samples, `channels` interleaved at
/// `sample_rate`, as one WAV clip. `None` when the samples overflow a
/// clip's 32-bit length.
#[must_use]
pub fn pcm16_wav(sample_rate: u32, channels: u16, samples: &[u8]) -> Option<Vec<u8>> {
    let data = u32::try_from(samples.len()).ok()?;
    let riff = data.checked_add(36)?;
    let block = channels.checked_mul(2)?;
    let byte_rate = sample_rate.checked_mul(u32::from(block))?;
    let mut wav = Vec::with_capacity(samples.len() + 44);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&riff.to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&channels.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&block.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data.to_le_bytes());
    wav.extend_from_slice(samples);
    Some(wav)
}
