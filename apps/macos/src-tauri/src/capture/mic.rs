//! The microphone leg.
//!
//! One mono stream off the default input device. A multi-channel microphone is
//! reduced to its first channel rather than mixed: the near end of a
//! conversation is one voice in one room, and averaging channels would smear
//! it. The stream is not `Send`, so it is opened on — and owned by — the
//! capture worker thread.

use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

use super::{CaptureError, PcmQueue, Result};

/// A running microphone stream feeding a [`PcmQueue`].
pub struct MicStream {
    /// Held for its lifetime: dropping it stops the stream.
    _stream: cpal::Stream,
    device: String,
    sample_rate: u32,
    fault: Arc<Mutex<Option<String>>>,
}

impl MicStream {
    /// Opens the default input device and starts feeding `queue`.
    ///
    /// # Errors
    ///
    /// [`CaptureError::NoInputDevice`] when the host has no microphone, or
    /// [`CaptureError::Audio`] when the backend refuses the stream or offers
    /// only a sample format this recorder does not read.
    pub fn open(queue: PcmQueue) -> Result<Self> {
        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .ok_or(CaptureError::NoInputDevice)?;
        let name = device
            .description()
            .map_or_else(|_| "unnamed input".to_owned(), |d| d.name().to_owned());
        let supported = device.default_input_config().map_err(audio_error)?;

        let sample_rate = supported.sample_rate();
        let channels = usize::from(supported.channels()).max(1);
        let format = supported.sample_format();
        let config = supported.config();

        let fault = Arc::new(Mutex::new(None));
        let on_error = {
            let fault = Arc::clone(&fault);
            move |err: cpal::Error| {
                if let Ok(mut slot) = fault.lock() {
                    *slot = Some(err.to_string());
                }
            }
        };

        let stream = match format {
            cpal::SampleFormat::F32 => device.build_input_stream::<f32, _, _>(
                config,
                move |data, _| {
                    queue.extend(data.iter().step_by(channels).copied().map(pcm_from_f32));
                },
                on_error,
                None,
            ),
            cpal::SampleFormat::I16 => device.build_input_stream::<i16, _, _>(
                config,
                move |data, _| {
                    queue.extend(data.iter().step_by(channels).copied());
                },
                on_error,
                None,
            ),
            other => {
                return Err(CaptureError::Audio(format!(
                    "input device offers only the {other:?} sample format"
                )));
            }
        }
        .map_err(audio_error)?;
        stream.play().map_err(audio_error)?;

        Ok(Self {
            _stream: stream,
            device: name,
            sample_rate,
            fault,
        })
    }

    /// Human-readable name of the device being recorded, as it goes onto every
    /// segment.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Frame rate the microphone is delivering.
    #[must_use]
    pub const fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// The last backend error, if the stream has faulted. A dead microphone
    /// must surface as a failed capture, never as a segment full of silence.
    #[must_use]
    pub fn fault(&self) -> Option<String> {
        self.fault.lock().ok().and_then(|slot| slot.clone())
    }
}

fn audio_error(err: cpal::Error) -> CaptureError {
    CaptureError::Audio(err.to_string())
}

/// Float samples are nominally in `[-1, 1]`; anything outside is clipped
/// rather than wrapped, because a wrapped sample is a click.
fn pcm_from_f32(sample: f32) -> i16 {
    let scaled = sample.clamp(-1.0, 1.0) * f32::from(i16::MAX);
    scaled as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_samples_clip_instead_of_wrapping() {
        assert_eq!(pcm_from_f32(0.0), 0);
        assert_eq!(pcm_from_f32(1.0), i16::MAX);
        assert_eq!(pcm_from_f32(4.0), i16::MAX);
        assert_eq!(pcm_from_f32(-4.0), -i16::MAX);
    }
}
