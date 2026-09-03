//! Dual-stream capture: the microphone and the audio other processes are
//! playing, cut into fixed segments and committed one by one.
//!
//! The vocabulary lives here; the platform edges live in the submodules
//! ([`mic`] for the microphone stream, [`route`] for output-route detection,
//! [`tap`] for the Core Audio process tap) and the running capture is
//! [`stream::DualStreamCapture`].
//!
//! Two honesty rules shape the whole module:
//!
//! * **A segment states the echo-cancellation mode it actually got.** The mode
//!   is derived from what happened — the output route the segment was opened
//!   on, whether any far-end audio was in it, and whether this build has a
//!   canceller at all — never from what we wish had happened.
//! * **Capture is never blocked by cancellation.** No canceller, no far-end
//!   tap, no route information: the microphone still records and the segment
//!   says so.

#[cfg(target_os = "macos")]
mod hal;
pub mod mic;
pub mod route;
pub mod segment;
pub mod stream;
#[cfg(target_os = "macos")]
pub mod tap;

use std::fmt;
use std::sync::{Arc, Mutex};

use oneiron::voice_segment::{
    AEC_MODE_ACTIVE, AEC_MODE_BYPASSED_HEADPHONES, AEC_MODE_BYPASSED_OTHER, AEC_MODE_UNAVAILABLE,
};

pub use route::OutputRoute;
pub use segment::{SEGMENT_SECONDS, SegmentCutter, SegmentSink, SegmentSpec};
pub use stream::{CaptureLauncher, DualStreamCapture, LiveCapture, RunningCapture};

/// Everything that can stop a capture from starting or continuing.
#[derive(Debug)]
pub enum CaptureError {
    /// The host has no microphone, or the one it has cannot be opened.
    NoInputDevice,
    /// The audio backend refused the stream.
    Audio(String),
    /// A Core Audio call returned a non-zero `OSStatus`.
    CoreAudio {
        /// The call that failed, e.g. `AudioHardwareCreateProcessTap`.
        call: &'static str,
        /// The raw status.
        status: i32,
    },
    /// The system-audio process tap is a macOS 14.2+ facility; this host has
    /// no such thing. The microphone leg still runs.
    NoSystemAudioTap,
    /// The vault refused a committed segment.
    Vault(oneiron::Error),
    /// A segment carried no audio at all, so there is nothing to state.
    EmptySegment,
    /// WAV encoding failed.
    Encoding(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputDevice => f.write_str("no input device is available"),
            Self::Audio(reason) => write!(f, "audio backend refused the stream: {reason}"),
            Self::CoreAudio { call, status } => write!(f, "{call} failed with status {status}"),
            Self::NoSystemAudioTap => f.write_str("system-audio capture needs a macOS process tap"),
            Self::Vault(err) => write!(f, "the vault refused the segment: {err}"),
            Self::EmptySegment => f.write_str("the segment carried no audio"),
            Self::Encoding(reason) => write!(f, "segment encoding failed: {reason}"),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<oneiron::Error> for CaptureError {
    fn from(err: oneiron::Error) -> Self {
        Self::Vault(err)
    }
}

/// Capture result.
pub type Result<T> = std::result::Result<T, CaptureError>;

/// The hand-off between a realtime audio callback and the segment worker.
///
/// A mutex on an audio thread is a compromise, made deliberately: the critical
/// section is one `extend` of a `Vec` the worker drains every tick, the
/// alternative is a lock-free ring nobody in this tree owns yet, and a
/// dropped-lock glitch in a one-minute meeting segment is a far smaller harm
/// than a dependency we cannot audit. If capture ever grows a latency budget,
/// this is the first thing to replace.
#[derive(Debug, Clone, Default)]
pub struct PcmQueue(Arc<Mutex<Vec<i16>>>);

impl PcmQueue {
    /// An empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends samples. Called from the audio callback; a poisoned lock means
    /// the worker panicked and the capture is over, so the samples are simply
    /// dropped rather than panicking a realtime thread.
    pub fn extend(&self, samples: impl Iterator<Item = i16>) {
        if let Ok(mut buffer) = self.0.lock() {
            buffer.extend(samples);
        }
    }

    /// Takes everything queued so far.
    #[must_use]
    pub fn drain(&self) -> Vec<i16> {
        self.0
            .lock()
            .map(|mut buffer| std::mem::take(&mut *buffer))
            .unwrap_or_default()
    }
}

/// Whether this build has an echo canceller wired in for speaker routes.
///
/// v1 ships route *awareness*, not cancellation: no canceller backend is
/// linked, so a live capture reports [`Cancellation::Absent`] and speaker-route
/// segments honestly record `unavailable` rather than claiming a cancellation
/// nobody ran. The variant exists because the mode mapping — not a future
/// refactor — is what a cancellation backend has to satisfy when it lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancellation {
    /// Nothing is cancelling echo on this build.
    Absent,
    /// A canceller processed the segment.
    Installed,
}

/// Whether any far-end audio was actually in the segment.
///
/// "Far end" is what the other apps were playing. With none of it there is no
/// echo path to cancel, whatever the output route is, and saying the segment
/// was *bypassed* is the truthful statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FarEnd {
    /// The process tap contributed no audio: it did not run, or everything it
    /// carried was silence.
    Absent,
    /// The tap carried signal.
    Present,
}

/// The echo-cancellation mode a segment actually got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AecMode {
    /// There was nothing to cancel: headphones (no acoustic path back into the
    /// microphone) or no far-end audio at all.
    Bypassed {
        /// The output route the segment was opened on.
        route: OutputRoute,
    },
    /// A canceller ran over the segment.
    Active,
    /// An echo path existed and nothing was available to cancel it. Capture
    /// continued anyway — this is a statement about the audio, not a failure.
    Unavailable,
}

impl AecMode {
    /// Derives the mode from what the segment actually experienced.
    ///
    /// Headphones win first: an isolated route has no echo path even when the
    /// far end is loud. Then an absent far end, which is a bypass on any
    /// route. Only a real echo path reaches the canceller question.
    #[must_use]
    pub const fn for_segment(
        route: OutputRoute,
        far_end: FarEnd,
        cancellation: Cancellation,
    ) -> Self {
        match (route, far_end, cancellation) {
            (OutputRoute::Headphones, _, _) => Self::Bypassed {
                route: OutputRoute::Headphones,
            },
            (route, FarEnd::Absent, _) => Self::Bypassed { route },
            (_, FarEnd::Present, Cancellation::Installed) => Self::Active,
            (_, FarEnd::Present, Cancellation::Absent) => Self::Unavailable,
        }
    }

    /// The `aec_mode` string this mode is written as in the `voice.segment`
    /// claim. The engine family pins the vocabulary; this is the only place
    /// the app maps onto it.
    #[must_use]
    pub const fn claim_mode(self) -> &'static str {
        match self {
            Self::Bypassed {
                route: OutputRoute::Headphones,
            } => AEC_MODE_BYPASSED_HEADPHONES,
            Self::Bypassed { .. } => AEC_MODE_BYPASSED_OTHER,
            Self::Active => AEC_MODE_ACTIVE,
            Self::Unavailable => AEC_MODE_UNAVAILABLE,
        }
    }
}

/// What one committed segment is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentMeta {
    /// Unix second the segment opened.
    pub started_at: u64,
    /// How much audio it holds.
    pub duration_ms: u32,
    /// The mode the audio actually got.
    pub aec: AecMode,
    /// Human-readable name of the input device it was captured on.
    pub device: String,
    /// 1 when only the microphone was captured, 2 when the process tap
    /// contributed a far-end channel alongside it.
    pub channels: u16,
}

impl SegmentMeta {
    /// The claim's `span_end`. A segment's span must advance — the engine
    /// family rejects one that does not — so a sub-second segment still spans
    /// the second it occupied.
    ///
    /// # Errors
    ///
    /// [`CaptureError::EmptySegment`] when the segment holds no audio at all.
    pub fn span_end(&self) -> Result<u64> {
        if self.duration_ms == 0 {
            return Err(CaptureError::EmptySegment);
        }
        Ok(self.started_at + u64::from(self.duration_ms.div_ceil(1_000).max(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headphones_bypass_on_any_far_end() {
        for far_end in [FarEnd::Absent, FarEnd::Present] {
            for cancellation in [Cancellation::Absent, Cancellation::Installed] {
                let mode = AecMode::for_segment(OutputRoute::Headphones, far_end, cancellation);
                assert_eq!(
                    mode.claim_mode(),
                    AEC_MODE_BYPASSED_HEADPHONES,
                    "headphones have no acoustic path back to the microphone"
                );
            }
        }
    }

    #[test]
    fn a_silent_far_end_bypasses_on_loud_routes() {
        for route in [OutputRoute::Speakers, OutputRoute::Other] {
            let mode = AecMode::for_segment(route, FarEnd::Absent, Cancellation::Absent);
            assert_eq!(mode, AecMode::Bypassed { route });
            assert_eq!(mode.claim_mode(), AEC_MODE_BYPASSED_OTHER);
        }
    }

    #[test]
    fn a_real_echo_path_is_active_or_unavailable_but_never_bypassed() {
        assert_eq!(
            AecMode::for_segment(
                OutputRoute::Speakers,
                FarEnd::Present,
                Cancellation::Installed
            )
            .claim_mode(),
            AEC_MODE_ACTIVE
        );
        // The blueprint's load-bearing case: no canceller does NOT stop the
        // recording, it only changes what the segment claims about itself.
        assert_eq!(
            AecMode::for_segment(OutputRoute::Speakers, FarEnd::Present, Cancellation::Absent)
                .claim_mode(),
            AEC_MODE_UNAVAILABLE
        );
    }

    #[test]
    fn a_sub_second_segment_still_spans_a_second() {
        let meta = SegmentMeta {
            started_at: 1_773_532_800,
            duration_ms: 40,
            aec: AecMode::Unavailable,
            device: "built-in".to_owned(),
            channels: 2,
        };
        assert_eq!(meta.span_end().expect("non-empty"), meta.started_at + 1);
    }

    #[test]
    fn an_empty_segment_has_no_span() {
        let meta = SegmentMeta {
            started_at: 1_773_532_800,
            duration_ms: 0,
            aec: AecMode::Unavailable,
            device: "built-in".to_owned(),
            channels: 1,
        };
        assert!(matches!(meta.span_end(), Err(CaptureError::EmptySegment)));
    }
}
