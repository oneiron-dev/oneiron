//! Cutting a continuous capture into committed segments.
//!
//! This is the part of capture that has nothing to do with hardware, and it is
//! where the segment law lives: a segment latches its output route when it
//! **opens**, so a route flip mid-segment lands on the next boundary and never
//! rewrites what a segment already said about itself. Stopping mid-segment
//! commits what was recorded rather than throwing it away.

use std::io::Cursor;

use oneiron::EntityId;

use super::{AecMode, Cancellation, CaptureError, FarEnd, OutputRoute, Result, SegmentMeta};

/// Segment length. One minute is short enough that a stop loses nothing and
/// long enough that a meeting is not a thousand entities.
pub const SEGMENT_SECONDS: u32 = 60;

/// Sixteen-bit PCM: what the WAV carries, and what both legs are converted to.
type Pcm = i16;

/// The fixed shape of one capture run.
#[derive(Debug, Clone)]
pub struct SegmentSpec {
    /// Frame rate both legs are aligned at.
    pub sample_rate: u32,
    /// Segment length in seconds.
    pub seconds: u32,
    /// Input device name, recorded on every segment.
    pub device: String,
    /// Whether this run has an echo canceller at all.
    pub cancellation: Cancellation,
}

impl SegmentSpec {
    /// A run on `device` at `sample_rate`, one-minute segments, no canceller —
    /// the shape v1 actually ships.
    #[must_use]
    pub fn new(sample_rate: u32, device: String) -> Self {
        Self {
            sample_rate,
            seconds: SEGMENT_SECONDS,
            device,
            cancellation: Cancellation::Absent,
        }
    }
}

/// One block of time-aligned audio: the microphone, and the far end when a
/// process tap is contributing one.
#[derive(Debug, Clone, Copy)]
pub struct Frames<'a> {
    /// Microphone samples, one per frame.
    pub mic: &'a [Pcm],
    /// Far-end samples, one per frame, when the tap is running.
    pub far: Option<&'a [Pcm]>,
}

impl<'a> Frames<'a> {
    /// Frames in this block. When a far-end leg is present the two legs are
    /// truncated to their common length, because a frame is only aligned if
    /// both halves of it exist.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.far {
            Some(far) => self.mic.len().min(far.len()),
            None => self.mic.len(),
        }
    }

    /// Whether the block carries nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn slice(&self, offset: usize, len: usize) -> Self {
        Self {
            mic: &self.mic[offset..offset + len],
            far: self.far.map(|far| &far[offset..offset + len]),
        }
    }
}

/// Where committed segments go.
pub trait SegmentSink: Send + Sync {
    /// Lands one encoded segment and the statement of what it is, returning
    /// the identity of the stored audio.
    ///
    /// # Errors
    ///
    /// Whatever the destination refused with.
    fn commit_segment(&self, audio: &[u8], meta: SegmentMeta) -> Result<EntityId>;
}

/// The segment currently being filled.
#[derive(Debug)]
struct OpenSegment {
    started_at: u64,
    /// Latched when the segment opened — the whole point of the boundary rule.
    route: OutputRoute,
    mic: Vec<Pcm>,
    far: Option<Vec<Pcm>>,
}

impl OpenSegment {
    fn new(started_at: u64, route: OutputRoute, tapped: bool) -> Self {
        Self {
            started_at,
            route,
            mic: Vec::new(),
            far: tapped.then(Vec::new),
        }
    }

    fn frames(&self) -> usize {
        self.mic.len()
    }

    fn extend(&mut self, frames: Frames<'_>) {
        self.mic.extend_from_slice(frames.mic);
        if let (Some(far), Some(block)) = (self.far.as_mut(), frames.far) {
            far.extend_from_slice(block);
        }
    }

    /// Two channels once a far-end leg is riding along, one otherwise.
    fn channels(&self) -> u16 {
        if self.far.is_some() { 2 } else { 1 }
    }

    /// Whether any far-end audio was in this segment. Digital silence is not
    /// an echo path, so a tap that carried nothing is an absent far end.
    fn far_end(&self) -> FarEnd {
        match &self.far {
            Some(far) if far.iter().any(|sample| *sample != 0) => FarEnd::Present,
            _ => FarEnd::Absent,
        }
    }
}

/// Cuts a capture into segments and commits each one.
#[derive(Debug)]
pub struct SegmentCutter {
    spec: SegmentSpec,
    open: Option<OpenSegment>,
    /// Where the next segment starts, so segments stay contiguous instead of
    /// drifting with however often the caller happens to push.
    next_start: Option<u64>,
}

impl SegmentCutter {
    /// A cutter with nothing open yet.
    #[must_use]
    pub fn new(spec: SegmentSpec) -> Self {
        Self {
            spec,
            open: None,
            next_start: None,
        }
    }

    /// Whether a segment is currently accumulating.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.open.is_some()
    }

    fn capacity(&self) -> usize {
        self.spec.sample_rate as usize * self.spec.seconds as usize
    }

    /// Feeds one aligned block, committing every segment it completes.
    ///
    /// `route` is consulted only when a segment **opens**: a flip inside a
    /// segment applies from the next boundary. `now` seeds the very first
    /// segment; later segments follow contiguously from it.
    ///
    /// # Errors
    ///
    /// Whatever `sink` refused a completed segment with.
    pub fn push(
        &mut self,
        frames: Frames<'_>,
        now: u64,
        route: OutputRoute,
        sink: &dyn SegmentSink,
    ) -> Result<()> {
        let total = frames.len();
        let capacity = self.capacity();
        let mut offset = 0;

        while offset < total {
            if self.open.is_none() {
                let started_at = self.next_start.unwrap_or(now);
                self.open = Some(OpenSegment::new(started_at, route, frames.far.is_some()));
            }

            let filled = {
                let open = self.open.as_mut().expect("a segment was just opened");
                let take = (capacity - open.frames()).min(total - offset);
                open.extend(frames.slice(offset, take));
                offset += take;
                open.frames() >= capacity
            };

            if filled {
                let finished = self.open.take().expect("the segment was open");
                self.next_start = Some(finished.started_at + u64::from(self.spec.seconds));
                self.commit(finished, sink)?;
            }
        }
        Ok(())
    }

    /// Commits the segment that was open when the operator said stop.
    ///
    /// Returns `None` when nothing was open. A partially filled segment is
    /// committed with its true duration — stopping mid-segment must not cost
    /// the operator the minute they were recording.
    ///
    /// # Errors
    ///
    /// Whatever `sink` refused the segment with.
    pub fn flush(&mut self, sink: &dyn SegmentSink) -> Result<Option<EntityId>> {
        let Some(finished) = self.open.take() else {
            return Ok(None);
        };
        if finished.frames() == 0 {
            return Ok(None);
        }
        self.next_start = Some(finished.started_at + u64::from(self.spec.seconds));
        self.commit(finished, sink).map(Some)
    }

    fn commit(&self, segment: OpenSegment, sink: &dyn SegmentSink) -> Result<EntityId> {
        let meta = SegmentMeta {
            started_at: segment.started_at,
            duration_ms: frames_to_millis(segment.frames(), self.spec.sample_rate),
            aec: AecMode::for_segment(segment.route, segment.far_end(), self.spec.cancellation),
            device: self.spec.device.clone(),
            channels: segment.channels(),
        };
        let audio = encode_wav(&segment, self.spec.sample_rate)?;
        sink.commit_segment(&audio, meta)
    }
}

fn frames_to_millis(frames: usize, sample_rate: u32) -> u32 {
    if sample_rate == 0 {
        return 0;
    }
    let millis = frames as u64 * 1_000 / u64::from(sample_rate);
    u32::try_from(millis).unwrap_or(u32::MAX)
}

/// Interleaves the legs into one WAV: channel 0 is the microphone, channel 1
/// the far end. Two aligned streams, one file, no post-hoc pairing.
fn encode_wav(segment: &OpenSegment, sample_rate: u32) -> Result<Vec<u8>> {
    let spec = hound::WavSpec {
        channels: segment.channels(),
        sample_rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer =
            hound::WavWriter::new(&mut cursor, spec).map_err(|err| encoding_error(&err))?;
        match &segment.far {
            Some(far) => {
                for (mic, far) in segment.mic.iter().zip(far.iter()) {
                    writer
                        .write_sample(*mic)
                        .map_err(|err| encoding_error(&err))?;
                    writer
                        .write_sample(*far)
                        .map_err(|err| encoding_error(&err))?;
                }
            }
            None => {
                for mic in &segment.mic {
                    writer
                        .write_sample(*mic)
                        .map_err(|err| encoding_error(&err))?;
                }
            }
        }
        writer.finalize().map_err(|err| encoding_error(&err))?;
    }
    Ok(cursor.into_inner())
}

fn encoding_error(err: &hound::Error) -> CaptureError {
    CaptureError::Encoding(err.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    const RATE: u32 = 8_000;
    const NOW: u64 = 1_773_532_800;

    #[derive(Default)]
    struct RecordingSink {
        committed: Mutex<Vec<(Vec<u8>, SegmentMeta)>>,
    }

    impl RecordingSink {
        fn metas(&self) -> Vec<SegmentMeta> {
            self.committed
                .lock()
                .expect("sink lock")
                .iter()
                .map(|(_, meta)| meta.clone())
                .collect()
        }

        fn audio(&self) -> Vec<Vec<u8>> {
            self.committed
                .lock()
                .expect("sink lock")
                .iter()
                .map(|(audio, _)| audio.clone())
                .collect()
        }
    }

    impl SegmentSink for RecordingSink {
        fn commit_segment(&self, audio: &[u8], meta: SegmentMeta) -> Result<EntityId> {
            self.committed
                .lock()
                .expect("sink lock")
                .push((audio.to_vec(), meta));
            Ok(EntityId::now())
        }
    }

    fn spec() -> SegmentSpec {
        SegmentSpec {
            sample_rate: RATE,
            seconds: 2,
            device: "built-in-microphone".to_owned(),
            cancellation: Cancellation::Absent,
        }
    }

    fn tone(frames: usize) -> Vec<Pcm> {
        (0..frames).map(|i| (i % 97) as Pcm).collect()
    }

    #[test]
    fn a_full_segment_commits_at_the_boundary_and_the_remainder_stays_open() {
        let sink = RecordingSink::default();
        let mut cutter = SegmentCutter::new(spec());
        let mic = tone(RATE as usize * 3);
        let far = vec![0; mic.len()];

        cutter
            .push(
                Frames {
                    mic: &mic,
                    far: Some(&far),
                },
                NOW,
                OutputRoute::Speakers,
                &sink,
            )
            .expect("push");

        let metas = sink.metas();
        assert_eq!(metas.len(), 1, "three seconds of a two-second segment");
        assert_eq!(metas[0].started_at, NOW);
        assert_eq!(metas[0].duration_ms, 2_000);
        assert_eq!(metas[0].channels, 2);
        assert!(cutter.is_open(), "the third second is still accumulating");

        // Stop mid-segment: what was recorded is committed, not dropped.
        cutter
            .flush(&sink)
            .expect("flush")
            .expect("a partial segment");
        let metas = sink.metas();
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[1].started_at, NOW + 2, "segments stay contiguous");
        assert_eq!(metas[1].duration_ms, 1_000);
        assert!(!cutter.is_open());
    }

    #[test]
    fn a_route_flip_applies_at_the_next_boundary() {
        let sink = RecordingSink::default();
        let mut cutter = SegmentCutter::new(spec());
        let mic = tone(RATE as usize * 2);
        let far = tone(RATE as usize * 2);
        let frames = Frames {
            mic: &mic,
            far: Some(&far),
        };

        // Opened on headphones, and the flip to speakers arrives while the
        // segment is still filling.
        cutter
            .push(
                frames.slice(0, RATE as usize),
                NOW,
                OutputRoute::Headphones,
                &sink,
            )
            .expect("push");
        cutter
            .push(
                frames.slice(RATE as usize, RATE as usize),
                NOW,
                OutputRoute::Speakers,
                &sink,
            )
            .expect("push");
        // The next segment opens on the new route.
        cutter
            .push(frames, NOW, OutputRoute::Speakers, &sink)
            .expect("push");

        let metas = sink.metas();
        assert_eq!(metas.len(), 2);
        assert_eq!(
            metas[0].aec,
            AecMode::Bypassed {
                route: OutputRoute::Headphones
            },
            "the segment keeps the route it opened on"
        );
        assert_eq!(
            metas[1].aec,
            AecMode::Unavailable,
            "the flip lands on the next segment: speakers, far end present, no canceller"
        );
    }

    #[test]
    fn a_mic_only_run_commits_mono_segments_with_no_echo_path() {
        let sink = RecordingSink::default();
        let mut cutter = SegmentCutter::new(spec());
        let mic = tone(RATE as usize * 2);

        cutter
            .push(
                Frames {
                    mic: &mic,
                    far: None,
                },
                NOW,
                OutputRoute::Speakers,
                &sink,
            )
            .expect("push");

        let metas = sink.metas();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].channels, 1);
        assert_eq!(
            metas[0].aec,
            AecMode::Bypassed {
                route: OutputRoute::Speakers
            },
            "no far end was captured, so there was nothing to cancel"
        );
        // A real RIFF/WAVE file carrying two seconds of 16-bit mono PCM.
        let audio = sink.audio();
        assert_eq!(&audio[0][..4], b"RIFF");
        assert_eq!(&audio[0][8..12], b"WAVE");
        assert!(
            audio[0].len() > RATE as usize * 2 * 2,
            "the payload must carry every sample plus a header"
        );
    }

    #[test]
    fn flushing_nothing_commits_nothing() {
        let sink = RecordingSink::default();
        let mut cutter = SegmentCutter::new(spec());
        assert!(cutter.flush(&sink).expect("flush").is_none());
        assert!(sink.metas().is_empty());
    }
}
