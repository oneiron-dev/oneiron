//! Media a typed decision reads by reference (owner point 3). `state.media` lists each
//! medium as an immutable ref: what the bytes are of, the full hash of the exact bytes,
//! their type and size (pixels and frame, or duration and time window). The bytes ride
//! beside the 65,536-byte state, never in it. A ref is a locator, not a grant: the host
//! resolves it through the asker's own lane before a call. A medium no rung reads is
//! never captioned in its place; its entry says it was not served, and why.

use super::{
    DecisionDial, DecisionImage, DecisionLadder, DecisionQuestion, DecisionRung, EvidenceVersion,
};
use crate::ingest::meeting_audio::{SourceSpan, SpeakerTrack, SpeechSpan};
use crate::llm::image::ImageBytes;
use crate::memory::PixelRegion;
use crate::{FatalLlmError, LlmResult};
use serde::{Deserialize, Serialize};

/// The state field a call's media entries fill.
pub const MEDIA_FIELD: &str = "media";

/// An image by reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    /// What the pixels are of: an image ASSET at the hash of its bytes, or the document a
    /// host rendered them from, at that document's version.
    pub evidence: EvidenceVersion,
    /// BLAKE3 of the exact encoded bytes.
    pub hash: [u8; 32],
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    /// The region read, in the image's own pixels; none is the whole image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<PixelRegion>,
}

impl ImageRef {
    /// The ref of `image`, whole or framed: PNG or JPEG whose header gives its size, and
    /// a frame of at least one pixel that lies inside it.
    pub fn of(
        evidence: EvidenceVersion,
        image: &ImageBytes,
        frame: Option<PixelRegion>,
    ) -> LlmResult<Self> {
        let (width, height) = dimensions(image)?;
        if frame.is_some_and(|frame| {
            frame.width == 0
                || frame.height == 0
                || u64::from(frame.x) + u64::from(frame.width) > u64::from(width)
                || u64::from(frame.y) + u64::from(frame.height) > u64::from(height)
        }) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(Self {
            evidence,
            hash: *blake3::hash(&image.bytes).as_bytes(),
            media_type: image.media_type.to_ascii_lowercase(),
            width,
            height,
            frame,
        })
    }

    /// Whether `served` is what this ref names: the exact bytes, type and size of the
    /// whole image, or an image the frame's size.
    pub fn check(&self, served: &ImageBytes) -> LlmResult<()> {
        let size = dimensions(served)?;
        let named = match self.frame {
            None => {
                *blake3::hash(&served.bytes).as_bytes() == self.hash
                    && served.media_type.eq_ignore_ascii_case(&self.media_type)
                    && size == (self.width, self.height)
            }
            Some(frame) => size == (frame.width, frame.height),
        };
        if named {
            Ok(())
        } else {
            Err(FatalLlmError::InvalidRequest.into())
        }
    }
}

/// The pixel size a PNG or JPEG header states.
pub(super) fn dimensions(image: &ImageBytes) -> LlmResult<(u32, u32)> {
    let format = match image.media_type.to_ascii_lowercase().as_str() {
        "image/png" => image::ImageFormat::Png,
        "image/jpeg" | "image/jpg" => image::ImageFormat::Jpeg,
        _ => return Err(FatalLlmError::InvalidRequest.into()),
    };
    image::ImageReader::with_format(std::io::Cursor::new(&image.bytes), format)
        .into_dimensions()
        .map_err(|_| FatalLlmError::InvalidRequest.into())
}

/// Audio by reference, on meeting_audio's clocks: `duration_ms`, `window` and the speaker
/// tracks run on the full-file clock; a speech pack adds its source map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudioRef {
    /// The audio ASSET at the hash of its bytes.
    pub evidence: EvidenceVersion,
    pub media_type: String,
    pub duration_ms: u64,
    /// The span a question reads.
    pub window: SpeechSpan,
    /// When the bytes are a speech pack: where each pack span sits in the recording.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_spans: Vec<SourceSpan>,
    /// Exclusive full-file speaker tracks, when the recording is diarized.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub speakers: Vec<SpeakerTrack>,
}

impl AudioRef {
    /// An audio type; a window of at least a millisecond inside the recording; source
    /// spans in pack order, each as long on both clocks; speaker tracks sorted, exclusive,
    /// labelled and inside the recording.
    pub fn validate(&self) -> LlmResult<()> {
        let window = self.window;
        let mut pack_end = 0;
        let spans = self.source_spans.iter().all(|span| {
            let fits = span.source_start_ms < span.source_end_ms
                && span.source_end_ms <= self.duration_ms
                && span.pack_start_ms >= pack_end
                && span.pack_start_ms < span.pack_end_ms
                && span.pack_end_ms - span.pack_start_ms
                    == span.source_end_ms - span.source_start_ms;
            pack_end = span.pack_end_ms;
            fits
        });
        let mut track_end = 0;
        let tracks = self.speakers.iter().all(|track| {
            let fits = track.start_ms < track.end_ms
                && track.start_ms >= track_end
                && track.end_ms <= self.duration_ms
                && !track.speaker_cluster.trim().is_empty();
            track_end = track.end_ms;
            fits
        });
        if !self.media_type.to_ascii_lowercase().starts_with("audio/")
            || window.start_ms >= window.end_ms
            || window.end_ms > self.duration_ms
            || !spans
            || !tracks
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(())
    }
}

/// One medium by reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionMediaRef {
    Image(ImageRef),
    Audio(AudioRef),
}

impl DecisionMediaRef {
    pub fn evidence(&self) -> &EvidenceVersion {
        match self {
            Self::Image(image) => &image.evidence,
            Self::Audio(audio) => &audio.evidence,
        }
    }
}

/// How a referenced medium reached the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaServed {
    /// The bytes the ref names rode beside the state.
    Full,
    /// No rung from the dial's first to its ceiling reads images.
    NoImageReader,
    /// No decision rung reads audio; nothing transcribes it in its place.
    AudioUnsupported,
}

/// One entry of `state.media`: the name the question uses, the ref and what was served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionMedia {
    pub name: String,
    pub reference: DecisionMediaRef,
    pub served: MediaServed,
}

/// One medium the host resolved through the asker's lane, with its bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedMedia {
    Image {
        name: String,
        reference: ImageRef,
        image: ImageBytes,
    },
    Audio {
        name: String,
        reference: AudioRef,
        bytes: Vec<u8>,
    },
}

/// A call's media as asked: the entries for `state.media`, the images that ride beside
/// the state, and the dial, its first rung moved up to the first that reads them.
#[derive(Debug, Clone)]
pub struct MediaCall {
    pub entries: Vec<DecisionMedia>,
    pub images: Vec<DecisionImage>,
    pub dial: DecisionDial,
}

impl MediaCall {
    /// `state` with this call's entries in its media field.
    pub fn state(&self, mut state: serde_json::Value) -> LlmResult<serde_json::Value> {
        let entries =
            serde_json::to_value(&self.entries).map_err(|_| FatalLlmError::InvalidRequest)?;
        let object = state.as_object_mut().ok_or(FatalLlmError::InvalidRequest)?;
        object.insert(MEDIA_FIELD.to_owned(), entries);
        Ok(state)
    }

    /// The media of one call under `dial`. Each image is checked against its ref and
    /// rides as a named image when `first_taking` finds a rung from the dial's first to
    /// its ceiling that takes them, the dial then starting there; otherwise every image
    /// is listed as not served, and the call stands on the rest of its state. Audio is
    /// checked and listed as not served: no rung reads it yet.
    pub fn of(
        dial: DecisionDial,
        media: Vec<ResolvedMedia>,
        first_taking: impl FnOnce(&[DecisionImage]) -> Option<DecisionRung>,
    ) -> LlmResult<Self> {
        let mut entries = Vec::with_capacity(media.len());
        let mut images = Vec::new();
        for medium in media {
            match medium {
                ResolvedMedia::Image {
                    name,
                    reference,
                    image,
                } => {
                    reference.check(&image)?;
                    images.push(DecisionImage {
                        name: name.clone(),
                        evidence: reference.evidence.clone(),
                        image,
                        frame: reference.frame,
                    });
                    entries.push(DecisionMedia {
                        name,
                        reference: DecisionMediaRef::Image(reference),
                        served: MediaServed::Full,
                    });
                }
                ResolvedMedia::Audio {
                    name,
                    reference,
                    bytes,
                } => {
                    reference.validate()?;
                    if bytes.is_empty()
                        || *blake3::hash(&bytes).as_bytes() != reference.evidence.body_hash
                    {
                        return Err(FatalLlmError::InvalidRequest.into());
                    }
                    entries.push(DecisionMedia {
                        name,
                        reference: DecisionMediaRef::Audio(reference),
                        served: MediaServed::AudioUnsupported,
                    });
                }
            }
        }
        DecisionImage::validate_all(&images)?;
        let mut dial = dial;
        if !images.is_empty() {
            match first_taking(&images) {
                Some(first) => dial.first = first,
                None => {
                    images.clear();
                    for entry in &mut entries {
                        if matches!(entry.reference, DecisionMediaRef::Image(_)) {
                            entry.served = MediaServed::NoImageReader;
                        }
                    }
                }
            }
        }
        Ok(Self {
            entries,
            images,
            dial,
        })
    }
}

impl DecisionLadder<'_> {
    /// The media of one call of `question` under `dial` ([`MediaCall::of`]): its images
    /// ride from the first rung of this ladder, from the dial's first to its ceiling,
    /// whose provider takes `question` over them.
    pub fn media_call(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        media: Vec<ResolvedMedia>,
    ) -> LlmResult<MediaCall> {
        MediaCall::of(dial, media, |images| {
            self.first_taking(question, dial, images)
        })
    }
}
