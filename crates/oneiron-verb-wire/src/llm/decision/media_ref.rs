//! Moved from `crates/oneiron/src/llm/decision/media_ref.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::ingest::meeting_audio::types::SourceSpan;
use crate::ingest::meeting_audio::types::SpeakerTrack;
use crate::ingest::meeting_audio::types::SpeechSpan;
use oneiron_model::llm::FatalLlmError;
use oneiron_model::llm::LlmResult;
use oneiron_model::llm::image::ImageBytes;
use oneiron_store::model_decision::EvidenceVersion;
use oneiron_wake_contract::memory::asset_resolve::types::PixelRegion;
use serde::Deserialize;
use serde::Serialize;

/// An image by reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    /// What the pixels are of: an image ASSET at the hash of its bytes, or the document a
    /// host rendered them from, at that document's version.
    pub evidence: EvidenceVersion,
    /// BLAKE3 of the exact encoded bytes: hex on a JSON wire, its bytes in
    /// storage (FIX 12262).
    #[serde(with = "oneiron_docedit::hex_digest")]
    #[schemars(with = "String")]
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
pub fn dimensions(image: &ImageBytes) -> LlmResult<(u32, u32)> {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MediaServed {
    /// The bytes the ref names rode beside the state.
    Full,
    /// No rung from the dial's first to its ceiling reads images.
    NoImageReader,
    /// No decision rung reads this audio: the caller does not hear audio, or the clip
    /// is in a type no rung takes. Nothing transcribes it in its place.
    AudioUnsupported,
    /// No rung from the dial's first to its ceiling reads audio.
    NoAudioReader,
}

/// One entry of `state.media`: the name the question uses, the ref and what was served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionMedia {
    pub name: String,
    pub reference: DecisionMediaRef,
    pub served: MediaServed,
}
