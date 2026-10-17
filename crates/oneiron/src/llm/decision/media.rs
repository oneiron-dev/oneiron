//! Images and audio clips a typed decision reads. The receipt keeps each one's evidence
//! ref and body version; the pixels and samples ride only on the wire to the seat.

use super::{EvidenceVersion, ImagePin, ProviderPin};
use crate::llm::image::ImageBytes;
use crate::memory::PixelRegion;
use crate::{FatalLlmError, LlmResult};
use base64::Engine as _;
use serde_json::Value;
use std::collections::BTreeSet;

/// Images one call may carry.
pub const MAX_DECISION_IMAGES: usize = 8;
/// Encoded bytes of one image, as handed in.
pub const MAX_DECISION_IMAGE_BYTES: usize = 10 * 1024 * 1024;
/// Encoded bytes of every image in one call.
pub const MAX_DECISION_IMAGES_BYTES: usize = 20 * 1024 * 1024;
/// The long edge a seat is sent unless it states its own.
pub const DECISION_IMAGE_EDGE: u32 = 2_048;

/// One image a question reads. The question names it in backticks, as in "where is
/// `mug` in `camera`?"; a reference image is one more named image. The image fills the
/// state field of its name, so state and question text point at the same thing.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionImage {
    /// The state field it fills and the name the question text uses for it.
    pub name: String,
    /// The unit and body version it was read from.
    pub evidence: EvidenceVersion,
    /// PNG or JPEG bytes.
    pub image: ImageBytes,
    /// Where these pixels sit in the image `evidence` is, when they are a crop of it;
    /// none is the whole image.
    pub frame: Option<PixelRegion>,
}

impl DecisionImage {
    /// A call's images: at most eight, uniquely named, PNG or JPEG, inside the byte
    /// bounds. A name is a plain state key of ASCII letters, digits and `_`.
    pub fn validate_all(images: &[Self]) -> LlmResult<()> {
        let mut names = BTreeSet::new();
        let mut total = 0usize;
        for image in images {
            total = total.saturating_add(image.image.bytes.len());
            if image.name.is_empty()
                || image.name.len() > 64
                || !image
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || !names.insert(image.name.as_str())
                || image.image.bytes.is_empty()
                || image.image.bytes.len() > MAX_DECISION_IMAGE_BYTES
                || image.format().is_none()
            {
                return Err(FatalLlmError::InvalidRequest.into());
            }
        }
        if images.len() > MAX_DECISION_IMAGES || total > MAX_DECISION_IMAGES_BYTES {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(())
    }

    /// A call's images against its state: valid, none filling a field the state already
    /// has, and at least one when the call asks a Box or Point question (`locates`).
    pub fn check_call(images: &[Self], state: &Value, locates: bool) -> LlmResult<()> {
        Self::validate_all(images)?;
        if (locates && images.is_empty())
            || images.iter().any(|image| state.get(&image.name).is_some())
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(())
    }

    /// `"png"` or `"jpeg"`, from the declared media type.
    pub fn format(&self) -> Option<&'static str> {
        match self.image.media_type.to_ascii_lowercase().as_str() {
            "image/png" => Some("png"),
            "image/jpeg" | "image/jpg" => Some("jpeg"),
            _ => None,
        }
    }

    /// The image with its long edge at most `max_edge` pixels, in its own format, at
    /// [`fitted_size`]. A box is in fractions of the image, so it reads the same on the
    /// smaller copy; small text may still need a crop before the call.
    pub fn fitted(&self, max_edge: u32) -> LlmResult<ImageBytes> {
        let format = match self.format() {
            Some("png") => image::ImageFormat::Png,
            Some(_) => image::ImageFormat::Jpeg,
            None => return Err(FatalLlmError::InvalidRequest.into()),
        };
        let decoded = image::load_from_memory_with_format(&self.image.bytes, format)
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        let (width, height) = fitted_size(decoded.width(), decoded.height(), max_edge);
        if (width, height) == (decoded.width(), decoded.height()) {
            return Ok(self.image.clone());
        }
        let smaller = decoded.resize_exact(width, height, image::imageops::FilterType::Triangle);
        let mut bytes = std::io::Cursor::new(Vec::new());
        smaller
            .write_to(&mut bytes, format)
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        Ok(ImageBytes {
            bytes: bytes.into_inner(),
            media_type: self.image.media_type.clone(),
        })
    }

    /// Standard padded base64 of `image`, with no `data:` prefix.
    pub fn base64(image: &ImageBytes) -> String {
        base64::engine::general_purpose::STANDARD.encode(&image.bytes)
    }

    /// What `provider`, fitting to `edge`, was sent of this image: the receipt's pin.
    pub fn pin(&self, provider: ProviderPin, edge: Option<u32>) -> LlmResult<ImagePin> {
        let (width, height) = super::media_ref::dimensions(&self.image)?;
        let (sent_width, sent_height) =
            edge.map_or((width, height), |edge| fitted_size(width, height, edge));
        Ok(ImagePin {
            provider,
            name: self.name.clone(),
            evidence: self.evidence.clone(),
            width,
            height,
            frame: self.frame,
            edge,
            sent_width,
            sent_height,
        })
    }
}

/// The size [`DecisionImage::fitted`] sends a `width` by `height` image at under
/// `max_edge`: unchanged when its long edge fits, else scaled to fit with its aspect
/// kept, each side rounded and at least one pixel.
pub fn fitted_size(width: u32, height: u32, max_edge: u32) -> (u32, u32) {
    let edge = max_edge.max(1);
    if width.max(height) <= edge {
        return (width, height);
    }
    let ratio = f64::from(edge) / f64::from(width.max(height));
    let side = |length: u32| ((f64::from(length) * ratio).round() as u32).clamp(1, edge);
    (side(width), side(height))
}

/// Audio clips one call may carry.
pub const MAX_DECISION_AUDIO: usize = 4;
/// Encoded bytes of one clip, as handed in.
pub const MAX_DECISION_AUDIO_BYTES: usize = 10 * 1024 * 1024;
/// Encoded bytes of every clip in one call.
pub const MAX_DECISION_AUDIOS_BYTES: usize = 20 * 1024 * 1024;

/// One audio clip a question reads, as in "is `audio_0` someone speaking?". Like an
/// image, the clip fills the state field of its name. The seat hears the encoded clip
/// itself, never a transcript put in its place.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionAudio {
    /// The state field it fills and the name the question text uses for it.
    pub name: String,
    /// The unit and body version it was read from.
    pub evidence: EvidenceVersion,
    /// `audio/wav` or `audio/mpeg`.
    pub media_type: String,
    /// The encoded clip.
    pub bytes: Vec<u8>,
}

impl DecisionAudio {
    /// A call's clips: at most four, uniquely named, WAV or MP3, inside the byte bounds.
    /// A name is a plain state key, as an image's is.
    pub fn validate_all(audio: &[Self]) -> LlmResult<()> {
        let mut names = BTreeSet::new();
        let mut total = 0usize;
        for clip in audio {
            total = total.saturating_add(clip.bytes.len());
            if clip.name.is_empty()
                || clip.name.len() > 64
                || !clip
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || !names.insert(clip.name.as_str())
                || clip.bytes.is_empty()
                || clip.bytes.len() > MAX_DECISION_AUDIO_BYTES
                || clip.format().is_none()
            {
                return Err(FatalLlmError::InvalidRequest.into());
            }
        }
        if audio.len() > MAX_DECISION_AUDIO || total > MAX_DECISION_AUDIOS_BYTES {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(())
    }

    /// A call's clips against its state and its images: valid, none filling a field the
    /// state already has, and none sharing a name with an image.
    pub fn check_call(audio: &[Self], images: &[DecisionImage], state: &Value) -> LlmResult<()> {
        Self::validate_all(audio)?;
        if audio.iter().any(|clip| {
            state.get(&clip.name).is_some() || images.iter().any(|image| image.name == clip.name)
        }) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(())
    }

    /// `"wav"` or `"mp3"`, the chat wire's name for the declared media type. Only these
    /// two: an audio-reading chat seat documents no other input format.
    pub fn format(&self) -> Option<&'static str> {
        audio_format(&self.media_type)
    }

    /// Standard padded base64 of the clip, with no `data:` prefix.
    pub fn base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.bytes)
    }
}

/// `"wav"` or `"mp3"` for an audio media type a decision clip may carry.
pub fn audio_format(media_type: &str) -> Option<&'static str> {
    match media_type.to_ascii_lowercase().as_str() {
        "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/vnd.wave" => Some("wav"),
        "audio/mpeg" | "audio/mp3" => Some("mp3"),
        _ => None,
    }
}
