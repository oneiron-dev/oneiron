//! Images a typed decision reads. The receipt keeps each image's evidence ref and body
//! version; the pixels ride only on the wire to the seat.

use super::EvidenceVersion;
use crate::llm::image::ImageBytes;
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
    /// has, and at least one when the call asks a Box question.
    pub fn check_call(images: &[Self], state: &Value, asks_box: bool) -> LlmResult<()> {
        Self::validate_all(images)?;
        if (asks_box && images.is_empty())
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

    /// The image with its long edge at most `max_edge` pixels, in its own format. A box
    /// is in fractions of the image, so it reads the same on the smaller copy; small
    /// text may still need a crop before the call.
    pub fn fitted(&self, max_edge: u32) -> LlmResult<ImageBytes> {
        let format = match self.format() {
            Some("png") => image::ImageFormat::Png,
            Some(_) => image::ImageFormat::Jpeg,
            None => return Err(FatalLlmError::InvalidRequest.into()),
        };
        let decoded = image::load_from_memory_with_format(&self.image.bytes, format)
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        if decoded.width().max(decoded.height()) <= max_edge.max(1) {
            return Ok(self.image.clone());
        }
        let smaller = decoded.resize(
            max_edge.max(1),
            max_edge.max(1),
            image::imageops::FilterType::Triangle,
        );
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
}
