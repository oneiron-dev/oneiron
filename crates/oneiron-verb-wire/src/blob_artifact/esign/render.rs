//! Moved from `crates/oneiron/src/blob_artifact/esign/render.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::model::*;
pub use crate::blob_artifact::esign::render::presentation::FieldControl;
pub use crate::blob_artifact::esign::render::presentation::FieldLayout;
pub use crate::blob_artifact::esign::render::presentation::FieldMark;
pub use crate::blob_artifact::esign::render::presentation::FieldPresentation;
pub use crate::blob_artifact::esign::render::presentation::PageGeometry;
pub use lopdf::DecodeAdmissionError;
use oneiron_contracts::limit_ask::EngineLimit;
use oneiron_esign_render as leaf;
pub use oneiron_store::blob_artifact::esign::render::admitted::InspectionMemory;

pub type Result<T> = std::result::Result<T, PdfPreparationError>;

/// Refusals are preparation failures, never a successful unsigned seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PdfPreparationError {
    /// Past a codec or format bound: a stream's decode bound, the format's
    /// object count or the writer's offset width.
    #[error("PDF past a codec or format bound")]
    Limit,
    /// One stream decodes past a host codec bound: the named `[limits]` row.
    #[error("a PDF stream decodes past the [limits] {} codec bound", .0.key())]
    StreamPastCodecBound(EngineLimit),
    #[error("malformed PDF")]
    MalformedPdf,
    #[error("encrypted PDF cannot be rewritten")]
    EncryptedPdf,
    #[error("signed PDF cannot be rewritten")]
    AlreadySigned,
    #[error("PDF construct cannot be safely flattened")]
    UnsupportedPdf,
    #[error("invalid field geometry")]
    InvalidGeometry,
    #[error("invalid document evidence")]
    InvalidEvidence,
    #[error("invalid field value")]
    InvalidField,
    #[error("signature raster is missing or invalid")]
    InvalidSignatureImage,
    #[error("field text requires an unsupported font")]
    UnsupportedText,
    #[error("field text does not fit")]
    FieldOverflow,
    #[error("invalid canonical HTTPS capability URL")]
    InvalidCanonicalUrl,
    #[error("PDF encoding failed")]
    Encoding,
    /// The machine's memory floor refused the revision read: `needed` more
    /// bytes past `available` at most (6274). Retryable, never malformed.
    #[error("the machine's memory floor: {needed} bytes needed, {available} available")]
    MemoryFloor { needed: u64, available: u64 },
    /// The host's wait for memory ran out on the revision read (6274).
    /// A caller may ask again. Never malformed.
    #[error("the work's resource wait or deadline passed")]
    Deadline,
    /// The producer must unwind before admitting a larger complete pool.
    /// Only the observed allocation prefix is measured; rounded and
    /// structural reservations are estimates.
    #[error("the seal input needs a {needed}-byte reservation")]
    InputReservation { needed: u64, measured: u64 },
}

impl From<lopdf::Error> for PdfPreparationError {
    fn from(error: lopdf::Error) -> Self {
        match error {
            lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { .. }) => {
                Self::Limit
            }
            lopdf::Error::AlreadyEncrypted
            | lopdf::Error::Decryption(_)
            | lopdf::Error::InvalidPassword
            | lopdf::Error::UnsupportedSecurityHandler(_) => Self::EncryptedPdf,
            _ => Self::MalformedPdf,
        }
    }
}

/// PDF user-space rectangle, with a bottom-left origin.
#[derive(
    Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PdfFieldRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// A shared-renderer failure as the wire reads it: the display-size refusal
/// as the codec-or-format limit, a lopdf failure through the existing
/// conversion, and each logic failure 1:1. The wire admits nothing and runs
/// no copier, so neither opaque arm is reachable.
fn map_leaf(err: leaf::BurnError<std::convert::Infallible>) -> PdfPreparationError {
    match err {
        leaf::BurnError::Admit(refusal) => match refusal {},
        leaf::BurnError::External(external) => match external {},
        leaf::BurnError::Lopdf(err) => PdfPreparationError::from(err),
        leaf::BurnError::DisplayTooLarge => PdfPreparationError::Limit,
        leaf::BurnError::TooLarge => PdfPreparationError::InvalidSignatureImage,
        leaf::BurnError::MalformedPdf => PdfPreparationError::MalformedPdf,
        leaf::BurnError::UnsupportedPdf => PdfPreparationError::UnsupportedPdf,
        leaf::BurnError::InvalidGeometry => PdfPreparationError::InvalidGeometry,
        leaf::BurnError::InvalidSignatureImage => PdfPreparationError::InvalidSignatureImage,
        leaf::BurnError::UnsupportedText => PdfPreparationError::UnsupportedText,
        leaf::BurnError::FieldOverflow => PdfPreparationError::FieldOverflow,
    }
}

/// Shared geometry for editor, ceremony and export. Page numbers are one-based.
/// Use `PageGeometry` to convert rotated/scaled page displays before placement.
pub fn render_field_geometry(g: &FieldGeometry, crop: [f64; 4]) -> Result<PdfFieldRect> {
    let geometry = leaf::FieldGeometry {
        page: g.page,
        x_percent: g.x_percent,
        y_percent: g.y_percent,
        width_percent: g.width_percent,
        height_percent: g.height_percent,
    };
    leaf::render_field_geometry(&geometry, crop)
        .map(|rect| PdfFieldRect {
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
        })
        .map_err(map_leaf)
}
pub mod presentation;
