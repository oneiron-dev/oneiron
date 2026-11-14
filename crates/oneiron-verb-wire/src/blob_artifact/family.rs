//! Moved from `crates/oneiron/src/blob_artifact/family.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use oneiron_store::blob_artifact::office_address::OfficeFormat;
use serde::Deserialize;
use serde::Serialize;

/// One kind of the artifact family. A kind is a body plus its fidelity rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// docx and friends.
    Document,
    /// xlsx and xlsm.
    Sheet,
    /// pptx.
    Deck,
    /// A code tree (CODE_ARTIFACT); git is its export.
    Code,
    /// A design canvas.
    Canvas,
    /// A static image (the image organ's kind).
    Image,
    /// Any other exported file, kept as versions with no kind-specific body.
    File,
}

impl ArtifactKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Sheet => "sheet",
            Self::Deck => "deck",
            Self::Code => "code",
            Self::Canvas => "canvas",
            Self::Image => "image",
            Self::File => "file",
        }
    }

    /// The kind a blob artifact's export media type names.
    #[must_use]
    pub fn of_media_type(media_type: &str) -> Self {
        match OfficeFormat::from_media_type(media_type) {
            Ok(OfficeFormat::Docx) => Self::Document,
            Ok(OfficeFormat::Xlsx) => Self::Sheet,
            Ok(OfficeFormat::Pptx) => Self::Deck,
            Err(_) => match media_type {
                "image/png" | "image/jpeg" | "image/webp" => Self::Image,
                _ => Self::File,
            },
        }
    }
}
