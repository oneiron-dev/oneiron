//! `vault.artifacts.body.deck.preview`: the asked slides of a deck's head,
//! drawn by the host's review renderer (ARCH-0077 "Review images") from the
//! export the head projects now ([`crate::Vault::export_pptx_body`]).
//! Nothing lands and nothing is proposed, whatever the export gate says. The
//! images are provisional: a review renderer's drawing is neither the
//! PowerPoint oracle's evidence nor a reason to open the gate. An embedded
//! vault has no renderer, so it refuses.
use std::collections::BTreeSet;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::edit_roundtrip::slides_review::{SlideRenderer, review_image_key};
use crate::gate::record_references::admit_row_references;
use crate::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult,
};
use oneiron_docedit::deck::DeckView;
use oneiron_docedit::retained_opc::Package;

const ROW: &str = "vault.artifacts.body.deck.preview";

/// The most slides one preview draws (CALLS "OF-510 deck preview").
const MAX_SLIDES: usize = 20;

/// `vault.artifacts.body.deck.preview`: the slides to draw, each named once,
/// 1-based in the deck's order (hidden slides count).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckPreviewRequest {
    pub artifact_ref: String,
    pub slides: Vec<u64>,
}

/// The slides a deck preview drew, and the projection they show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckPreview {
    /// The head the export projected.
    pub frontier: Vec<u8>,
    pub profile: String,
    pub projector: String,
    /// BLAKE3 of the export's memo key, in hex.
    pub export_key: String,
    /// The renderer's identity: its version and raster settings.
    pub renderer: String,
    /// Always true: fonts, autofit and image effects differ from
    /// PowerPoint's.
    pub provisional: bool,
    pub slides: Vec<DeckPreviewSlide>,
}

/// One drawn slide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckPreviewSlide {
    pub slide: u64,
    /// `image/png`, or `image/jpeg`.
    pub media_type: String,
    /// The image's BLAKE3 in hex, as a review image is keyed.
    pub image_hash: String,
    pub content_base64: String,
}

impl Memory<'_> {
    /// `vault.artifacts.body.deck.preview`: draw the asked slides of the
    /// deck's head with the host's review renderer, `None` where there is
    /// none.
    pub fn artifacts_body_deck_preview(
        &self,
        input: &DeckPreviewRequest,
        renderer: Option<&dyn SlideRenderer>,
    ) -> MemoryResult<DeckPreview> {
        let Some(renderer) = renderer else {
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                format!("{ROW} draws with a host's review renderer, and this vault has none"),
                &["Call it through a server with LibreOffice (soffice) and pdftoppm on its PATH."],
            ));
        };
        if input.slides.is_empty() || input.slides.len() > MAX_SLIDES {
            return Err(MemoryError::bad_request(format!(
                "a deck preview names 1 to {MAX_SLIDES} slides"
            )));
        }
        admit_row_references(self, ROW, input, &["/artifact_ref"])?;
        let artifact = self.body_ref(&input.artifact_ref)?;
        // A drawn slide cannot show a lifted key as its handle: a deck that
        // holds one draws for the owner alone (OF-067).
        if self.reads_lifted_keys_masked()?
            && !self.vault().typed_body_lifted_keys(&artifact)?.is_empty()
        {
            return Err(MemoryError::bad_request(format!(
                "{ROW} draws a deck whose text holds a lifted secret for the vault owner only"
            )));
        }
        let export = self.vault().export_pptx_body(&artifact)?;
        let count = Package::open(
            &export.outcome.bytes,
            self.vault().docedit_package_limits()?,
        )
        .ok()
        .and_then(|package| DeckView::read(&package).ok())
        .map(|view| u64::try_from(view.slides.len()).unwrap_or(u64::MAX))
        .ok_or_else(|| failed("the deck's export could not be read back"))?;
        let mut named = BTreeSet::new();
        for &slide in &input.slides {
            if slide == 0 || slide > count || !named.insert(slide) {
                return Err(MemoryError::bad_request(format!(
                    "slide {slide} is not one of the deck's {count} slides, or is named twice"
                )));
            }
        }
        let images = renderer.render(&export.outcome.bytes, &input.slides)?;
        if images.len() != input.slides.len() {
            return Err(failed("the renderer drew another number of slides"));
        }
        Ok(DeckPreview {
            frontier: export.frontier,
            export_key: blake3::Hash::from(export.outcome.key.hash())
                .to_hex()
                .to_string(),
            profile: export.outcome.key.profile,
            projector: export.outcome.key.projector,
            renderer: renderer.name().to_owned(),
            provisional: true,
            slides: input
                .slides
                .iter()
                .zip(images)
                .map(|(&slide, image)| DeckPreviewSlide {
                    slide,
                    media_type: if image.starts_with(&[0xFF, 0xD8, 0xFF]) {
                        "image/jpeg"
                    } else {
                        "image/png"
                    }
                    .to_owned(),
                    image_hash: review_image_key(&image),
                    content_base64: base64::engine::general_purpose::STANDARD.encode(&image),
                })
                .collect(),
        })
    }
}

fn failed(reason: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{ROW}: {reason}"),
        &["Report this deck preview failure."],
    )
}
