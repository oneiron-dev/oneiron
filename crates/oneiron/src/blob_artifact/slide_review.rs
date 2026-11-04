//! Slide review rendering, memory accounting and unit-refusal vocabulary.

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// The name a unit's image goes by in its `state.media` and its call.
pub const REVIEW_IMAGE: &str = "review_image";

/// A review image's BLAKE3 hash in hex: the `hash` its [`ImageRef`] names in
/// `state.media`, and its judgment's `render_hash`, as text.
pub fn review_image_key(image: &[u8]) -> String {
    blake3::hash(image).to_hex().to_string()
}

/// The most the review's own copies of a render's `images` hold at once,
/// admitted to its renderer first (FIX 8244): the largest, since a review
/// copies one unit's image at a time and drops it before the next.
pub(crate) fn review_copy_bytes(images: &[Vec<u8>]) -> u64 {
    let bytes = images.iter().map(Vec::len).max().unwrap_or(0);
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// The host's review renderer (ARCH-0077 "Review images"), which a proposer
/// wake asks for the changed slides of a held review: the engine renders
/// nothing itself.
pub trait SlideRenderer: Send + Sync {
    /// The renderer's identity, saved on each judgment as provisional evidence.
    fn name(&self) -> &str;
    /// One PNG or JPEG per entry of `slides` (1-based numbers in `deck`), in
    /// that order, each rendered from these exact bytes.
    fn render(&self, deck: &[u8], slides: &[u64]) -> Result<Vec<Vec<u8>>>;
    /// Reserve memory for `bytes` the caller is about to allocate; the
    /// reservation lives as long as the renderer (FIX 7653). A host's
    /// renderer refuses one the machine cannot hold, typed; a renderer that
    /// keeps no account of memory admits every one.
    fn admit(&self, bytes: u64) -> Result<()> {
        let _ = bytes;
        Ok(())
    }
    /// Name `reserved` of the bytes admitted allocated, as the `actual` bytes
    /// the caller now holds (FIX 8240): an exact reservation made, what an
    /// estimate came to, room left unused (`actual` 0), or bytes read before
    /// their size was known (`reserved` 0). Only bookkeeping: it never waits
    /// or refuses. A renderer that keeps no account of memory ignores it.
    fn materialized(&self, reserved: u64, actual: u64) {
        let _ = (reserved, actual);
    }
}

/// On the wire as its variant name (`MissingShape`, ...), the words a
/// review's refusals have always carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum SlideUnitRefusalReason {
    /// No shape on the slide carries the creation id.
    MissingShape,
    /// Several shapes carry it.
    AmbiguousShape,
    /// The shape no longer matches the caller's fingerprint.
    TargetChanged,
    /// The writer cannot verify the shape's slide-space position.
    UnresolvedGeometry,
    /// The unit's text or state exceeds the evidence budget; nothing is trimmed to fit.
    EvidenceBudget,
    /// The rendered image is not PNG or JPEG whose header gives its size.
    UnreadableImage,
    /// The run's deadline came before the unit's batch started: nothing was
    /// asked about it (FIX 9819).
    RunDeadline,
}
