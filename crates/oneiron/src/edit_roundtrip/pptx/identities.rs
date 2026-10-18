//! The engine door onto the docedit organ's slide and shape identities, and
//! the annotation locator re-binding over them.

use super::limits::PptxOperationalLimits;
use super::package::*;
use crate::anchored_annotation::{Locator, ReanchorOutcome};
use oneiron_docedit::pptx_comments::{self, rebind_shape};

/// Reads identities without creating missing ones or changing any package byte.
pub fn inspect_pptx(bytes: &[u8]) -> Result<PptxInspection, PptxError> {
    inspect_pptx_with_limits(bytes, &PptxOperationalLimits::default())
}
pub(crate) fn inspect_pptx_with_limits(
    bytes: &[u8],
    limits: &PptxOperationalLimits,
) -> Result<PptxInspection, PptxError> {
    pptx_comments::inspect_pptx(bytes, &limits.codec())
}

/// Rebinds by imported creation identities, never by a nearby shape or its name.
/// `shape_id = "slide"` denotes a whole-slide locator. Numeric legacy shape IDs
/// are resolved in the old version first; only their creation GUID may follow.
/// Missing, duplicate, or changed shape evidence drifts instead of guessing.
pub fn rebind_locator(
    locator: &Locator,
    before: &PptxInspection,
    after: &PptxInspection,
) -> ReanchorOutcome {
    let Locator::Pptx { slide, shape_id } = locator else {
        return ReanchorOutcome::Drifted;
    };
    match rebind_shape(*slide, shape_id, before, after) {
        Some((slide, shape_id)) => ReanchorOutcome::Mapped(Locator::Pptx { slide, shape_id }),
        None => ReanchorOutcome::Drifted,
    }
}
