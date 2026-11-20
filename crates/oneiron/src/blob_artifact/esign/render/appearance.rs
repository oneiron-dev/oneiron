//! Flatten explicit static annotation appearances; never invent missing glyphs.
use super::fields::map_leaf;
use super::*;
use oneiron_esign_render::{self as leaf, NoAdmission};

/// Flattens a page's `/Annots`, every annotation of it, however many. An
/// indirect `/Annots` array that several pages name is flattened again for
/// each of them, into that page's own resources and operations, as a reader
/// draws it on each: the shared source array is only read, never changed.
pub(super) fn flatten(
    source: &Document,
    annotations: Option<&&Object>,
    copier: &mut VisualCopy<'_>,
    out: &mut Document,
    resources: &mut Dictionary,
) -> Result<Vec<Operation>> {
    let mut copy =
        |out: &mut Document, value: &Object, depth: usize| copier.copy(out, value, depth);
    leaf::flatten(source, annotations, &mut copy, out, resources, &NoAdmission).map_err(map_leaf)
}
