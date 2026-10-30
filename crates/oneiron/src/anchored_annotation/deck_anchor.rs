//! The deck arm of the body-frontier anchor (FIX 12264; ARCH-0075 section
//! 4, the body).
//!
//! A deck comment's version anchor names the file's ids: the slide's
//! 1-based position, and the shape's creation id or native id (`slide` for
//! the whole slide). Its body anchor names the commented node by its model
//! identity, which no edit changes: a pptx locator whose `slide` is the
//! node's slide position at the anchor's frontier and whose `shape_id` is
//! the node id, the slide's own for a whole-slide comment. A follow is a
//! frontier move; a deleted node drifts. The deck's bindings tie the two:
//! a node's binding names its ids in the version the deck is bound to.

use super::model::{Locator, ReanchorOutcome};
use crate::office_body::{DeckUnits, OfficeBodyUnits};
use oneiron_docedit::pptx_comments::guid_bytes;

/// The shape id of a whole-slide locator.
const WHOLE_SLIDE: &str = "slide";

/// A deck node's ids in one version's file: its slide's position, and the
/// shape's native id and creation id; `shape` is `None` for the slide.
struct Filed<'a> {
    position: u64,
    shape: Option<(Option<u32>, Option<&'a str>)>,
}

/// The body locator of a deck thread's version locator: the one node at
/// `at`, the frontier `version` projects, on the locator's slide whose ids
/// in `version` the locator names. `None` when no node or more than one
/// does.
pub(super) fn deck_body_locator(
    at: &DeckUnits,
    head: Option<&OfficeBodyUnits>,
    version: u64,
    locator: &Locator,
) -> Option<Locator> {
    let Locator::Pptx { slide, shape_id } = locator else {
        return None;
    };
    let ids = bound_to(at, head, version);
    let mut named = at.nodes.iter().filter(|unit| {
        unit.position == *slide
            && filed_ids(at, ids, unit.node).is_some_and(|found| names(&found, shape_id))
    });
    let unit = named.next()?;
    if named.next().is_some() {
        return None;
    }
    Some(Locator::Pptx {
        slide: unit.position,
        shape_id: unit.node.to_string(),
    })
}

/// Where a deck body locator's node stands at `to`: its slide's position
/// there, under the same node id; drifted when the node is gone. `None`
/// when the locator names no node.
pub(super) fn move_deck_locator(to: &DeckUnits, locator: &Locator) -> Option<ReanchorOutcome> {
    let Locator::Pptx { shape_id, .. } = locator else {
        return None;
    };
    let node: u64 = shape_id.parse().ok()?;
    Some(match to.nodes.iter().find(|unit| unit.node == node) {
        Some(unit) => ReanchorOutcome::Mapped(Locator::Pptx {
            slide: unit.position,
            shape_id: shape_id.clone(),
        }),
        None => ReanchorOutcome::Drifted,
    })
}

/// The version locator of a deck body locator at `at`, the frontier the
/// export `version` projects: the node's slide position and the shape's
/// creation id, else its native id. `None` when its ids there are not
/// known, or when they name another node of that slide as well.
pub(super) fn deck_file_locator(
    at: &DeckUnits,
    head: Option<&OfficeBodyUnits>,
    version: u64,
    locator: &Locator,
) -> Option<Locator> {
    let Locator::Pptx { shape_id, .. } = locator else {
        return None;
    };
    let filed = filed_ids(at, bound_to(at, head, version), shape_id.parse().ok()?)?;
    let shape_id = match filed.shape {
        None => WHOLE_SLIDE.to_owned(),
        Some((native, creation)) => creation
            .map(str::to_owned)
            .or_else(|| native.map(|id| id.to_string()))?,
    };
    let landed = Locator::Pptx {
        slide: filed.position,
        shape_id,
    };
    // The file's ids land the comment only where they name this node alone.
    (deck_body_locator(at, head, version, &landed).as_ref() == Some(locator)).then_some(landed)
}

/// The deck read whose bindings name `version`'s ids: `at` itself, or the
/// head when it is bound to `version`.
fn bound_to<'a>(
    at: &'a DeckUnits,
    head: Option<&'a OfficeBodyUnits>,
    version: u64,
) -> Option<&'a DeckUnits> {
    let head = match head {
        Some(OfficeBodyUnits::Pptx(head)) => Some(head),
        _ => None,
    };
    [Some(at), head]
        .into_iter()
        .flatten()
        .find(|units| units.bound == version)
}

/// Where `node` of `at` stands in the version `at`'s frontier projects: its
/// slide's position at `at`, and its ids from `ids`, the deck bound to that
/// version. A node `ids` does not hold is named by `at`'s own binding,
/// which names an earlier version's ids; an export keeps those while the
/// node stays on the slide its binding names, so only such a node is named.
fn filed_ids<'a>(
    at: &'a DeckUnits,
    ids: Option<&'a DeckUnits>,
    node: u64,
) -> Option<Filed<'a>> {
    let unit = at.nodes.iter().find(|unit| unit.node == node)?;
    if unit.node == unit.slide {
        return Some(Filed {
            position: unit.position,
            shape: None,
        });
    }
    let (_, native, creation) = match ids.and_then(|ids| binding_of(ids, node)) {
        Some(binding) => binding,
        None => {
            let binding = binding_of(at, node)?;
            let (slide_part, _, _) = binding_of(at, unit.slide)?;
            if &binding.0 != slide_part {
                return None;
            }
            binding
        }
    };
    Some(Filed {
        position: unit.position,
        shape: Some((*native, creation.as_deref())),
    })
}

fn binding_of(units: &DeckUnits, node: u64) -> Option<&(String, Option<u32>, Option<String>)> {
    units
        .nodes
        .iter()
        .find(|unit| unit.node == node)?
        .binding
        .as_ref()
}

/// Whether a version locator's `shape_id` names these ids: `slide` the
/// slide, a number the shape's native id, a GUID its creation id.
fn names(filed: &Filed<'_>, shape_id: &str) -> bool {
    match filed.shape {
        None => shape_id == WHOLE_SLIDE,
        Some((native, creation)) => {
            shape_id
                .parse::<u32>()
                .is_ok_and(|number| native == Some(number))
                || guid_bytes(shape_id)
                    .is_some_and(|wanted| creation.and_then(guid_bytes) == Some(wanted))
        }
    }
}
