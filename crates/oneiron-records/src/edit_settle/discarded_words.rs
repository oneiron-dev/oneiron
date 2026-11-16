//! Moved from `crates/oneiron/src/edit_settle/discarded_words.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_docedit::edit::Effect;

/// Whether `effect` names only ids, parts and relationships, no word of the document. A variant
/// not listed here is dropped, so a new one never keeps words by default.
pub fn carries_only_ids(effect: &Effect) -> bool {
    matches!(
        effect,
        Effect::GluedConnector { .. }
            | Effect::PreviousMedia { .. }
            | Effect::NotesCreated { .. }
            | Effect::ShapeAdded { .. }
            | Effect::Unglued { .. }
            | Effect::TimingRemoved { .. }
            | Effect::Unreferenced { .. }
            | Effect::MediaReleased { .. }
            | Effect::MediaKept { .. }
            | Effect::SlideAdded { .. }
            | Effect::PartCloned { .. }
            | Effect::CommentsOmitted { .. }
            | Effect::SlideRemoved { .. }
            | Effect::ShapeCopied { .. }
            | Effect::CustomGeometryReplaced
            | Effect::InheritedGeometryOwned
            | Effect::FontSizeClamped { .. }
    )
}
