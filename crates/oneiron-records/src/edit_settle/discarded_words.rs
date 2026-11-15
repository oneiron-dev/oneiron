//! Moved from `crates/oneiron/src/edit_settle/discarded_words.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RwTxn;
use oneiron_docedit::edit::DeckTransactionReport;
use oneiron_docedit::edit::Effect;
use oneiron_store::blob_artifact::deck_context::DeckEditContext;
use serde::Deserialize;
use serde::Serialize;

/// A settled native deck transaction without its words: the handoff it bound, who made it and
/// what it answered, its review renders, and its report (digests, part diff, id marks, and each
/// step's verb, parts, fit and the effects that carry only ids: minted shape and slide ids,
/// copied and removed ids, parts and relationships). An effect that carries a document's own
/// words (a custom show's name, a cut field's type, a chart series' names) goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscardedDeck {
    pub handoff: [u8; 32],
    pub context: DeckEditContext,
    /// `None` when the stored report did not read.
    pub report: Option<DeckTransactionReport>,
}

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

impl DiscardedDeck {
    fn of(deck: crate::edit_roundtrip::deck::DeckSettleEvidence) -> Self {
        let mut report = serde_json::from_str::<DeckTransactionReport>(&deck.report).ok();
        for step in report.iter_mut().flat_map(|report| &mut report.steps) {
            step.effects.retain(carries_only_ids);
        }
        Self {
            handoff: deck.handoff,
            context: deck.context,
            report,
        }
    }
}
