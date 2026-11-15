//! Moved from `crates/oneiron/src/edit_roundtrip/deck.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_docedit::edit::transaction::DeckTransactionReport;
pub use oneiron_store::blob_artifact::deck_context::DeckEditContext;
pub use oneiron_store::blob_artifact::deck_context::DeckRender;
pub use oneiron_store::blob_artifact::deck_context::DeckRenderSide;
pub use oneiron_store::blob_artifact::deck_inspection::DeckRejectionInspection;
use serde::Deserialize;
use serde::Serialize;

/// One line of the semantic diff for a deck transaction.
pub fn render_report(report: &str) -> String {
    match serde_json::from_str::<DeckTransactionReport>(report) {
        Ok(report) => {
            let verbs: Vec<_> = report.steps.iter().map(|step| step.verb.as_str()).collect();
            format!(
                "deck transaction {}: {} ({} part(s) changed)",
                report.handoff.to_hex(),
                verbs.join(", "),
                report.parts.len()
            )
        }
        Err(_) => "deck transaction (unreadable report)".to_owned(),
    }
}

/// The settled deck transaction, kept with the consume-once ledger row: the
/// handoff hash it settled, its canonical report (part diff, effects, marks,
/// fit) and its context (made_by, thread, review renders).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckSettleEvidence {
    pub handoff: [u8; 32],
    pub report: String,
    pub context: DeckEditContext,
}
