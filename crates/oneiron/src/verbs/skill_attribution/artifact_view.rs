//! The public artifact view, its texts read through the retained document.

use super::{ProposalArtifactView, ProposalOpSpanView};
use crate::edit_distance::RetainedProposal;

impl From<RetainedProposal> for ProposalArtifactView {
    fn from(retained: RetainedProposal) -> Self {
        let spans = retained
            .record
            .ops_by_actor
            .iter()
            .map(|(attribution, span)| {
                let (before, after) = retained.change_texts(span);
                ProposalOpSpanView {
                    actor: attribution.actor().map(|actor| actor.entity_ref()),
                    trust: attribution.as_str().to_owned(),
                    before_text: before.into_text(),
                    after_text: after.into_text(),
                    lamport: span.lamport,
                    timestamp: span.timestamp,
                }
            })
            .collect();
        Self {
            artifact_ref: retained.record.artifact_ref.entity_id(),
            proposed_text: retained.proposed_text().into_text(),
            final_text: retained.final_text().into_text(),
            source_turn_ref: retained.record.source_turn_ref,
            spans,
        }
    }
}
