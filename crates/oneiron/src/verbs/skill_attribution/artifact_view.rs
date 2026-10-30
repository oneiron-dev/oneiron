//! The public artifact view, its texts read through the retained document.

use super::{ProposalArtifactView, ProposalOpSpanView};
use crate::Vault;
use crate::claim::CallerLocality;
use crate::consent::AuthenticatedOwner;
use crate::edit_distance::RetainedProposal;
use crate::edit_distance::reservoir::owner_readable_proposal_in;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::MemoryResult;

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

/// FIX 11351, 11355: the artifact under `artifact` as `owner`'s own governed
/// read at `locality` may show it, read and judged in one snapshot by the
/// corpus predicates. `None` when nothing is retained there, or when its
/// artifact row or input source is withheld, so none of its proposed, final
/// or span texts leave.
pub(super) fn readable_artifact(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    locality: CallerLocality,
    artifact: EntityId,
) -> MemoryResult<Option<ProposalArtifactView>> {
    let key = vault.owner_proof_read_key(owner)?;
    let reader = vault.scoped_read(key.at(locality));
    reader.persist_grant_clock()?;
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(owner_readable_proposal_in(vault, &rtxn, &reader, artifact)?.map(Into::into))
}
