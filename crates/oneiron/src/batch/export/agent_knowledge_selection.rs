//! Which claims an agent pack's selected-knowledge facet may carry: the
//! ordinary claims directly about the agent. The agent definition layer
//! (`agent_def`) builds and checks facets with it; the archive export
//! selects an agent's knowledge with it.
use crate::batch::export::ExportEntity;
use crate::entity_id::EntityId;
use crate::write_envelope::claim_body::{ClaimSubject, decode_claim_body};

/// A selected-knowledge facet includes only ordinary claims directly ABOUT this
/// definition. Reserved actor/control claims are not portable authority.
pub(crate) fn select_agent_knowledge(id: &EntityId, claims: &[ExportEntity]) -> Vec<ExportEntity> {
    claims
        .iter()
        .filter(|row| {
            row.body
                .to_bytes()
                .ok()
                .and_then(|b| decode_claim_body(&b, false).ok())
                .is_some_and(|claim| claim.subject == ClaimSubject::Entity(*id))
        })
        .cloned()
        .collect()
}
