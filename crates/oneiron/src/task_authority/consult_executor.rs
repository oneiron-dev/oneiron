//! The executor standing of a consult, read from its immutable ConsultAssignee
//! fact (FIX 10182), never from its mutable body.

use super::{ConsultParties, ConsultStanding, TaskAuthorityFacts};
use crate::entity_id::EntityId;

impl TaskAuthorityFacts {
    /// Whether the consult carries any ConsultAssignee fact: a minted one or
    /// a fork. Every consult mint writes one, so a consult with none proves no
    /// executor.
    pub(crate) const fn has_consult_party_fact(&self) -> bool {
        !matches!(self.consult_parties, ConsultParties::Unminted)
    }

    /// `actor`'s standing to write the consult's execution facts: the party
    /// its one ConsultAssignee fact addressed or, for a consult addressed to
    /// no actor (the local Dreamer), its asker, the TASK's proven owner; each
    /// with the binding generation it held when the consult was minted. The
    /// asker of an addressed consult has none here, unlike its ladder
    /// standing. A forked fact, or one whose asker is not the proven owner,
    /// gives nobody standing.
    pub(crate) fn consult_execution_standing(&self, actor: EntityId) -> Option<ConsultStanding> {
        let ConsultParties::Minted(parties) = &self.consult_parties else {
            return None;
        };
        if self.owner_ref != Some(parties.asker) {
            return None;
        }
        let (executor, generation) = match parties.assignee {
            Some(assignee) => (assignee, &parties.assignee_generation),
            None => (parties.asker, &parties.asker_generation),
        };
        (executor == actor).then(|| ConsultStanding {
            generation: generation.clone(),
        })
    }
}
