//! Live questions joined to an already-authorized native status snapshot.

use oneiron::EntityId;
use oneiron::outbound_consent::{ConnectorCallState, ConnectorQuestion};

use super::ConnectorElicitationRegistry;

impl ConnectorElicitationRegistry {
    /// Borrows the same unanswered round without claiming its answer.
    /// The native reader has already checked caller-or-owner access. The
    /// original grant and key remain the live entry's immutable binding;
    /// this read never re-resolves either or authorizes another send.
    pub(crate) fn questions_for_status(
        &self,
        call_ref: EntityId,
        state: &ConnectorCallState,
    ) -> Vec<ConnectorQuestion> {
        let Some(round) = state.input.as_ref() else {
            return Vec::new();
        };
        let live = self.lock();
        let Some(entry) = live.get(&round.handle) else {
            return Vec::new();
        };
        if entry.call_ref != Some(call_ref)
            || entry.generation != round.generation
            || entry.questions.len() != round.asked
            || entry.binding.principal.to_hex() != state.principal_ref
            || state.grant_id.as_deref() != Some(entry.binding.grant_id.to_hex().as_str())
            || entry.binding.name != state.name
            || entry.binding.tool != state.tool
        {
            return Vec::new();
        }
        entry.questions.clone()
    }
}
