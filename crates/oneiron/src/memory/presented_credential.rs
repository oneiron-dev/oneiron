//! The verified credential a host bound to a handle, for the engine doors
//! that take the caller's own credential rather than its actor alone (an
//! agent's contact-disclosure offer, `vault.disclosure.offer`).

use super::Memory;
use crate::authority::VerifiedSlip;

impl Memory<'_> {
    /// The credential this handle's caller presented, when a host bound one
    /// ([`Memory::with_read_proof`]); none on an embedded handle.
    pub(crate) fn presented_credential(&self) -> Option<&VerifiedSlip> {
        self.read_proof.as_ref()
    }

    /// The ask guest's grant a host bound to this handle
    /// ([`Memory::with_task_grant`]), as task verbs prove its actor by it.
    #[must_use]
    pub fn presented_task_grant(&self) -> Option<crate::EntityId> {
        self.task_grant.map(|grant| grant.grant())
    }

    /// The ask guest's grant a host bound to this handle, whole: what an
    /// agent dispatch its request queues keeps as its requester's standing
    /// (FIX 11688).
    pub(crate) const fn admitted_task_grant(&self) -> Option<crate::authority::AdmittedTaskGrant> {
        self.task_grant
    }

    /// Binds the requester a held request was admitted under, for the host's
    /// release of it on a surface of its own (FIX 11691): an agent dispatch
    /// the release queues keeps it, as the request's own surface would have
    /// kept it, and its claim judges it again. It proves nothing and grants
    /// nothing; `None` binds none.
    #[must_use]
    pub(crate) fn with_kept_requester(
        mut self,
        requester: Option<crate::agent_dispatch::QueuedRequester>,
    ) -> Self {
        self.kept_requester = requester;
        self
    }

    /// The requester [`Self::with_kept_requester`] bound, if any.
    pub(crate) const fn kept_requester(&self) -> Option<&crate::agent_dispatch::QueuedRequester> {
        self.kept_requester.as_ref()
    }
}
