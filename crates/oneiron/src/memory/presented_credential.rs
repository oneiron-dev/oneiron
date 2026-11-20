//! The verified credential a host bound to a handle, for the engine doors
//! that take the caller's own credential rather than its actor alone (an
//! agent's contact-disclosure offer, `vault.disclosure.offer`).

use super::Memory;
use crate::authority::VerifiedSlip;

impl Memory<'_> {
    /// The credential this handle's caller presented, when a host bound one
    /// ([`Memory::with_read_proof`]): a served request's, or the one an
    /// embedded handle's delegated reader presented to its host (FIX 647).
    /// A handle bound to none, as an embedded owner's is, carries none.
    pub(crate) fn presented_credential(&self) -> Option<&VerifiedSlip> {
        self.read_proof.as_ref()
    }

    /// Whether the credential this handle presented passes the scope guard a
    /// served call of `verb` meets before its door runs (the server's
    /// `require_action_scope`): the core class of the verb's row, `read` or
    /// `write`, granted by that name or as `core:<class>`, and for a write no
    /// record or channel cut and an uncut record scope, as the owner door's
    /// delegate check composes it (`owner_door.rs`). A handle bound to no
    /// credential, as an embedded owner's is, passes; an unknown verb does
    /// not. An inbox tap is offered only to a caller this passes
    /// (REVIEW-10022 P1).
    pub(crate) fn presented_credential_reaches_verb(&self, verb: &str) -> bool {
        let Some(row) = crate::verbs::AgentVerb::from_name(verb) else {
            return false;
        };
        let Some(credential) = self.presented_credential() else {
            return true;
        };
        let class = if row.writes() { "write" } else { "read" };
        if !(credential.allows_verb(class) || credential.allows_verb(&format!("core:{class}"))) {
            return false;
        }
        if !row.writes() {
            return true;
        }
        let claims = credential.claims();
        let mut uncut = crate::federation::Scope::top();
        uncut.verbs = credential.scope().verbs.clone();
        claims.records.is_empty()
            && claims.channels.is_empty()
            && uncut.is_narrowing_of(credential.scope())
    }

    /// Whether this handle acts as a person in its own right: its class is
    /// Human, and it carries no presented credential whose mint was handed
    /// to another key ([`VerifiedSlip::is_transferred`]). A person's slip
    /// handed on to an agent's key is that agent's act, whatever class the
    /// mint names (Astra review on #8189, F1). The doors that let only a
    /// person close a restriction ask this (canon #widen-world-floor).
    pub(crate) fn acts_as_own_person(&self) -> bool {
        self.actor_class == crate::EdgeActorClass::Human
            && !self
                .presented_credential()
                .is_some_and(VerifiedSlip::is_transferred)
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
