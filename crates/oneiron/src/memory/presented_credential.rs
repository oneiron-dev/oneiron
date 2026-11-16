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

    /// Whether this handle's caller presented a credential whose mint was
    /// handed on to another key ([`VerifiedSlip::is_transferred`]), the
    /// person's own other device key included (HANDED-ON-SLIP-PERSON Q2 = A).
    pub(crate) fn presents_handed_on_credential(&self) -> bool {
        self.presented_credential()
            .is_some_and(VerifiedSlip::is_transferred)
    }

    /// Whether this handle carries a handed-on credential: its field or its proof.
    pub(crate) fn carries_handed_on_credential(&self) -> bool {
        // A handed-on credential acts as its key's holder, not the person (HANDED-ON-SLIP-PERSON).
        self.handed_on_credential || self.presents_handed_on_credential()
    }

    /// Whether this handle acts as a person in its own right: its class is
    /// Human, and it carries no handed-on credential ([`Self::carries_handed_on_credential`]).
    /// A person's slip handed on to an agent's key is that agent's act, whatever class
    /// the mint names (Astra review on #8189, F1; canon
    /// `#credential-read-key-built`: a narrower credential "never takes the
    /// owner's floor"). Every person gate asks this, never the class alone:
    /// the doors that let only a person close a restriction (canon
    /// #widen-world-floor), the owner's demote, correction, retract and
    /// delete of another's row, `can`'s person proof, and the person's own
    /// provenance stamps, which a handed-on credential's writes never carry
    /// (HANDED-ON-SLIP-PERSON Q1 = A: Generated or Observed, never
    /// UserStated). [`Self::write_actor`] carries the same mark to the
    /// checks that judge a write actor.
    pub(crate) fn acts_as_own_person(&self) -> bool {
        // A handed-on credential acts as its key's holder, not the person (HANDED-ON-SLIP-PERSON).
        self.actor_class == crate::EdgeActorClass::Human && !self.carries_handed_on_credential()
    }

    /// The owner's deletion authority for this handle's own act
    /// ([`super::verify_deletion_authority_in_txn`]), refused to a
    /// handed-on credential ([`Self::acts_as_own_person`]) with the same
    /// forbidden code, so a delete door that falls back to its role path
    /// judges it there (`federation::require_delete_authority_in_txn`).
    pub(crate) fn verify_own_deletion_authority_in(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> super::MemoryResult<()> {
        super::verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class)?;
        if self.acts_as_own_person() {
            return Ok(());
        }
        Err(super::MemoryError::new(
            super::MEMORY_CODE_FORBIDDEN,
            "a credential handed on to another key may not delete as the vault owner: \
             it acts as its key's holder, not as the person it names",
            &["Present the owner's own credential, not one handed on to another key."],
        ))
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
