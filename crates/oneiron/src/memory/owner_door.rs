//! The embedded owner's door for the verb-table rows that are the vault
//! owner's (`vault.packs.put`, the `connector.*` key lifecycle). A server
//! takes the owner's proof from the request instead.

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::authority::{OwnerOrDelegate, VerifiedSlip, is_owner_delegate_verb};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::GateError;
use crate::skill_hub::pack_catalog::PackInstallDisposition;
use crate::store::GateDecisionId;
use crate::write_envelope::skill_source::HubFile;

impl Memory<'_> {
    /// The vault owner's proof for this handle. Only the constructor-owned
    /// handle that holds the vault's writer lease has one, as
    /// [`Memory::export`]'s local door; binding a different PERSON never
    /// grants it.
    ///
    /// A handle a host bound to a credential ([`Memory::with_read_proof`])
    /// has it only while that credential is the owner's own live human slip
    /// that reaches `verb` and cuts nothing else: the owner's full slip, or
    /// one the owner minted to a verb subset that names `verb` or the core
    /// scope its row needs (`oneiron token read`, `token agent`, `token pair
    /// --scope`). The proof then carries it, so every door that revalidates
    /// the proof refuses once it is revoked or expires. A revoked
    /// credential, one handed to another key, one cut on its records,
    /// channels or any scope axis but its verbs, one whose verbs do not reach
    /// `verb`, or another person's takes no owner door, as it reads only what
    /// it grants (FIX EMBEDDED-OWNER-IGNORES-BOUND-PROOF).
    pub fn embedded_owner(&self, verb: &str) -> MemoryResult<AuthenticatedOwner> {
        let owner = self.embedded_owner_actor(verb)?;
        let proof =
            self.vault
                .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
        let Some(credential) = &self.read_proof else {
            return Ok(proof);
        };
        self.vault
            .bind_owner_credential_for_verb(proof, credential.clone(), verb)
            .map_err(|error| match error {
                crate::Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason)) => {
                    MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!("{verb} is the vault owner's: {reason}"),
                        &["Call it with the owner's own live credential that reaches this verb."],
                    )
                }
                other => MemoryError::from(other),
            })
    }

    /// Runs the owner act `verb`, one whose door also admits the owner's
    /// delegate (restriction wave 11), as this in-process handle may take
    /// it. The embedded owner [`Self::embedded_owner`] admits takes it as
    /// before: `act` gets the owner's proof and no credential. An agent
    /// handle bound to its own live credential ([`Self::with_read_proof`])
    /// that the facade would admit for the verb's row takes it as the
    /// owner's delegate: `act` gets the agent and that credential, and runs
    /// the delegate door, which reads the owner's Setting key and the
    /// agent's live Grant in the act's own transaction, as for the facade.
    /// Any other caller gets the owner refusal (FIX
    /// WAVE11-INPROCESS-OWNER-DOORS).
    ///
    /// # Errors
    ///
    /// The owner refusal for a caller that is neither; `FORBIDDEN` for an
    /// agent's credential that no longer holds, that does not reach the
    /// row's core scope or that is cut on its records; `act`'s own errors.
    pub(crate) fn with_owner_or_delegate<T>(
        &self,
        verb: &str,
        act: impl FnOnce(OwnerOrDelegate<'_>, Option<&VerifiedSlip>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        let refusal = match self.embedded_owner(verb) {
            Ok(owner) => return act(OwnerOrDelegate::Owner(&owner), None),
            Err(refusal) => refusal,
        };
        match self.own_delegate_credential(verb)? {
            Some(credential) => act(OwnerOrDelegate::Delegate(self.actor), Some(credential)),
            None => Err(refusal),
        }
    }

    /// This agent handle's own credential, when the handle may take the
    /// owner act `verb` as the owner's delegate, held to the checks the
    /// facade runs before its delegate door: the caller is an agent, the
    /// credential names it and its class, is reusable and was not handed to
    /// another key, and stands now; it grants the row's core scope; and it
    /// is cut on no records, channels or scope axis but its verbs (every
    /// owner-delegate row asks unrestricted record scope). `None` for a
    /// handle that is no agent, a verb whose door admits no delegate, or no
    /// credential that is the agent's own.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` for a credential that no longer holds, that does not
    /// reach the row's core scope or that is cut; storage errors.
    fn own_delegate_credential(&self, verb: &str) -> MemoryResult<Option<&VerifiedSlip>> {
        let Some(row) = crate::verbs::AgentVerb::from_name(verb) else {
            return Ok(None);
        };
        if self.actor_class != EdgeActorClass::Agent || !is_owner_delegate_verb(verb) {
            return Ok(None);
        }
        let Some(credential) = self.read_proof.as_ref() else {
            return Ok(None);
        };
        let claims = credential.claims();
        if claims.holder_ref != self.actor.to_hex()
            || claims.actor_class.as_deref() != Some("agent")
            || claims.single_use
            || claims.invitation_ref.is_some()
            || credential.is_transferred()
        {
            return Ok(None);
        }
        if !self.vault.capability_slip_is_live(credential)? {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the credential is no longer live",
                &["Present a live credential, then call again."],
            ));
        }
        let class = if row.writes() { "write" } else { "read" };
        if !(credential.allows_verb(class) || credential.allows_verb(&format!("core:{class}"))) {
            return Err(scope_refusal(&format!("core:{class}")));
        }
        let mut uncut = crate::federation::Scope::top();
        uncut.verbs = credential.scope().verbs.clone();
        if !claims.records.is_empty()
            || !claims.channels.is_empty()
            || !uncut.is_narrowing_of(credential.scope())
        {
            return Err(scope_refusal("record-scope"));
        }
        Ok(Some(credential))
    }

    /// The embedded owner as the caller of the authority clock repair (FIX
    /// 11202), on the handle [`Self::embedded_owner`] admits: the one that
    /// holds the vault's writer lease and binds that owner as a human. No
    /// owner proof is minted here: the repair's writer judges the owner
    /// against the floor it stages. A handle bound to a credential calls
    /// with that credential and `verb`, which the writer judges as
    /// [`Self::embedded_owner`] judges them: only the owner's own live human
    /// slip that reaches `verb` and cuts nothing else acts as the owner.
    pub fn embedded_clock_repair_caller(
        &self,
        verb: &str,
    ) -> MemoryResult<crate::authority::ClockRepairCaller> {
        self.embedded_owner_actor(verb)?;
        Ok(match &self.read_proof {
            Some(credential) => {
                crate::authority::ClockRepairCaller::bound_for_verb(credential.clone(), verb)
            }
            None => crate::authority::ClockRepairCaller::embedded(),
        })
    }

    /// The embedded owner, when this handle binds that owner as a human in
    /// the process that holds the vault's writer lease.
    fn embedded_owner_actor(&self, verb: &str) -> MemoryResult<crate::EntityId> {
        let owner = crate::vault::embedded_owner_actor_id()?;
        if self.actor != owner
            || self.actor_class != EdgeActorClass::Human
            || !self
                .vault
                .writer_lease()
                .is_some_and(crate::store::VaultWriterLease::held_by_current_process)
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{verb} is the vault owner's"),
                &["Call it as the vault's owner."],
            ));
        }
        Ok(owner)
    }

    /// Installs a pack folder as the vault's embedded owner, for the owner
    /// verb `verb` that installs it (`vault.packs.put`, or
    /// `vault.mail.pack.install` for the engine's own Mail & Calendar pack):
    /// a bound handle's credential must reach that verb, as
    /// [`Self::embedded_owner`] says.
    pub fn put_pack_as_embedded_owner(
        &self,
        verb: &str,
        files: Vec<HubFile>,
    ) -> MemoryResult<PackInstallDisposition> {
        let proof = self.embedded_owner(verb)?;
        Ok(self.vault.put_pack(&proof, files)?)
    }
}

/// An owner-delegate door's refusal of an agent's credential that lacks
/// `required`, the scope the facade names for the same refusal.
fn scope_refusal(required: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("the credential does not have the required scope {required}"),
        &["Present a credential with the required Oneiron core scope, then call again."],
    )
}
