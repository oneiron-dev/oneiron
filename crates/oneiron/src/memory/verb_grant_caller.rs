//! Who may call a door whose verb row names the proof `verb_grant_caller`
//! (design pass 32 section 5, the lane economy's doors; substrate behind
//! grants, 9 Nov): the vault owner under their own proof, or an agent whose
//! own live Grant from a live owner names it and lists the verb, judged at
//! each call. It is the GPU job caller's rule for its reads
//! ([`crate::gpu_job::GpuJobVerb`]) keyed by the verb's own name, so a door
//! that admits on it needs no verb list of its own. A person other than the
//! owner is refused: these doors name agents in Grants, never people.

use crate::EdgeActorClass;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// A caller a `verb_grant_caller` door admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbGrantCaller {
    /// The vault owner under their own proof.
    Owner,
    /// An agent under the one live Grant that admits it to the verb now.
    Agent { actor: EntityId, grant: EntityId },
}

impl Memory<'_> {
    /// Admits this handle's caller to `verb` in a snapshot of its own
    /// ([`Self::verb_grant_caller_admits_in_txn`]).
    ///
    /// # Errors
    ///
    /// `forbidden` for a caller it does not admit; a store read failure.
    pub fn verb_grant_caller_admits(
        &self,
        owner: Option<&AuthenticatedOwner>,
        verb: &str,
    ) -> MemoryResult<VerbGrantCaller> {
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.verb_grant_caller_admits_in_txn(&txn, owner, verb)
    }

    /// Admits this handle's caller to `verb` in `txn`. With `owner`, the
    /// caller's own proof decides: revalidated as a live owner of this vault
    /// and this handle's own human actor. Without one, the caller is this
    /// handle's agent, its presented credential still live, and one live
    /// Grant a live owner gave it confers now and lists `verb`; the standing
    /// rule picks that one Grant, never a union.
    ///
    /// # Errors
    ///
    /// `forbidden` for a caller it does not admit; a store read failure.
    pub(crate) fn verb_grant_caller_admits_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: Option<&AuthenticatedOwner>,
        verb: &str,
    ) -> MemoryResult<VerbGrantCaller> {
        let vault = self.vault();
        let (actor, class) = (self.actor(), self.actor_class());
        crate::memory::verify_actor_binding_in_txn(vault, txn, actor, class)?;
        if let Some(owner) = owner {
            if owner.revalidate_in_txn(vault, txn)? != actor || class != EdgeActorClass::Human {
                return Err(refused(
                    verb,
                    "the owner proof does not belong to this caller",
                ));
            }
            return Ok(VerbGrantCaller::Owner);
        }
        if let Some(slip) = self.presented_credential()
            && !vault.capability_slip_is_live_in_txn(txn, slip)?
        {
            return Err(refused(verb, "the caller's credential is no longer live"));
        }
        let standing = match class {
            EdgeActorClass::Agent | EdgeActorClass::System => {
                principal_standing_or_lapse_in_txn(vault, txn, actor, class, verb)?
            }
            EdgeActorClass::Human => Err(NoStanding::NotStanding),
        };
        match standing.map(|standing| standing.grant) {
            Ok(Some(grant)) => Ok(VerbGrantCaller::Agent { actor, grant }),
            Err(NoStanding::PactStandingLapsed) => Err(refused(verb, PACT_STANDING_LAPSED)),
            Ok(None) | Err(NoStanding::NotStanding) => Err(refused(
                verb,
                "no live Grant from a live owner names this agent and lists the verb",
            )),
        }
    }
}

/// The refusal of a caller `verb` does not admit.
fn refused(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{verb} takes the vault owner's own proof or an agent's own Grant that names it: {why}"
        ),
        &["Call it as the vault owner, or name the verb in the agent's Grant."],
    )
}
