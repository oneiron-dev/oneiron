//! An agent's cleanup decision (RESTRICTION-WAVE-10 C43). With the owner's
//! `vault_cleanup.decide.owner_only` off, an agent whose live owner Grant names
//! [`DECIDE_VERB`] decides one open proposal as the owner's door does: the same
//! complete verdict, bound to the revision it names, with the same digest. The
//! key and the Grant are read in the write that decides, so a Grant revoked or
//! a key turned on before it commits changes nothing. A member never decides:
//! a verdict acts on other persons' records.

use super::proposal_review::{Decided, decide_cleanup_proposal_sourced_in_txn};
use super::{CleanupDecideRequest, CleanupDecideView};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::Memory;
use oneiron_contracts::memory::MemoryResult;

/// The verb, and the line an agent's live owner Grant names to decide.
pub(super) const DECIDE_VERB: &str = "vault.cleanup.decide";

impl Vault {
    /// [`Self::decide_cleanup_proposal_as`] for `agent`, admitted only while the
    /// owner's `vault_cleanup.decide.owner_only` is off and under the first live
    /// owner Grant that names `vault.cleanup.decide`.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` "vault.cleanup.decide is the vault owner's", as an agent's
    /// call answered before the key, while the key is on or no such Grant
    /// stands; otherwise as [`Self::decide_cleanup_proposal_as`].
    pub fn decide_cleanup_proposal_as_agent(
        &self,
        agent: EntityId,
        input: &CleanupDecideRequest,
    ) -> MemoryResult<CleanupDecideView> {
        self.decide_cleanup_proposal_sourced_as_agent(agent, input)
            .map(|(view, _)| view)
    }

    /// [`Self::decide_cleanup_proposal_as_agent`] beside the decision's
    /// additive attempt sources, as
    /// [`Self::decide_cleanup_proposal_sourced_as`].
    ///
    /// # Errors
    ///
    /// As [`Self::decide_cleanup_proposal_as_agent`].
    pub fn decide_cleanup_proposal_sourced_as_agent(
        &self,
        agent: EntityId,
        input: &CleanupDecideRequest,
    ) -> MemoryResult<(CleanupDecideView, Vec<EntityId>)> {
        let decided = self.with_write_txn(|txn| {
            if !agent_decides_in_txn(self, txn, agent)? {
                return Ok((Decided::Refused, Vec::new()));
            }
            decide_cleanup_proposal_sourced_in_txn(self, txn, input)
        });
        Decided::answer_sourced(decided, &input.proposal)
    }
}

/// Whether `agent` decides now: the owner's key is off and a live owner Grant
/// names [`DECIDE_VERB`].
fn agent_decides_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, agent: EntityId) -> Result<bool> {
    if super::setting_keys::DECIDE_OWNER_ONLY
        .read_in_txn(vault, txn, &[], None)?
        .value
    {
        return Ok(false);
    }
    Ok(vault
        .admit_queue_review_policy_in_txn(txn, agent, EdgeActorClass::Agent, DECIDE_VERB)?
        .is_ok())
}

impl Memory<'_> {
    /// Whether this caller is an agent [`Vault::decide_cleanup_proposal_as_agent`] admits now,
    /// for `can()`.
    ///
    /// # Errors
    ///
    /// A store read that fails.
    pub(crate) fn agent_decides_cleanup(&self) -> MemoryResult<bool> {
        if self.actor_class() != EdgeActorClass::Agent {
            return Ok(false);
        }
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        Ok(agent_decides_in_txn(vault, &txn, self.actor())?)
    }
}

/// The `vault.cleanup.decide` row's door: an agent through
/// [`Vault::decide_cleanup_proposal_as_agent`], anyone else as the vault's
/// owner through [`Vault::decide_cleanup_proposal_as`].
///
/// # Errors
///
/// As the door the caller takes; a caller who is neither the owner nor an
/// agent answers [`Memory::embedded_owner`]'s refusal.
pub fn decide_cleanup_proposal_wire(
    memory: &Memory<'_>,
    input: &CleanupDecideRequest,
) -> MemoryResult<CleanupDecideView> {
    let vault = memory.vault();
    if memory.actor_class() == EdgeActorClass::Agent {
        return vault.decide_cleanup_proposal_as_agent(memory.actor(), input);
    }
    vault.decide_cleanup_proposal_as(&memory.embedded_owner(DECIDE_VERB)?, input)
}
