//! An agent's cleanup decision (RESTRICTION-WAVE-10 C43). With the owner's
//! `vault_cleanup.decide.owner_only` off, an agent whose live owner Grant names
//! [`DECIDE_VERB`] decides one open proposal as the owner's door does: the same
//! complete verdict, bound to the revision it names, with the same digest. The
//! key and the Grant are read in the write that decides, so a Grant revoked or
//! a key turned on before it commits changes nothing; a read first refuses an
//! agent they do not admit without waiting on the writer. A member never
//! decides: a verdict acts on other persons' records.

use super::attempt_delete_authority::credential_reaches;
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
    /// owner Grant that names `vault.cleanup.decide`. The caller has judged the
    /// agent's credential, as the server's facade does.
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
        decide_as_agent(self, agent, None, input).map(|(view, _)| view)
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
        decide_as_agent(self, agent, None, input)
    }

    /// Whether [`Self::decide_cleanup_proposal_as_agent`] admits `agent` now: the
    /// owner's key is off and a live owner Grant names `vault.cleanup.decide`.
    /// The server's facade asks it before the call's hooks run.
    ///
    /// # Errors
    ///
    /// A store read that fails.
    pub fn cleanup_decide_admits_agent(&self, agent: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        agent_admitted_in_txn(self, &txn, agent, None)
    }
}

impl Memory<'_> {
    /// Whether this caller is an agent the decide admits now, its presented
    /// credential included, for `can()`.
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
        Ok(agent_admitted_in_txn(
            vault,
            &txn,
            self.actor(),
            Some(self),
        )?)
    }
}

/// The agent decide: a read that refuses an agent the key, the Grant or its
/// `memory`'s presented credential does not admit, then the write that checks
/// all three again and decides.
fn decide_as_agent(
    vault: &Vault,
    agent: EntityId,
    memory: Option<&Memory<'_>>,
    input: &CleanupDecideRequest,
) -> MemoryResult<(CleanupDecideView, Vec<EntityId>)> {
    let admitted = vault
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)
        .and_then(|txn| agent_admitted_in_txn(vault, &txn, agent, memory));
    let decided = match admitted {
        Ok(true) => vault.with_write_txn(|txn| {
            if !agent_admitted_in_txn(vault, txn, agent, memory)? {
                return Ok((Decided::Refused, Vec::new()));
            }
            decide_cleanup_proposal_sourced_in_txn(vault, txn, input)
        }),
        Ok(false) => Ok((Decided::Refused, Vec::new())),
        Err(error) => Err(error),
    };
    Decided::answer_sourced(decided, &input.proposal)
}

/// Whether `agent` decides now: `memory`'s presented credential, when the
/// caller hands one, is the agent's own, bound to no invitation, record or
/// channel, and live; the owner's key is off; and a live owner Grant names
/// [`DECIDE_VERB`].
fn agent_admitted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    memory: Option<&Memory<'_>>,
) -> Result<bool> {
    let credential_reaches = match memory {
        Some(memory) => credential_reaches(memory, txn, false)?,
        None => true,
    };
    if !credential_reaches
        || super::setting_keys::DECIDE_OWNER_ONLY
            .read_in_txn(vault, txn, &[], None)?
            .value
    {
        return Ok(false);
    }
    Ok(vault
        .admit_queue_review_policy_in_txn(txn, agent, EdgeActorClass::Agent, DECIDE_VERB)?
        .is_ok())
}

/// The `vault.cleanup.decide` row's door: an agent as the agent decide does,
/// its presented credential judged too, anyone else as the vault's owner
/// through [`Vault::decide_cleanup_proposal_as`].
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
        return decide_as_agent(vault, memory.actor(), Some(memory), input).map(|(view, _)| view);
    }
    vault.decide_cleanup_proposal_as(&memory.embedded_owner(DECIDE_VERB)?, input)
}
