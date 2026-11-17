//! An agent's cleanup decision (RESTRICTION-WAVE-10 C43). With the owner's
//! `vault_cleanup.decide.owner_only` off, an agent whose live owner Grant names
//! [`DECIDE_VERB`] decides one open proposal as the owner's door does: the same
//! complete verdict, bound to the revision it names, with the same digest. The
//! decide runs on the agent's handle, so the credential a host bound to it is
//! judged on every path, a served call's as an in-process one's. The key, the
//! Grant and that credential are read in the write that decides, so a Grant
//! revoked or a key turned on before it commits changes nothing; a read first
//! refuses an agent they do not admit without waiting on the writer. A member
//! never decides: a verdict acts on other persons' records.

use super::attempt_delete_authority::credential_reaches;
use super::proposal_review::{Decided, decide_cleanup_proposal_sourced_in_txn};
use super::{CleanupDecideRequest, CleanupDecideView};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::Memory;
use oneiron_contracts::memory::MemoryResult;

/// The verb, and the line an agent's live owner Grant names to decide.
pub(super) const DECIDE_VERB: &str = "vault.cleanup.decide";

impl Memory<'_> {
    /// [`crate::Vault::decide_cleanup_proposal_sourced_as`] for this handle's
    /// agent, beside the decision's additive attempt sources. It decides only
    /// while the owner's `vault_cleanup.decide.owner_only` is off, under the
    /// first live owner Grant that names `vault.cleanup.decide`, and on the
    /// credential a host bound to this handle ([`Memory::with_read_proof`]),
    /// when one is bound: the agent's own, bound to no invitation, record or
    /// channel, and live. A server binds the credential its caller presented.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` "vault.cleanup.decide is the vault owner's", as an agent's
    /// call answered before the key, for a caller that is no agent, while the
    /// key is on, while no such Grant stands, or on a credential that does not
    /// reach; otherwise as [`crate::Vault::decide_cleanup_proposal_as`].
    pub fn decide_cleanup_proposal_sourced_as_agent(
        &self,
        input: &CleanupDecideRequest,
    ) -> MemoryResult<(CleanupDecideView, Vec<EntityId>)> {
        let vault = self.vault();
        let admitted = vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)
            .and_then(|txn| agent_admitted_in_txn(self, &txn));
        let decided = match admitted {
            Ok(true) => vault.with_write_txn(|txn| {
                if !agent_admitted_in_txn(self, txn)? {
                    return Ok((Decided::Refused, Vec::new()));
                }
                decide_cleanup_proposal_sourced_in_txn(vault, txn, input)
            }),
            Ok(false) => Ok((Decided::Refused, Vec::new())),
            Err(error) => Err(error),
        };
        Decided::answer_sourced(decided, &input.proposal)
    }

    /// Whether [`Self::decide_cleanup_proposal_sourced_as_agent`] admits this
    /// caller now, its bound credential included: for `can()`, and for a
    /// server's door before the call's hooks run.
    ///
    /// # Errors
    ///
    /// A store read that fails.
    pub fn agent_decides_cleanup(&self) -> MemoryResult<bool> {
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        Ok(agent_admitted_in_txn(self, &txn)?)
    }
}

/// Whether `memory`'s caller decides now: it is an agent; the credential
/// bound to the handle, when one is, is the agent's own, bound to no
/// invitation, record or channel, and live; the owner's key is off; and a
/// live owner Grant names [`DECIDE_VERB`].
fn agent_admitted_in_txn(memory: &Memory<'_>, txn: &heed::RoTxn<'_>) -> Result<bool> {
    if memory.actor_class() != EdgeActorClass::Agent || !credential_reaches(memory, txn, false)? {
        return Ok(false);
    }
    let vault = memory.vault();
    if super::setting_keys::DECIDE_OWNER_ONLY
        .read_in_txn(vault, txn, &[], None)?
        .value
    {
        return Ok(false);
    }
    Ok(vault
        .admit_queue_review_policy_in_txn(txn, memory.actor(), EdgeActorClass::Agent, DECIDE_VERB)?
        .is_ok())
}

/// The `vault.cleanup.decide` row's door: an agent as the agent decide does,
/// its presented credential judged too, anyone else as the vault's owner
/// through [`crate::Vault::decide_cleanup_proposal_as`].
///
/// # Errors
///
/// As the door the caller takes; a caller who is neither the owner nor an
/// agent answers [`Memory::embedded_owner`]'s refusal.
pub fn decide_cleanup_proposal_wire(
    memory: &Memory<'_>,
    input: &CleanupDecideRequest,
) -> MemoryResult<CleanupDecideView> {
    if memory.actor_class() == EdgeActorClass::Agent {
        return memory
            .decide_cleanup_proposal_sourced_as_agent(input)
            .map(|(view, _)| view);
    }
    memory
        .vault()
        .decide_cleanup_proposal_as(&memory.embedded_owner(DECIDE_VERB)?, input)
}
