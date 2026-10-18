//! Whose act a repo proposal records, and the erase that forgets it
//! (FIX 3520).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{PROPOSAL, PROPOSAL_OP, RepoProposalStatus, invalid};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;

/// Who opened a repo proposal: an actor, or no one once that actor was
/// erased (FIX 3520). It reads and writes as the actor's hex id, or as
/// [`ERASED_CALL_IDENTITY`]. An erased one is never a live critic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalActor {
    Actor(EntityId),
    Erased,
}

impl ProposalActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is not erased.
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// How a view spells it: the actor's hex id, or [`ERASED_CALL_IDENTITY`].
    #[must_use]
    pub fn to_hex(self) -> String {
        match self {
            Self::Actor(id) => id.to_hex(),
            Self::Erased => ERASED_CALL_IDENTITY.to_owned(),
        }
    }

    /// The actor a reviewed write lands under. An erased actor's proposal
    /// never runs again.
    pub(in crate::repo_mutation) fn live(self) -> Result<EntityId> {
        self.id()
            .ok_or_else(|| invalid("an erased actor's proposal cannot run"))
    }
}

impl Serialize for ProposalActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ProposalActor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

/// What an actor's erase does with a proposal it opened that has not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingRepoProposalErase {
    /// The proposal goes, with any operation pointer to it.
    Delete,
    /// The proposal stays and names no one; the queue refuses to run it.
    Keep,
}

/// A proposal that has not run, proposed or approved and never queued, is
/// still work the queue could land, so an erase of the actor who opened it
/// deletes it (FIX 3520).
pub const ACTOR_ERASE_PENDING_REPO_PROPOSAL: PendingRepoProposalErase =
    PendingRepoProposalErase::Delete;

/// Erasing `actor` from the proposals it opened (FIX 3520): one that ran,
/// applied or failed, keeps its row, critiques and outcome and names no one,
/// and the queue refuses to run it again. One that has not run goes, with any
/// operation pointer to it, when [`ACTOR_ERASE_PENDING_REPO_PROPOSAL`] says
/// so. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a proposal row that cannot be read.
pub(crate) fn erase_proposal_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if super::super::support::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut named = Vec::new();
    for row in PROPOSAL.iter_from(&vault.store, wtxn, &[])? {
        let (id, mut proposal) = row?;
        if proposal.actor.is(*actor) {
            proposal.actor = ProposalActor::Erased;
            named.push((id, proposal));
        }
    }
    let mut gone = BTreeSet::new();
    for (id, proposal) in named {
        let pending = proposal.operation_seq.is_none()
            && matches!(
                proposal.status,
                RepoProposalStatus::Proposed | RepoProposalStatus::Approved
            );
        if pending && ACTOR_ERASE_PENDING_REPO_PROPOSAL == PendingRepoProposalErase::Delete {
            PROPOSAL.delete(&vault.store, wtxn, &id)?;
            gone.insert(id);
        } else {
            PROPOSAL.put(&vault.store, wtxn, &id, &proposal)?;
        }
    }
    if gone.is_empty() {
        return Ok(());
    }
    let mut pointers = Vec::new();
    for row in PROPOSAL_OP.iter_from(&vault.store, wtxn, &[])? {
        let (key, id) = row?;
        if gone.contains(&id) {
            pointers.push(key);
        }
    }
    for key in pointers {
        PROPOSAL_OP.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}
