//! A NOTE workflow row as a carrier holds it (FIX 3878): a window's copy, or
//! a recovery artifact's. An actor this vault erased reads as no one there
//! too, as the erase takes it out of this vault's own rows, and two copies
//! that differ only in who they name settle by
//! [`crate::deletion::ACTOR_ERASE_CARRIER_MERGE`]. That is carrier
//! equivalence, never a landing or replay check.

#[cfg(feature = "sync")]
use super::proposals::{ACTOR_ERASE_PENDING_NOTE_FORK, NoteReviewBundle, PendingNoteForkErase};
use super::proposals::{NoteActor, NoteFork, NoteLandingReceipt};
use crate::Vault;
#[cfg(feature = "sync")]
use crate::deletion::carrier_actor_merged;
use crate::error::Result;

impl NoteActor {
    /// This actor as this vault knows it: no one once this vault erased it.
    pub(crate) fn erased_here(self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        if let Self::Actor(id) = self
            && vault.carrier_actor_erased_in_txn(txn, &id)?
        {
            return Ok(Self::Erased);
        }
        Ok(self)
    }
}

impl NoteFork {
    /// This fork naming no one where this vault erased its actor.
    pub(crate) fn erased_here(mut self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        self.actor = self.actor.erased_here(vault, txn)?;
        Ok(self)
    }

    /// This fork as a carrier holds it here: naming no one where this vault
    /// erased its actor, or `None` when no one decided it and it goes with
    /// that erase, as [`ACTOR_ERASE_PENDING_NOTE_FORK`] says.
    #[cfg(feature = "sync")]
    pub(crate) fn carried_here(self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<Self>> {
        let named = self.actor;
        let fork = self.erased_here(vault, txn)?;
        if fork.actor != named
            && !fork.decided
            && ACTOR_ERASE_PENDING_NOTE_FORK == PendingNoteForkErase::Delete
        {
            return Ok(None);
        }
        Ok(Some(fork))
    }

    /// Two copies of one fork as one: the copy that stands, or `None` when
    /// they conflict. Every field but the actor must match.
    #[cfg(feature = "sync")]
    pub(crate) fn erased_wins(&self, other: &Self) -> Option<Self> {
        let actor = carrier_actor_merged(self.actor, other.actor, NoteActor::Erased)?;
        let ours = Self {
            actor,
            ..self.clone()
        };
        let theirs = Self {
            actor,
            ..other.clone()
        };
        (ours == theirs).then_some(ours)
    }
}

impl NoteLandingReceipt {
    /// This receipt naming no one where this vault erased its actor; its
    /// heads, verdict and time stay.
    pub(crate) fn erased_here(mut self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        self.actor = self.actor.erased_here(vault, txn)?;
        Ok(self)
    }

    /// Two copies of one receipt as one, as [`NoteFork::erased_wins`].
    #[cfg(feature = "sync")]
    pub(crate) fn erased_wins(&self, other: &Self) -> Option<Self> {
        let actor = carrier_actor_merged(self.actor, other.actor, NoteActor::Erased)?;
        let ours = Self {
            actor,
            ..self.clone()
        };
        let theirs = Self {
            actor,
            ..other.clone()
        };
        (ours == theirs).then_some(ours)
    }
}

#[cfg(feature = "sync")]
impl NoteReviewBundle {
    /// This bundle as a carrier holds it here: each landing naming no one
    /// where this vault erased its actor, each waiting fork as
    /// [`NoteFork::carried_here`] holds it, and the explainer redacted once a
    /// waiting fork went, since it can quote what left. `None` when no
    /// member is left.
    pub(crate) fn carried_here(
        mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<Self>> {
        let waiting = std::mem::take(&mut self.waiting);
        let count = waiting.len();
        for fork in waiting {
            self.waiting.extend(fork.carried_here(vault, txn)?);
        }
        if self.waiting.len() != count {
            self.explainer = "redacted".to_owned();
        }
        for receipt in &mut self.landed {
            receipt.actor = receipt.actor.erased_here(vault, txn)?;
        }
        Ok((!self.waiting.is_empty() || !self.landed.is_empty()).then_some(self))
    }

    /// Two copies of one bundle as one, as [`NoteFork::erased_wins`]: the
    /// same members in the same order, each settled so.
    pub(crate) fn erased_wins(&self, other: &Self) -> Option<Self> {
        if self.id != other.id
            || self.explainer != other.explainer
            || self.waiting.len() != other.waiting.len()
            || self.landed.len() != other.landed.len()
        {
            return None;
        }
        Some(Self {
            id: self.id,
            waiting: self
                .waiting
                .iter()
                .zip(&other.waiting)
                .map(|(ours, theirs)| ours.erased_wins(theirs))
                .collect::<Option<_>>()?,
            landed: self
                .landed
                .iter()
                .zip(&other.landed)
                .map(|(ours, theirs)| ours.erased_wins(theirs))
                .collect::<Option<_>>()?,
            explainer: self.explainer.clone(),
        })
    }
}
