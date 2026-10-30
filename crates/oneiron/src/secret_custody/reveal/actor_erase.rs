//! An erased actor out of the reveal rows (FIX 3520).

use super::{READER_AGENT, READER_OWNER, REVEALS, RevealRow, SecretRevealState};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::vault::Vault;

/// What an actor's erase does with a reveal that actor asked for whose value
/// has not gone out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealAskErase {
    /// The reveal goes: no one is left to collect it.
    Delete,
    /// The reveal stays as history, naming no one.
    Keep,
}

/// A reveal an erased agent asked for, still waiting on its answer or its
/// collection, is an act no one is left to take, so the erase deletes it
/// (FIX 3520). A delivered, denied or expired one is history and stays,
/// naming no one.
pub const ACTOR_ERASE_REVEAL_ASK: RevealAskErase = RevealAskErase::Delete;

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the custody rows.
pub(in crate::secret_custody) use crate::deletion::names_no_actor;

impl RevealRow {
    /// Whether this reveal may still go out: covered, asked or approved,
    /// and inside its window at `now`.
    pub(super) fn still_open(&self, now: u64) -> bool {
        matches!(
            self.state,
            SecretRevealState::Covered
                | SecretRevealState::Asked
                | SecretRevealState::ApprovedOnce
                | SecretRevealState::ApprovedStanding
        ) && now < self.expires_at
    }
}

/// Erasing `actor` from the reveals (FIX 3520): one the actor asked for that
/// may still go out goes, when [`ACTOR_ERASE_REVEAL_ASK`] says so. Every
/// other one keeps its row, its handle, its class, its why, its state, its
/// decisions and its times, and names no one where it named the actor: the
/// agent that asked and its connection, the owner who read, or the owner
/// who answered. A reveal that names no asker sends nothing more: its
/// connection names no one a lease could reach. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a reveal row that cannot be read.
pub(crate) fn erase_reveal_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let owner = format!("{READER_OWNER}:{}", actor.to_hex());
    let mut doomed = Vec::new();
    let mut erased = Vec::new();
    for (reveal, mut row) in REVEALS.scan(&vault.store, wtxn)? {
        let asked = row.actor == Some(*actor);
        let answered = row.answered_by.as_deref() == Some(owner.as_str());
        if asked && row.still_open(now) && ACTOR_ERASE_REVEAL_ASK == RevealAskErase::Delete {
            doomed.push(reveal);
            continue;
        }
        if asked {
            row.actor = None;
            if row.reader == READER_AGENT {
                row.connection = Some(format!("{READER_AGENT}:{ERASED_CALL_IDENTITY}"));
            }
        }
        if answered {
            row.answered_by = Some(format!("{READER_OWNER}:{ERASED_CALL_IDENTITY}"));
        }
        if asked || answered {
            erased.push((reveal, row));
        }
    }
    for reveal in &doomed {
        REVEALS.delete(&vault.store, wtxn, reveal)?;
    }
    for (reveal, row) in &erased {
        REVEALS.put(&vault.store, wtxn, reveal, row)?;
    }
    Ok(())
}
