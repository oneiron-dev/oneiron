//! The owner's resume of programs a store holds paused (FIX
//! TURNPROGRAM-OCCURRENCE-ARMINGS-LIVE-ON-A-VAULT-COPY, lead ruling 21 Nov).
//!
//! A vault copy made beside its source starts with its timer, feed and idle
//! programs paused (`trigger::pause_occurrence_armings_in_txn`), and nothing
//! there wakes one until the owner resumes it on that copy. The owner names
//! the registrations, so some resume and the others stay paused. This module
//! is the act's parts, each in the caller's own transaction: the chosen
//! programs as one snapshot holds them (`resume_chosen_in_txn`), what the
//! owner's sheet shows of them (`ResumeChosen::sheet_in_txn`), and the write
//! that clears their pause (`resume_paused_in_txn`). The sheet shows each
//! program as the paused list shows it: its pinned SKILL, with the name and
//! description that SKILL has now, only when the SKILL reads on the caller's
//! own lane (`ResumeChosen::readable_skills`), so a SKILL the list withholds
//! is withheld here too. The owner's proof and the confirm of the sheet are
//! the verb's (`crate::verbs::turn_program_resume`).

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{Memory, MemoryError, MemoryResult};

use super::read::{paused_armings_in_txn, paused_item, readable_on_lane, skills_now_in_txn};
use super::types::{ProgramTrigger, TurnProgramArming};

#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_runner::program::resume_paused::{
    ResumePausedTurnProgramItem, ResumePausedTurnProgramsPreview, ResumePausedTurnProgramsRequest,
    ResumedTurnPrograms,
};

/// The most registrations one resume names.
const RESUME_MAX_REGISTRATIONS: usize = 64;

/// The paused programs one resume names, as one snapshot holds them: each
/// arming and the time it was paused at, in key order.
pub(crate) struct ResumeChosen(Vec<(TurnProgramArming, u64)>);

/// The paused programs `registrations` name, as they stand in `txn`.
///
/// # Errors
///
/// `BAD_REQUEST` for no registration, more than 64, or one named twice;
/// `NOT_FOUND` for a registration that is no paused program of this store;
/// storage errors.
pub(crate) fn resume_chosen_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    registrations: &[EntityId],
) -> MemoryResult<ResumeChosen> {
    if registrations.is_empty() {
        return Err(MemoryError::bad_request(
            "registrations names at least one paused program",
        ));
    }
    if registrations.len() > RESUME_MAX_REGISTRATIONS {
        return Err(MemoryError::bad_request(
            "registrations names at most 64 paused programs",
        ));
    }
    let asked: BTreeSet<EntityId> = registrations.iter().copied().collect();
    if asked.len() != registrations.len() {
        return Err(MemoryError::bad_request(
            "registrations names a program twice",
        ));
    }
    let mut chosen = paused_armings_in_txn(vault, txn, &[])?;
    chosen.retain(|(arming, _)| asked.contains(&arming.registration));
    let found: BTreeSet<EntityId> = chosen
        .iter()
        .map(|(arming, _)| arming.registration)
        .collect();
    if let Some(missing) = asked.difference(&found).next() {
        return Err(MemoryError::not_found(format!(
            "registration {} is no paused program of this vault",
            missing.to_hex()
        )));
    }
    Ok(ResumeChosen(chosen))
}

impl ResumeChosen {
    /// Each chosen program's key in the arming table, its actor, then its
    /// registration, in key order.
    pub(crate) fn keys(&self) -> Vec<(EntityId, EntityId)> {
        self.0
            .iter()
            .map(|(arming, _)| (arming.actor, arming.registration))
            .collect()
    }

    /// Of the SKILLs the chosen programs pin, the ones that read on
    /// `memory`'s own lane, as the paused list judges them. It opens the
    /// lane's own reads: the caller holds no snapshot of the store.
    ///
    /// # Errors
    ///
    /// The handle's read key refused; storage errors.
    pub(crate) fn readable_skills(&self, memory: &Memory<'_>) -> MemoryResult<BTreeSet<EntityId>> {
        readable_on_lane(
            memory,
            self.0.iter().map(|(arming, _)| arming.definition.skill),
        )
    }

    /// What the owner's sheet shows of the chosen programs at `now`: each
    /// as the paused list shows it to a caller who reads the SKILLs of
    /// `readable`, with the name and description each such SKILL has in
    /// `txn`, and whether it is a timer whose due time has passed, which
    /// the resume wakes at once.
    pub(crate) fn sheet_in_txn(
        self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        now: u64,
        readable: &BTreeSet<EntityId>,
    ) -> ResumePausedTurnProgramsPreview {
        let named = skills_now_in_txn(vault, txn, readable);
        let programs = self
            .0
            .into_iter()
            .map(|(arming, paused_at)| {
                let fires_at_once = matches!(arming.trigger, ProgramTrigger::Timer { .. })
                    && arming.next_due.is_some_and(|due| due <= now);
                ResumePausedTurnProgramItem {
                    program: paused_item(arming, paused_at, readable, &named),
                    fires_at_once,
                }
            })
            .collect();
        ResumePausedTurnProgramsPreview { programs }
    }
}

/// Resumes the paused programs `keys` name, in the caller's write, and
/// answers how many the store still holds paused; `None`, with nothing
/// written, when one of them is no longer a paused program.
///
/// # Errors
///
/// Storage errors; an arming row the write must read that does not decode.
pub(crate) fn resume_paused_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    keys: &[(EntityId, EntityId)],
) -> Result<Option<u64>> {
    if !super::trigger::resume_occurrence_armings_in_txn(vault, txn, keys)? {
        return Ok(None);
    }
    let still = paused_armings_in_txn(vault, &*txn, &[])?.len();
    Ok(Some(u64::try_from(still).unwrap_or(u64::MAX)))
}
