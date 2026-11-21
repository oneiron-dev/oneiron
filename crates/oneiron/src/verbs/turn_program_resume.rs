//! `vault.turn_programs.resume`: the owner resumes programs a vault copy
//! holds paused (FIX TURNPROGRAM-OCCURRENCE-ARMINGS-LIVE-ON-A-VAULT-COPY, lead
//! ruling 21 Nov, ASK TURNPROGRAM-PAUSED-ARMINGS-OWNER-VERBS = A).
//!
//! A copy made beside its source starts with its timer, feed and idle turn
//! programs paused, so that the two stores do not both run them. Resuming
//! one lifts that guard for it on this copy: it is the owner's act alone,
//! under the owner's own proof, which the write revalidates. No grant names
//! it, and an agent's, a delegate's or another person's credential resumes
//! nothing. It goes through the owner's sheet
//! (`vault.owner_confirm.preview`): the sheet lists the chosen programs as
//! the paused list shows them on the calling handle's own lane, and marks
//! each timer whose due time has passed, which the resume wakes at once; the
//! confirm binds that sheet, and a program that moved since is refused with
//! nothing written.

use std::collections::BTreeSet;

use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    ResumePausedTurnProgramsPreview, ResumePausedTurnProgramsRequest, ResumedTurnPrograms,
    resume_chosen_in_txn, resume_paused_in_txn,
};
use crate::memory::{
    MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OWNER_CONFIRM_REQUIRED, Memory, MemoryError, MemoryResult,
};
use crate::{EntityId, Error};

/// The owner's resume verb's public spelling.
pub const TURN_PROGRAMS_RESUME_VERB: &str = "vault.turn_programs.resume";

/// What the owner's sheet shows of a `vault.turn_programs.resume` call, and
/// what its confirm binds: the paused programs `input` names as they stand,
/// read at `now` under `owner`'s proof, revalidated in the read's own
/// snapshot, each with its pinned SKILL only when that SKILL reads on
/// `memory`'s own lane.
///
/// # Errors
///
/// A proof that no longer holds; a request that names none, too many or one
/// twice; a registration that is no paused program of this store; the
/// handle's read key refused; storage errors.
pub(crate) fn turn_programs_resume_view(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &ResumePausedTurnProgramsRequest,
    now: u64,
) -> MemoryResult<ResumePausedTurnProgramsPreview> {
    Ok(sheet(memory, owner, input, now)?.1)
}

/// [`turn_programs_resume_view`]'s sheet, beside the SKILLs it shows: of the
/// ones the chosen programs pin, those that read on `memory`'s own lane. The
/// snapshot that revalidates the proof and reads the programs closes before
/// the lane reads, as the module's reads do.
fn sheet(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &ResumePausedTurnProgramsRequest,
    now: u64,
) -> MemoryResult<(BTreeSet<EntityId>, ResumePausedTurnProgramsPreview)> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    let chosen = resume_chosen_in_txn(vault, &txn, &input.registrations)?;
    drop(txn);
    let readable = chosen.readable_skills(memory)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let preview = chosen.sheet_in_txn(vault, &txn, now, &readable);
    Ok((readable, preview))
}

/// `vault.turn_programs.resume` on an embedded handle, as the vault's
/// embedded owner.
///
/// # Errors
///
/// `FORBIDDEN` for any caller but the embedded owner; then as
/// [`resume_paused_turn_programs_as`].
pub fn resume_paused_turn_programs(
    memory: &Memory<'_>,
    input: &ResumePausedTurnProgramsRequest,
) -> MemoryResult<ResumedTurnPrograms> {
    let owner = memory.embedded_owner(TURN_PROGRAMS_RESUME_VERB)?;
    resume_paused_turn_programs_as(memory, &owner, input)
}

/// `vault.turn_programs.resume` under the vault owner's own proof: clears
/// the pause of each program `input` names, in one write that revalidates
/// the proof, reads the programs again and reads the time again. `memory`
/// is the owner's own handle, the one the preview took: its lane decides
/// which pinned SKILL the sheet shows. A resumed timer keeps the due time
/// it was paused with, so one whose time has passed wakes once at its
/// actor's next timer run; an idle or a feed program wakes at its next
/// occurrence. The programs the request does not name stay paused.
///
/// # Errors
///
/// `OWNER_CONFIRM_REQUIRED` without the confirm of this call's sheet as it
/// stands now, or when the sheet changed between that check and the write:
/// a chosen program moved or is gone, or a timer's due time passed; a proof
/// that no longer holds; a request the sheet refuses; storage errors.
pub fn resume_paused_turn_programs_as(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &ResumePausedTurnProgramsRequest,
) -> MemoryResult<ResumedTurnPrograms> {
    let vault = memory.vault();
    let ask = super::owner_confirm::asked(TURN_PROGRAMS_RESUME_VERB, input)?;
    let (readable, shown) = sheet(memory, owner, input, vault.now_recorded_at())?;
    super::owner_confirm::admit(vault, owner, ask, &shown)?;
    let changed = || {
        MemoryError::new(
            MEMORY_CODE_OWNER_CONFIRM_REQUIRED,
            "the paused programs changed since their preview",
            &["Preview it again and confirm what it shows now."],
        )
    };
    let still_paused = vault.try_with_write_txn_grouped(|wtxn| {
        owner.revalidate_in_txn(vault, &*wtxn)?;
        // The call found every program before its confirm was admitted, so
        // one that is missing here went since: the sheet changed.
        let chosen = match resume_chosen_in_txn(vault, &*wtxn, &input.registrations) {
            Ok(chosen) => chosen,
            Err(error) if error.code == MEMORY_CODE_NOT_FOUND => return Err(changed()),
            Err(error) => return Err(error),
        };
        let keys = chosen.keys();
        // The write's own time, not the one the confirm was admitted at: a
        // timer that fell due while this write waited is no longer the
        // timer the sheet showed.
        let sheet_now = chosen.sheet_in_txn(vault, &*wtxn, vault.now_recorded_at(), &readable);
        if sheet_now != shown {
            return Err(changed());
        }
        resume_paused_in_txn(vault, wtxn, &keys)?.ok_or_else(changed)
    })?;
    Ok(ResumedTurnPrograms {
        resumed: shown.programs,
        still_paused,
    })
}
