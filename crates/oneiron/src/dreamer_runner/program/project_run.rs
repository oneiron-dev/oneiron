//! A program armed as one run of a project ([RSI-PROJECT-WORKFLOW]): an
//! admitted SKILL's pinned entry, armed on a trigger other than a turn for a
//! project its actor works in, which advances that project's workflow at
//! each wake and stops waking at the run's end.
//!
//! Arming checks the project once (`admit_project_run_in_txn`): the arming
//! actor leads it, sits on its board or holds a seat in it, and the SKILL is
//! a shared one or a fork that project lists, never another project's fork.
//! The pin keeps the project, so each occurrence's run sends in it
//! (`program_run_project_in_txn`), and a program armed for no project sends
//! in none, never a wider read.
//!
//! The run ends in the writer of the step that ended it
//! (`end_project_run_in_txn`): an entry that returned no pending answer, a
//! write the door refused, or a call the door refused for authority, which a
//! revoked Grant is at the next stage. That writer disarms the program, so
//! no later due time wakes it. A program armed for no project keeps waking
//! as before.

use crate::attempt_queue::AttemptId;
use crate::error::{ArtifactError, ClaimError, Error, Result};
use crate::workspace_roster::{ProjectReader, ProjectVerdict};
use crate::{EntityId, Vault};

use super::types::ProgramTrigger;
use super::{ADMISSION, ATTEMPT};

/// The member of an entry's returned object that keeps a project run
/// waking: `true` while a stage it started has not ended. Any other answer
/// ends the run.
pub(crate) const PENDING_MEMBER: &str = "pending";

/// Checks, in the arming writer, that `actor` may arm `skill` as one run of
/// `project` on `trigger`: a trigger other than a turn, a project the read
/// fold serves that `actor` leads, sits on the board of or holds a seat in,
/// and a SKILL that project lists among its forks or that no other project
/// lists.
///
/// # Errors
///
/// A turn trigger or another project's fork as an invalid skill body; an
/// unknown project as not found; an actor outside the project as lacking
/// authority; storage errors.
pub(super) fn admit_project_run_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    project: EntityId,
    skill: EntityId,
    trigger: &ProgramTrigger,
) -> Result<()> {
    if trigger.is_turn() {
        return Err(invalid(
            "a turn program sends in the project its turn lands in; only another trigger names one",
        ));
    }
    let (_, effective) = vault
        .effective_project_in_txn(txn, project)?
        .ok_or(Error::EntityNotFound)?;
    let actor_hex = actor.to_hex();
    if effective.leader != actor_hex
        && !effective.board.contains(&actor_hex)
        && !effective.seats.contains(&actor_hex)
    {
        return Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
            reason: "the arming actor neither leads, sits on the board of nor holds a seat in this project",
        }));
    }
    let Some(reader) = ProjectReader::new(&vault.store, txn, vault.privacy_posture())? else {
        return Ok(());
    };
    let mut listed_elsewhere = false;
    for (id, record, verdict) in reader.all()? {
        if verdict != ProjectVerdict::Visible
            || !record
                .skill_forks
                .iter()
                .any(|fork| EntityId::from_hex(fork).ok() == Some(skill))
        {
            continue;
        }
        if id == project {
            return Ok(());
        }
        listed_elsewhere = true;
    }
    if listed_elsewhere {
        return Err(invalid(
            "the skill is a fork another project lists; arm this project's own fork",
        ));
    }
    Ok(())
}

/// Ends the project run program attempt `attempt` serves, in the caller's
/// writer: disarms its arming when its pin names a project, so no later due
/// time wakes it. `false`, with nothing written, for a program armed for no
/// project, an attempt no program stamped, or an arming already disarmed.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn end_project_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<bool> {
    if attempt == attempt {
        return Ok(false);
    }
    let Some(stamp) = ATTEMPT.get(vault, &*txn, &attempt)? else {
        return Ok(false);
    };
    let Some(row) = ADMISSION.get(vault, &*txn, &stamp.admission)? else {
        return Ok(false);
    };
    if row
        .definition
        .as_ref()
        .and_then(|definition| definition.project)
        .is_none()
    {
        return Ok(false);
    }
    super::arm::disarm_turn_program_in_txn(
        vault,
        txn,
        row.wake.authority.actor(),
        row.wake.registration,
    )
}

/// Whether an entry's returned answer keeps a project run waking: a JSON
/// object whose [`PENDING_MEMBER`] is `true`.
pub(crate) fn answer_is_pending(answer: &serde_json::Value) -> bool {
    answer
        .get(PENDING_MEMBER)
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

const fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}
