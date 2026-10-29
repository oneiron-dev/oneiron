//! The owner's release of a held turn program (DOOR-141, FIX 5880).
//!
//! A program the runtime holds for a run that no longer lines up with its
//! checkpoint, or for a run that ended without its pinned entry finishing,
//! has no condition that returns: nothing resumes it on its own. The vault's
//! authenticated owner releases one such hold at a time, against the exact
//! hold a program read showed him (its reason and when it was parked), so a
//! hold that changed since refuses and nothing moves.
//!
//! Stop ends the try through the queue's owner force-cancel, whose receipt
//! names the owner, clears the program's own park and marks the try's own
//! Pending sends Abandoned (FIX 7188, `stop_sends`), a ledger that refuses
//! that never refusing the Stop; the run, its checkpoint and its steps stay
//! as they are, and a settled try is never reopened. Resume queues the same
//! try again, only once its checkpoint lines up with its run's record, its
//! authority and pin bind again and nothing it did is unsettled, with the
//! owner's intervention on its queue row. It repairs nothing: a head behind
//! its record stays held until its repair (FIX 5881) lands. Nothing here runs
//! on its own, and no other park is touched.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, ForceAttemptCancel,
    ForceCancelAuthority, ForceCancelOutcome, InterveneAttempt,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{DreamerParkCause, DreamerRunnerStore};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

use super::super::store::PARKED;
use super::authority::TurnProgramBound;
use super::resume::{ProgramHold, resume_preflight_in_txn};
use super::stop_sends::abandon_stopped_sends_in_txn;
use super::{ATTEMPT, PROGRAM_PARK_OWNER};

/// The note a validated resume's intervention carries when the owner gave
/// none.
const RESUME_NOTE: &str = "the owner resumed the turn program's held try, its checkpoint validated";

/// The owner's release of one held turn program's try.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTurnProgramHoldRequest {
    /// 32-hex id of the held try, as a program read's `held` names it
    /// (`job:` prefix allowed).
    pub attempt: String,
    /// The hold's exact reason and the time it was parked, as that read
    /// showed them: a hold that changed since refuses.
    pub reason: String,
    pub parked_at: u64,
    pub action: ProgramHoldReleaseAction,
    /// The owner's note: a stop's cancellation reason, or a resume's
    /// intervention note.
    #[serde(default)]
    pub note: Option<String>,
}

/// What the owner does with a held program's try.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProgramHoldReleaseAction {
    /// End the try and clear its hold; its run, checkpoint and steps stay.
    Stop,
    /// Queue the same try again: only a diverged or unfinished program's
    /// hold, once its checkpoint lines up with its run's record, its
    /// authority and pin bind and nothing it did is unsettled.
    ResumeValidated,
}

/// What releasing one program's hold did.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProgramHoldReleaseView {
    /// 32-hex try.
    pub attempt: String,
    pub action: ProgramHoldReleaseAction,
    /// The released hold's exact reason.
    pub released: String,
    /// The try's queue state after the release.
    pub state: String,
    /// Whether this release stopped or queued the try: a stop of a try
    /// already settled only clears its hold.
    pub effected: bool,
}

/// What one release committed, and what its commit signals after.
struct Released {
    view: ProgramHoldReleaseView,
    /// The try a stop ended, at its lease generation: its running step stops.
    stopped: Option<(AttemptId, u32)>,
    /// A resume queued the try: the deadline lane arms it.
    resumed: bool,
}

/// Releases one held turn program's try as the vault's authenticated owner
/// (FIX 5880): the owner is revalidated in the writer, the try must be a
/// program's, and its park the program runtime's own hold with exactly the
/// reason and park time the request names. Stop force-cancels the try on the
/// owner's grounds and clears that hold; a resume of a diverged or
/// unfinished program's hold checks its checkpoint against its run's record,
/// binds its authority and pin, checks nothing it did is unsettled, records
/// the owner's intervention and resumes the park as the same try. After the
/// commit a stopped try's running step stops and a resumed one is armed.
///
/// # Errors
///
/// A malformed attempt id ([`Error::InvalidConfig`]); a proof that no longer
/// holds; a try no program stamped, or one the program runtime does not hold
/// ([`Error::EntityNotFound`]); a hold that changed since it was read
/// ([`Error::ConcurrentWrite`]); a resume of any other hold, of a settled
/// try, or of one whose checkpoint, authority, pin or effects do not let it
/// resume ([`Error::InvalidConfig`]); a note the queue refuses; storage
/// errors.
pub fn release_turn_program_hold_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ReleaseTurnProgramHoldRequest,
) -> Result<ProgramHoldReleaseView> {
    let attempt = attempt_id(&input.attempt)?;
    let now = vault.now_recorded_at();
    let released = vault
        .with_write_txn_grouped(|wtxn| release_in_txn(vault, wtxn, owner, attempt, input, now))?;
    // Committed: the write door told the attempt observers.
    if let Some((id, generation)) = released.stopped {
        crate::engine_executor::stop_attempt_step(Some(vault), id, generation);
    }
    // A resume arms its try at once, and a Stop may owe an abandon whose
    // retry the deadline lane arms (FIX 7352).
    if released.resumed || released.stopped.is_some() {
        vault.store.notify_proactivity_changes();
    }
    Ok(released.view)
}

fn release_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    attempt: AttemptId,
    input: &ReleaseTurnProgramHoldRequest,
    now: u64,
) -> Result<Released> {
    let actor = owner.revalidate_in_txn(vault, &*wtxn)?;
    let stamped = ATTEMPT
        .get_lenient(vault, &*wtxn, &attempt)?
        .is_some_and(|stamp| stamp.attempt_id == *attempt.as_bytes());
    if !stamped {
        return Err(Error::EntityNotFound);
    }
    let store = DreamerRunnerStore::new(vault);
    let Some((status, Some(park))) = store.status_with_park_in_txn(&*wtxn, attempt)? else {
        return Err(Error::EntityNotFound);
    };
    if park.park_owner != PROGRAM_PARK_OWNER || park.cause != DreamerParkCause::Other {
        return Err(Error::EntityNotFound);
    }
    if park.reason != input.reason || park.parked_at != input.parked_at {
        return Err(Error::ConcurrentWrite(
            "the turn program's hold changed since it was read",
        ));
    }
    let (record, effected, stopped) = match input.action {
        ProgramHoldReleaseAction::Stop => {
            let (record, stopped) = stop_in_txn(vault, wtxn, actor, attempt, input, now)?;
            let generation = stopped.then_some((attempt, record.attempt_count));
            (record, stopped, generation)
        }
        ProgramHoldReleaseAction::ResumeValidated => {
            if !matches!(
                ProgramHold::of_reason(&park.reason),
                Some(ProgramHold::Diverged | ProgramHold::Unfinished)
            ) {
                return Err(Error::InvalidConfig(
                    "only a diverged or unfinished turn program's hold resumes at the owner's \
                     word; any other resumes once its condition is met, or stops"
                        .to_owned(),
                ));
            }
            if status.attempt.state.is_terminal() {
                return Err(Error::InvalidConfig(
                    "a settled turn program try is never reopened; stop clears its hold".to_owned(),
                ));
            }
            let record = resume_in_txn(vault, wtxn, actor, attempt, input, now)?;
            (record, true, None)
        }
    };
    Ok(Released {
        view: ProgramHoldReleaseView {
            attempt: bytes_to_hex_lower(attempt.as_bytes()),
            action: input.action,
            released: park.reason,
            state: record.state.as_str().to_owned(),
            effected,
        },
        resumed: input.action == ProgramHoldReleaseAction::ResumeValidated,
        stopped,
    })
}

/// Ends `attempt` on the owner's grounds, unless it already settled, clears
/// the program's own park and abandons the try's Pending sends, an abandon
/// the ledger refuses being owed rather than refusing the Stop (FIX 7188).
/// `true` when this stop ended it.
fn stop_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    attempt: AttemptId,
    input: &ReleaseTurnProgramHoldRequest,
    now: u64,
) -> Result<(AttemptRecord, bool)> {
    let authority = ForceCancelAuthority::owner(actor.to_hex().as_str())?;
    let outcome = AttemptQueue::new(vault).force_cancel_in_txn(
        wtxn,
        ForceAttemptCancel {
            id: attempt,
            authority,
            reason: input.note.clone(),
            now,
        },
    )?;
    let (record, stopped) = match outcome {
        ForceCancelOutcome::Cancelled(record) => (record, true),
        ForceCancelOutcome::AlreadyCancelled(record)
        | ForceCancelOutcome::AlreadySettled(record) => (record, false),
    };
    PARKED.delete(&vault.store, wtxn, &attempt)?;
    abandon_stopped_sends_in_txn(vault, wtxn, attempt, now);
    Ok((record, stopped))
}

/// Resumes `attempt`'s hold as the same try once nothing holds it: its
/// checkpoint lines up with its run's record for the pin it binds, its
/// authority and pin stand, and nothing it did is unsettled. The owner's
/// intervention is recorded on its queue row first.
fn resume_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    attempt: AttemptId,
    input: &ReleaseTurnProgramHoldRequest,
    now: u64,
) -> Result<AttemptRecord> {
    let binding = match vault.bind_turn_program_in_txn(&*wtxn, attempt)? {
        TurnProgramBound::Bound(binding) => binding,
        TurnProgramBound::Lapsed(held) => return Err(not_resumed(held.reason())),
        TurnProgramBound::OwnerNotLive => {
            return Err(not_resumed(crate::authority::OWNER_NOT_LIVE));
        }
        TurnProgramBound::Withdrawn { reason } => {
            return Err(not_resumed(reason));
        }
    };
    if let Some(why) = vault.validate_program_resume_checkpoint_in_txn(
        &*wtxn,
        binding.code_run,
        binding.pin.skill,
        &binding.pin.content_hash,
        &binding.pin.contract_digest,
    )? {
        return Err(not_resumed(why));
    }
    if let Some(held) = resume_preflight_in_txn(vault, &*wtxn, attempt)? {
        return Err(not_resumed(held.reason()));
    }
    AttemptQueue::new(vault).intervene_in_txn(
        wtxn,
        InterveneAttempt {
            id: attempt,
            kind: AttemptInterventionKind::Interrupt,
            actor: actor.to_hex(),
            note: Some(input.note.clone().unwrap_or_else(|| RESUME_NOTE.to_owned())),
            now,
        },
    )?;
    let store = DreamerRunnerStore::new(vault);
    store
        .resume_parked_in_txn(wtxn, attempt, PROGRAM_PARK_OWNER, now)?
        .ok_or(Error::EntityNotFound)?;
    store
        .status_with_park_in_txn(&*wtxn, attempt)?
        .map(|(status, _)| status.attempt)
        .ok_or(Error::EntityNotFound)
}

fn not_resumed(why: &str) -> Error {
    Error::InvalidConfig(format!("the turn program does not resume: {why}"))
}

fn attempt_id(text: &str) -> Result<AttemptId> {
    let text = text.trim();
    let id = EntityId::from_hex(text.strip_prefix("job:").unwrap_or(text))
        .map_err(|_| Error::InvalidConfig("attempt must be a 32-hex attempt id".to_owned()))?;
    AttemptId::from_bytes(id.as_bytes())
}
