//! The grant-scoped forms of `vault.runs.step` and `vault.runs.checkpoint`
//! (primitive A, slice 6.4c; ENGINE CALL S64-3 = A: the same verb names), and
//! of `vault.code.reply_evidence` (RAW-PROVIDER-EVIDENCE-READ). The
//! owner reads as before. Any other caller reads a run it is the actor of,
//! through its own read lane: every claim, artifact and source the answer
//! derives from must read for it, as the existing caller projections judge.
//! A Steward of this shared vault (ARCH-0043's seventh role, #6886) reads
//! every run of its root the same way (slice 6.4f): it reads and organises
//! everything in this vault, through its own read lane all the same.

use crate::attempt_queue::AttemptId;
use crate::edge::EdgeActorClass;
use crate::engine_executor::checkpoint_read::{CheckpointReadRequest, CheckpointView};
use crate::engine_executor::reply_evidence::{ReplyEvidenceRequest, ReplyEvidenceView};
use crate::llm::model_step::{SettledStepRequest, SettledStepView};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::model_step_record::CallerSettledStep;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};

/// Whether `caller` is the actor attempt `attempt` runs as: an agent
/// dispatch's target, a resident attempt's resident, a turn program's waking
/// actor, or the Dreamer on its own stamp.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn is_attempt_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: WriteActor,
    attempt: AttemptId,
) -> Result<bool> {
    if let Some(record) = crate::store::attempt_record_read::get_in_txn(&vault.store, txn, attempt)?
        && let Some(input) = crate::agent_dispatch::record_dispatch_input(&record)
        && crate::agent_dispatch::agent_dispatch_actor(&input)? == caller
    {
        return Ok(true);
    }
    if vault.resident_actor_for_attempt_in_txn(txn, attempt)? == Some(caller)
        || vault.program_actor_for_attempt_in_txn(txn, attempt)? == Some(caller)
    {
        return Ok(true);
    }
    Ok(vault
        .dreamer_attempt_authority_in_txn(txn, attempt)?
        .is_some_and(|stamp| {
            caller.actor_class() == EdgeActorClass::System && stamp.actor == caller.entity_ref()
        }))
}

/// Whether `caller` is the actor code run `run` runs as: the actor a live
/// run was attached under, or a turn program's waking actor.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn is_code_run_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: WriteActor,
    run: &EntityId,
) -> Result<bool> {
    if vault
        .get_code_run_replay_record_in_txn(txn, run)?
        .and_then(|record| record.live_run)
        .is_some_and(|binding| binding.actor() == caller)
    {
        return Ok(true);
    }
    Ok(
        crate::dreamer_runner::program_run_actor_in_txn(&vault.store, txn, run)?
            == Some(caller.entity_ref()),
    )
}

/// Whether `caller` holds a live Steward grant over this shared vault, as
/// its membership standing reads in `txn`. A vault that is not shared has no
/// Steward.
///
/// # Errors
///
/// Storage errors, and a conflicted vault root.
pub(crate) fn is_steward_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: WriteActor,
) -> Result<bool> {
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(false);
    };
    Ok(matches!(
        vault.membership_standing_in_txn(txn, creation.vault_id, &caller.entity_ref())?,
        Some(crate::federation::MembershipStanding::Member {
            role: crate::federation::FederationGrantRole::Steward,
            ..
        })
    ))
}

fn caller_of(memory: &Memory<'_>) -> WriteActor {
    WriteActor::new(memory.actor(), memory.actor_class())
}

pub(crate) fn not_the_callers(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} reads the owner's runs, a Steward's, and the caller's own"),
        &["Call it as the vault's owner or a Steward, or for a run you are the actor of."],
    )
}

/// `vault.runs.step` for a caller other than the owner: one settled step of
/// an attempt the caller is the actor of, or of any attempt for a Steward.
/// `None` when no terminal claim records exactly this step.
///
/// # Errors
///
/// A malformed request; an attempt the caller is not the actor of, for a
/// caller that is no Steward, or a step
/// whose claim or response does not read for the caller (`FORBIDDEN`); and
/// storage errors.
pub fn settled_step_as_reader(
    memory: &Memory<'_>,
    input: &SettledStepRequest,
) -> MemoryResult<Option<SettledStepView>> {
    const VERB: &str = "vault.runs.step";
    let (attempt, step_hash) = crate::llm::settled_step_target(input)?;
    let own = {
        let txn = memory.vault().store.env.read_txn().map_err(Error::from)?;
        is_attempt_actor_in_txn(memory.vault(), &txn, caller_of(memory), attempt)?
            || is_steward_in_txn(memory.vault(), &txn, caller_of(memory))?
    };
    if !own {
        return Err(not_the_callers(VERB));
    }
    // The response as this reader reads it: a masked reader reads each
    // lifted key as its handle (review of #6968).
    match crate::llm::settled_step_for_reader(memory, attempt, step_hash)? {
        None => Ok(None),
        Some(CallerSettledStep::Readable(view)) => Ok(Some(*view)),
        Some(CallerSettledStep::Withheld { .. }) => Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the step's claim or response does not read for the caller",
            &[],
        )),
    }
}

/// `vault.runs.checkpoint` for a caller other than the owner: one page of a
/// code run the caller is the actor of, or of any code run for a Steward,
/// every source read through its lane.
///
/// # Errors
///
/// A malformed request; a run the caller is not the actor of, for a caller
/// that is no Steward, or a source
/// that does not read for it (`FORBIDDEN`); and storage errors.
pub fn checkpoint_as_reader(
    memory: &Memory<'_>,
    input: &CheckpointReadRequest,
) -> MemoryResult<Option<CheckpointView>> {
    const VERB: &str = "vault.runs.checkpoint";
    let run = EntityId::from_hex(input.run_ref.trim())
        .map_err(|_| MemoryError::bad_request("run_ref must be a 32-hex code-run id"))?;
    let own = {
        let txn = memory.vault().store.env.read_txn().map_err(Error::from)?;
        is_code_run_actor_in_txn(memory.vault(), &txn, caller_of(memory), &run)?
            || is_steward_in_txn(memory.vault(), &txn, caller_of(memory))?
    };
    if !own {
        return Err(not_the_callers(VERB));
    }
    crate::engine_executor::checkpoint_read::checkpoint_projection(memory, input)
}

/// `vault.code.reply_evidence` for a caller other than the owner: one step's
/// kept reply of a code run the caller is the actor of, or of any code run
/// for a Steward, every check of the read run on its own lane.
///
/// # Errors
///
/// A malformed request; a run the caller is not the actor of, for a caller
/// that is no Steward, or a source that does not read for it (`FORBIDDEN`);
/// and storage errors.
pub fn reply_evidence_as_reader(
    memory: &Memory<'_>,
    input: &ReplyEvidenceRequest,
) -> MemoryResult<Option<ReplyEvidenceView>> {
    const VERB: &str = "vault.code.reply_evidence";
    let run = crate::engine_executor::reply_evidence::reply_evidence_run(input)?;
    let own = {
        let txn = memory.vault().store.env.read_txn().map_err(Error::from)?;
        is_code_run_actor_in_txn(memory.vault(), &txn, caller_of(memory), &run)?
            || is_steward_in_txn(memory.vault(), &txn, caller_of(memory))?
    };
    if !own {
        return Err(not_the_callers(VERB));
    }
    crate::engine_executor::reply_evidence::reply_evidence_projection(memory, input)
}

/// `vault.runs.step` on an in-process handle: the embedded owner's read, or
/// [`settled_step_as_reader`] for any other caller.
///
/// # Errors
///
/// As the read it takes.
pub fn settled_step_embedded(
    memory: &Memory<'_>,
    input: &SettledStepRequest,
) -> MemoryResult<Option<SettledStepView>> {
    match memory.embedded_owner("vault.runs.step") {
        Ok(owner) => crate::llm::model_step::settled_step_as_owner(memory, &owner, input),
        Err(_) => settled_step_as_reader(memory, input),
    }
}

/// `vault.runs.checkpoint` on an in-process handle: the embedded owner's
/// read, or [`checkpoint_as_reader`] for any other caller.
///
/// # Errors
///
/// As the read it takes.
pub fn checkpoint_embedded(
    memory: &Memory<'_>,
    input: &CheckpointReadRequest,
) -> MemoryResult<Option<CheckpointView>> {
    match memory.embedded_owner("vault.runs.checkpoint") {
        Ok(owner) => {
            crate::engine_executor::checkpoint_read::checkpoint_as_owner(memory, &owner, input)
        }
        Err(_) => checkpoint_as_reader(memory, input),
    }
}

/// `vault.code.reply_evidence` on an in-process handle: the embedded owner's
/// read, or [`reply_evidence_as_reader`] for any other caller.
///
/// # Errors
///
/// As the read it takes.
pub fn reply_evidence_embedded(
    memory: &Memory<'_>,
    input: &ReplyEvidenceRequest,
) -> MemoryResult<Option<ReplyEvidenceView>> {
    match memory.embedded_owner("vault.code.reply_evidence") {
        Ok(owner) => {
            crate::engine_executor::reply_evidence::reply_evidence_as_owner(memory, &owner, input)
        }
        Err(_) => reply_evidence_as_reader(memory, input),
    }
}
