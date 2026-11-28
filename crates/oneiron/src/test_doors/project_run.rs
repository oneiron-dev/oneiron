//! Doors for `tests/turn_program_workflow.rs` ([RSI-PROJECT-WORKFLOW]): the
//! program runtime's own writers for one admitted turn program entry, with
//! no code host. A door leases the next queued program try and enters its
//! code run as the runtime does, then settles the entry, or settles one verb
//! write of it with the door's refusal, through the writers the runtime and
//! the dispatcher call.

use crate::agent_def::AgentAuthorLease;
use crate::attempt_queue::AttemptRecord;
use crate::code_run::CodeRunReplayGeneration;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore, ProgramWrite,
    TurnProgramBound, bind_program_write_in_txn, program_run_project_in_txn,
    settle_program_write_in_txn, turn_programs_armed_in_txn,
};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

const TEST_LEASE_OWNER: &str = "project-run-test";

/// Leases the next queued turn program try at `now` (the vault's recording
/// clock, seconds, as the drain that queued it took it) as the program
/// runtime does, and enters its code run. `None` when no program try is ready.
///
/// # Errors
///
/// The lease's or the entry's refusal; a try whose binding does not stand;
/// a store failure.
pub fn lease_program_entry(vault: &Vault, now: u64) -> Result<Option<AttemptRecord>> {
    let outcome = DreamerRunnerStore::new(vault).admit_next_turn_program(AdmitDreamerAttempt {
        lease_owner: TEST_LEASE_OWNER.to_owned(),
        now,
        budget_id: TEST_LEASE_OWNER.to_owned(),
        budget_total_units: 1_000_000,
        reserve_units: 1,
        started_milestone: None,
    })?;
    let DreamerAdmissionOutcome::Admitted(admitted) = outcome else {
        return Ok(None);
    };
    let attempt = admitted.status.attempt;
    let (admission, code_run) = bound(vault, &attempt)?;
    vault.enter_turn_program_run(&attempt, &admission, code_run, now)?;
    Ok(Some(attempt))
}

/// Settles the leased entry `attempt` finished, its pinned callable's root
/// call answering pending or not, in the runtime's settle writer.
///
/// # Errors
///
/// The settle's refusal; a store failure.
pub fn settle_program_entry(
    vault: &Vault,
    attempt: &AttemptRecord,
    pending: bool,
    now: u64,
) -> Result<()> {
    let (_, code_run) = bound(vault, attempt)?;
    let generation = CodeRunReplayGeneration {
        bridge_call_count: 0,
        step_checkpoint_count: 0,
        output_count: 0,
        last_state_hash: [0; 32],
        pending_digest: [0; 32],
    };
    vault.settle_turn_program_run(attempt, code_run, &generation, now, !pending)
}

/// Binds one verb write of the leased entry `attempt` before it runs, in a
/// commit of its own, then settles it with the door's refusal in the commit
/// that keeps its answer, as the dispatcher does.
///
/// # Errors
///
/// The bind's refusal (a moved lease, a lapsed authority); a store failure.
pub fn settle_refused_program_write(
    vault: &Vault,
    attempt: &AttemptRecord,
    now: u64,
) -> Result<()> {
    let (_, code_run) = bound(vault, attempt)?;
    let lease = AgentAuthorLease::from_leased(attempt)?;
    let write = ProgramWrite {
        attempt: lease.attempt,
        lease_owner: lease.owner,
        generation: lease.generation,
        code_run,
        step_start: 0,
        ordinal: 0,
        receipt: vault.new_entity_id()?,
        call_digest: [1; 32],
    };
    vault.with_write_txn_grouped(|wtxn| bind_program_write_in_txn(vault, wtxn, &write, now))?;
    vault.with_write_txn_grouped(|wtxn| {
        settle_program_write_in_txn(vault, wtxn, &write, [2; 32], true, now);
        Ok(())
    })
}

/// The project the code run of the leased entry `attempt` sends in.
///
/// # Errors
///
/// A try whose binding does not stand; a store failure.
pub fn entry_run_project(vault: &Vault, attempt: &AttemptRecord) -> Result<Option<EntityId>> {
    let (_, code_run) = bound(vault, attempt)?;
    let txn = vault.store.env.read_txn()?;
    program_run_project_in_txn(vault, &txn, &code_run)
}

/// Whether `actor` has any program armed.
///
/// # Errors
///
/// A store failure.
pub fn any_program_armed(vault: &Vault, actor: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    turn_programs_armed_in_txn(vault, &txn, actor)
}

/// The admission and code run the program try `attempt` is bound to.
fn bound(vault: &Vault, attempt: &AttemptRecord) -> Result<([u8; 32], EntityId)> {
    match vault.bind_turn_program_execution(attempt.id)? {
        TurnProgramBound::Bound(binding) => Ok((binding.admission, binding.code_run)),
        _ => Err(Error::InvalidClaimBody(
            "the program try's binding does not stand",
        )),
    }
}

/// A host write origin naming the agent `agent`, as the code-run dispatcher
/// stamps one host-side for a turn program entry's verb call: a `Generated`
/// envelope with empty provenance, proposed.
///
/// # Errors
///
/// The provenance payload's construction (never on this fixed value).
pub fn agent_write_origin(agent: EntityId) -> Result<crate::memory::HostWriteOrigin> {
    Ok(crate::memory::HostWriteOrigin::new(
        crate::WriteEnvelope::new(
            crate::WriteActor::new(agent, crate::EdgeActorClass::Agent),
            crate::ClaimSource::Generated,
            crate::WriteProvenance::new(rmpv::Value::Map(Vec::new()))?,
            crate::ClaimApprovalStatus::Proposed,
        ),
    ))
}
