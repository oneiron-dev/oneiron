//! A queued browser program admission's run (CUA E8b; DESIGN-2 "The
//! Coach", row E8): the write origin each of its browser calls takes, built
//! only from the job's own leased try. No admitted binding fits such a job:
//! the agent-dispatch and live-run bindings are kind-specific, and a plain
//! dispatcher is no admission. Each call checks again that the try is a
//! browser program admission, still leased as its worker claimed it, and
//! that the job's source caller is the actor the call is made as. The run
//! is the job's own: no TASK host, no agent lease, no other run's origin.

use super::*;
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use crate::browser_library::{
    PROGRAM_ADMISSION_KIND, ProgramAdmissionJob, program_admission_job_id,
};
use crate::memory::{HostWriteOrigin, MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use crate::task_verb::sdk::AgentVerb;

impl<'a> HostSelfDispatcher<'a> {
    /// The write origin of browser call `verb` in the run of the admission
    /// job `leased` is, made as `actor` (CUA E8b): the job's run, read from
    /// its leased try as it stands now, never from the job's input.
    ///
    /// # Errors
    ///
    /// A verb that is no browser row; a try that is no browser program
    /// admission, or is no longer leased as `leased` holds it; a job whose
    /// source caller is not `actor`; storage errors.
    pub fn program_admission_origin(
        vault: &'a Vault,
        actor: WriteActor,
        leased: &AttemptRecord,
        verb: AgentVerb,
    ) -> MemoryResult<HostWriteOrigin> {
        if !verb.is_browser() {
            return Err(MemoryError::bad_request("a browser verb is required"));
        }
        let refused = || {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a program admission's run needs its own leased try, made as its source caller",
                &["Queue the admission again; a job runs once, on its own lease."],
            )
        };
        if leased.kind != PROGRAM_ADMISSION_KIND || leased.lease_owner.is_none() {
            return Err(refused());
        }
        let live = AttemptQueue::new(vault)
            .get(leased.id)?
            .ok_or_else(refused)?;
        if live.kind != PROGRAM_ADMISSION_KIND
            || live.state != AttemptState::Leased
            || live.lease_owner != leased.lease_owner
            || live.attempt_count != leased.attempt_count
        {
            return Err(refused());
        }
        let job = ProgramAdmissionJob::decode(&live)?;
        if job.scope.actor != actor.entity_ref()
            || job.scope.actor_class != actor.actor_class() as u8
        {
            return Err(refused());
        }
        let run = program_admission_job_id(&live)?;
        let dispatcher = Self::new(vault, actor, format!("browser-admission:{}", run.to_hex()))?;
        Ok(HostWriteOrigin::new(
            dispatcher.agent_verb_envelope(verb, None)?,
        ))
    }
}
