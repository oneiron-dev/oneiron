//! A turn program's reads (DOOR-141 PR3a, PR3b): what a landed turn's wakes
//! admitted, where one program's run stands, one settled step's exact
//! result and the resume checkpoint its restarter reads, each over the
//! caller's own credential read lane. The program's
//! waking actor or the verified owner reads its rows; every record a field
//! derives from reads on the caller's lane or is withheld. None executes,
//! admits, resumes or leases anything. Beside them, the owner's release of
//! a held program (FIX 5880), which takes the vault owner's proof as
//! `/v1/owner` takes it and rechecks it in its own write.
use std::sync::Arc;

use oneiron::dreamer_runner::{
    self, ProgramCheckpointRequest, ProgramCheckpointView, ProgramHoldReleaseView,
    ProgramRunRequest, ProgramRunView, ReleaseTurnProgramHoldRequest, SettledProgramStepRequest,
    SettledProgramStepView, TurnProgramAdmissionRequest, TurnProgramAdmissionView,
    program_checkpoint, program_run, settled_program_step, turn_program_admission,
};
use oneiron::memory::MemoryError;
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing};
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_turn_programs_admission(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: TurnProgramAdmissionRequest,
) -> Listed<Option<TurnProgramAdmissionView>> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.turn_programs.admission",
        move |_, _, memory| turn_program_admission(&memory, &input),
    )
    .await
}

pub(crate) async fn vault_runs_program(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ProgramRunRequest,
) -> Listed<Option<ProgramRunView>> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.runs.program",
        move |_, _, memory| program_run(&memory, &input),
    )
    .await
}

pub(crate) async fn vault_runs_program_step(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SettledProgramStepRequest,
) -> Listed<Option<SettledProgramStepView>> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.runs.program_step",
        move |_, _, memory| settled_program_step(&memory, &input),
    )
    .await
}

pub(crate) async fn vault_runs_program_checkpoint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ProgramCheckpointRequest,
) -> Listed<Option<ProgramCheckpointView>> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.runs.program_checkpoint",
        move |_, _, memory| program_checkpoint(&memory, &input),
    )
    .await
}

pub(crate) async fn vault_runs_program_hold_release(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ReleaseTurnProgramHoldRequest,
) -> Listed<ProgramHoldReleaseView> {
    as_owner_naming(
        server,
        auth,
        "vault.runs.program_hold.release",
        move |server, owner| {
            dreamer_runner::release_turn_program_hold_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}
