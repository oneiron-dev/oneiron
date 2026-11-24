//! The pinned workload doors (pass 33, section 6 rows 2-5):
//! `vault.jobs.workloads.pin`, `.approve`, `.revoke`, `.get` and `.list`.
//! The engine decides (`oneiron::job_workload`); a door admits the caller and
//! calls it. Every door takes the owner's own proof or an agent's own Grant
//! that names the verb. Approve and revoke take an agent only while the
//! owner's Setting `jobs.workloads.agent_may_approve` is on (off by default:
//! EN-1 A), and the owner's approve asks the owner's presence at `Important`.
//! Workloads live in a side table, which holds no entity row: the doors list
//! none.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::job_workload::{
    WorkloadAgent, WorkloadApproveRequest, WorkloadCaller, WorkloadChange, WorkloadList,
    WorkloadListRequest, WorkloadPinRequest, WorkloadRef, WorkloadVerb, WorkloadView,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

use super::super::FacadeApiError;
use super::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::gpu_host::now_ms;
use crate::server::SyncServer;

/// A workload door's caller, as the engine admitted it: the owner under
/// their own proof, or an agent under its own handle.
enum DoorCaller {
    Owner(AuthenticatedOwner),
    Agent(WorkloadAgent),
}

impl DoorCaller {
    fn caller(&self) -> WorkloadCaller<'_> {
        match self {
            Self::Owner(owner) => WorkloadCaller::Owner(owner),
            Self::Agent(agent) => WorkloadCaller::Agent(agent),
        }
    }
}

/// `act` off the runtime on the caller's own handle, after the engine admits
/// the caller to `verb`: the caller's own owner proof when its credential is
/// owner-grade, its agent handle otherwise.
async fn workload_door<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: WorkloadVerb,
    act: impl FnOnce(&SyncServer, &DoorCaller) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let caller = match crate::api::facade::facade_actor(server, auth)
        .map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    let owner = if auth.is_owner_grade() {
        match owner_proof(auth, server, verb.name()) {
            Ok(owner) => Some(owner),
            Err(error) => return (Err(error), Vec::new()),
        }
    } else {
        None
    };
    credential_listing(
        server,
        auth,
        caller,
        verb.name(),
        move |server, _, memory| {
            memory.workload_admits(owner.as_ref(), verb)?;
            let caller = match owner {
                Some(owner) => DoorCaller::Owner(owner),
                None => DoorCaller::Agent(memory.workload_agent()),
            };
            act(server, &caller)
        },
    )
    .await
}

/// The workload rows' early authority check (proof `job_workload_caller`):
/// the engine's admission of the caller for `verb`, the owner's own proof on
/// an owner-grade credential, else an agent's own Grant naming the verb,
/// judged before the row's verb hooks fire. The door admits the caller again
/// when it acts.
pub(super) fn job_workload_caller_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    let verb = WorkloadVerb::from_name(verb).ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is not a workload verb"),
            &[],
        )
    })?;
    let (actor, class) = crate::api::facade::facade_actor(server, auth)
        .map_err(FacadeApiError::into_memory_error)?;
    let owner = if auth.is_owner_grade() {
        Some(owner_proof(auth, server, verb.name())?)
    } else {
        None
    };
    crate::api::credential_memory(&server.vault, Some(auth), actor, class)
        .at(auth.locality())
        .workload_admits(owner.as_ref(), verb)
}

/// `vault.jobs.workloads.pin`: the owner, or an agent under its own Grant,
/// pins one exact workload. A pin approves nothing; pinning the same
/// workload again answers the pin that stands.
pub(crate) async fn vault_jobs_workloads_pin(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkloadPinRequest,
) -> Listed<WorkloadChange> {
    workload_door(server, auth, WorkloadVerb::Pin, move |server, caller| {
        Ok(server
            .vault
            .pin_job_workload(caller.caller(), &input, now_ms())?)
    })
    .await
}

/// `vault.jobs.workloads.approve`: the owner, or an agent while
/// `jobs.workloads.agent_may_approve` is on, approves one pinned workload on
/// the machines it may run on, for the Grants that may start it, until its
/// expiry. The owner's presence is asked at `Important` first.
pub(crate) async fn vault_jobs_workloads_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkloadApproveRequest,
) -> Listed<WorkloadChange> {
    workload_door(
        server,
        auth,
        WorkloadVerb::Approve,
        move |server, caller| {
            Ok(server
                .vault
                .approve_job_workload(caller.caller(), &input, now_ms())?)
        },
    )
    .await
}

/// `vault.jobs.workloads.revoke`: the owner, or an agent while
/// `jobs.workloads.agent_may_approve` is on, revokes one workload. No later
/// start passes the gate, and the issuer stops its running jobs.
pub(crate) async fn vault_jobs_workloads_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkloadRef,
) -> Listed<WorkloadChange> {
    workload_door(server, auth, WorkloadVerb::Revoke, move |server, caller| {
        Ok(server
            .vault
            .revoke_job_workload(caller.caller(), &input, now_ms())?)
    })
    .await
}

/// `vault.jobs.workloads.get`: one workload, as the caller may read it.
pub(crate) async fn vault_jobs_workloads_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkloadRef,
) -> Listed<WorkloadView> {
    workload_door(server, auth, WorkloadVerb::Get, move |server, caller| {
        Ok(server
            .vault
            .get_job_workload(caller.caller(), &input, now_ms())?)
    })
    .await
}

/// `vault.jobs.workloads.list`: every workload the caller may read, newest
/// pin first.
pub(crate) async fn vault_jobs_workloads_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: WorkloadListRequest,
) -> Listed<WorkloadList> {
    workload_door(server, auth, WorkloadVerb::List, move |server, caller| {
        Ok(server.vault.list_job_workloads(caller.caller(), now_ms())?)
    })
    .await
}
