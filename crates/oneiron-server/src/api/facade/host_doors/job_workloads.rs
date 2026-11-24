//! The pinned workload doors (pass 33, section 6 rows 2-5):
//! `vault.jobs.workloads.pin`, `.approve`, `.revoke`, `.get` and `.list`.
//! The engine decides (`oneiron::job_workload`); a door admits the caller and
//! calls it. Every door takes the owner's own proof or an agent's own Grant
//! that names the verb, but approve and revoke are the owner's own acts
//! (EN-1 A), and the owner's approve asks the owner's presence at `Important`.
//! Workloads live in a side table, which holds no entity row: the doors list
//! none, and the two reads keep no reply for a same-id retry
//! (`invocations::UNKEPT_REPLY_VERBS`), so visibility is judged at each read.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::job_workload::{
    PinSignals, ScreenVerdict, WorkloadAgent, WorkloadApproveRequest, WorkloadCaller,
    WorkloadChange, WorkloadList, WorkloadListRequest, WorkloadPinRequest, WorkloadRef,
    WorkloadScreen, WorkloadVerb, WorkloadView,
};
use oneiron::llm::decision::DecisionAnswer;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::AiVerdictRequest;

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
    act: impl FnOnce(&SyncServer, &Memory<'_>, &DoorCaller) -> MemoryResult<T> + Send + 'static,
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
            act(server, &memory, &caller)
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
/// pins one exact workload, and the pin checks in (pass 34, 6.5). Pinning
/// the same workload again answers the pin that stands, unless it waits.
pub(crate) async fn vault_jobs_workloads_pin(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkloadPinRequest,
) -> Listed<WorkloadChange> {
    workload_door(server, auth, WorkloadVerb::Pin, move |server, memory, _| {
        let screen = LadderScreen { server, memory };
        Ok(memory.pin_job_workload(&input, &screen, now_ms())?)
    })
    .await
}

/// The question the screen puts to the host's decision ladder for an
/// agent's pin no `compute.pin` grant covers (pass 34, 6.5). Its state is
/// the pin's [`PinSignals`].
const PIN_SCREEN_QUESTION: &str = "An agent asks to pin this workload to run on the owner's \
machines, outside any standing grant the owner gave its family. Answer yes only if it is routine \
for this agent: the same template and code it ran before, no larger than its earlier runs, with \
no network. Answer no for a new repository or template, a changed template, a much larger request \
or any network use.";

/// The pin's screen on the host's decision ladder, the path `ai.verdict`
/// takes, asked for the pinning caller and metered to its line. Sure is a
/// yes; a no, an abstain or another answer is unsure.
struct LadderScreen<'a, 'm> {
    server: &'a SyncServer,
    memory: &'a Memory<'m>,
}

impl WorkloadScreen for LadderScreen<'_, '_> {
    fn screen(&self, signals: &PinSignals) -> oneiron::Result<ScreenVerdict> {
        let state = serde_json::to_value(signals)
            .map_err(|_| oneiron::Error::InvariantViolation("pin signals encode"))?;
        let request: AiVerdictRequest = serde_json::from_value(serde_json::json!({
            "question": PIN_SCREEN_QUESTION,
            "state": state,
        }))
        .map_err(|_| oneiron::Error::InvariantViolation("the pin screen's verdict request"))?;
        let mut evidence_read = Vec::new();
        let verdict = crate::decision_verdict::run_verdict(
            self.server,
            self.memory.actor(),
            self.memory.actor_class(),
            self.memory,
            None,
            None,
            &request,
            None,
            &mut evidence_read,
            None,
        )
        .map_err(|error| {
            oneiron::Error::InvalidConfig(format!("the pin screen did not answer: {error}"))
        })?;
        Ok(ScreenVerdict {
            sure: matches!(verdict.answer, DecisionAnswer::Noul(true)),
            probability_permille: verdict.p.map(permille),
            rung: verdict.rung.and_then(|rung| {
                serde_json::to_value(rung)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
            }),
            receipt: Some(verdict.receipt.question.to_hex()),
        })
    }
}

/// `p`, a probability, in thousandths: 0 to 1000.
fn permille(p: f64) -> u16 {
    let scaled = (p.clamp(0.0, 1.0) * 1000.0).round();
    (0..=1000u16)
        .find(|step| f64::from(*step) >= scaled)
        .unwrap_or(1000)
}

/// `vault.jobs.workloads.approve`: the owner approves one pinned workload on
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
        move |server, _, caller| {
            Ok(server
                .vault
                .approve_job_workload(caller.caller(), &input, now_ms())?)
        },
    )
    .await
}

/// `vault.jobs.workloads.revoke`: the owner revokes one workload. No later
/// start passes the gate, and the issuer stops its running jobs.
pub(crate) async fn vault_jobs_workloads_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkloadRef,
) -> Listed<WorkloadChange> {
    workload_door(
        server,
        auth,
        WorkloadVerb::Revoke,
        move |server, _, caller| {
            Ok(server
                .vault
                .revoke_job_workload(caller.caller(), &input, now_ms())?)
        },
    )
    .await
}

/// `vault.jobs.workloads.get`: one workload, as the caller may read it.
pub(crate) async fn vault_jobs_workloads_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkloadRef,
) -> Listed<WorkloadView> {
    workload_door(server, auth, WorkloadVerb::Get, move |server, _, caller| {
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
    workload_door(
        server,
        auth,
        WorkloadVerb::List,
        move |server, _, caller| Ok(server.vault.list_job_workloads(caller.caller(), now_ms())?),
    )
    .await
}
