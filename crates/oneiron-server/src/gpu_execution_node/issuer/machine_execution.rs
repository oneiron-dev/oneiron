//! The server half of `vault.machines.execution.get` (pass 33 door 11): the serving machine asks
//! each machine the engine named ([`MachineExecutionTarget`]) what it offers, its GPUs and the
//! keys it holds, over the issuer's job calls ([`JobNodeClient`]), and answers what each said.
//! It asks `oneiron/job/1` only under a held job grant and `oneiron/job-status/1` only under a
//! held status grant, every machine at once, and never itself. A machine that does not answer
//! is shown with the ask and the reason; nothing is retried and nothing is ranked.

use std::sync::Arc;

use oneiron::task_verb::sdk::{
    MachineAsk, MachineDiskReading, MachineExecution, MachineExecutionReply,
    MachineExecutionTarget, MachineGpuAvailability, MachineGpuDevice, MachineGpuState,
    MachineKeyState, MachineLiveKey, MachineNodeOffer, MachineScopeClass, MachineScopeReport,
    MachineTemplateOffer, MachineUnreachable,
};

use super::clock::IssuerClock;
use super::node_client::{JobNodeClient, NodeCallError};
use super::{job_answer_kind, job_refusal_code, status_answer_kind};
use crate::gpu_execution_node::availability::{
    GpuAvailability, GpuDeviceAvailability, GpuDeviceState, GpuDiskReading,
};
use crate::gpu_execution_node::wire::{
    JobAnswer, JobRequest, JobState, JobStatusAnswer, JobStatusRequest, NodeAnswer, ScopeClass,
    ScopeReport, TemplateOffer,
};
use crate::server::SyncServer;

/// The most pages of keys one read takes from one machine. A bound on one read, as
/// `FETCH_MAX_BYTES` bounds one fetch: a page stays under the transport's 1 MiB message bound,
/// so a machine that keeps naming a next page cannot hold the read open. Past it the machine is
/// shown unreachable on its keys.
pub const MACHINE_EXECUTION_KEY_PAGES_MAX: usize = 16;

/// The job calls this server makes for `vault.machines.execution.get`: over the vault's mesh,
/// on the runtime the caller runs on, each waiting at most the `vault_machine` backend's
/// `call_timeout_secs`.
#[cfg(feature = "mesh")]
#[must_use]
pub fn machine_execution_client(server: &Arc<SyncServer>) -> Box<dyn JobNodeClient> {
    let timeout =
        std::time::Duration::from_secs(server.config.gpu_jobs.vault_machine.call_timeout_secs);
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => Box::new(super::MeshJobNodeClient::new(
            Arc::downgrade(server),
            runtime,
            timeout,
        )),
        Err(_) => Box::new(NoJobCalls("no runtime serves this read")),
    }
}

/// The job calls of a server built without the mesh: every ask is unreachable.
#[cfg(not(feature = "mesh"))]
#[must_use]
pub fn machine_execution_client(_server: &Arc<SyncServer>) -> Box<dyn JobNodeClient> {
    Box::new(NoJobCalls("this server is built without the mesh"))
}

/// Job calls that reach no machine, with why.
struct NoJobCalls(&'static str);

impl JobNodeClient for NoJobCalls {
    fn job(
        &self,
        _node: oneiron::EntityId,
        _request: &JobRequest,
    ) -> Result<JobAnswer, NodeCallError> {
        Err(NodeCallError::Unreachable {
            reason: self.0.to_owned(),
        })
    }

    fn job_status(
        &self,
        _node: oneiron::EntityId,
        _request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError> {
        Err(NodeCallError::Unreachable {
            reason: self.0.to_owned(),
        })
    }
}

/// Asks every machine of `targets` that holds a job grant, at once, through `client`, and
/// answers each in `targets`' order. The calls block: run it on a blocking thread.
#[must_use]
pub fn read_machine_execution(
    client: &dyn JobNodeClient,
    clock: &dyn IssuerClock,
    targets: Vec<MachineExecutionTarget>,
) -> MachineExecutionReply {
    let machines = std::thread::scope(|scope| {
        let asks: Vec<_> = targets
            .into_iter()
            .map(|target| scope.spawn(move || read_machine(client, clock, &target)))
            .collect();
        asks.into_iter()
            .map(|ask| match ask.join() {
                Ok(machine) => machine,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    });
    MachineExecutionReply { machines }
}

/// One machine: its offer and its GPUs under the job grant, then its keys under the status
/// grant. A machine that cannot be reached on its offer is not asked again.
fn read_machine(
    client: &dyn JobNodeClient,
    clock: &dyn IssuerClock,
    target: &MachineExecutionTarget,
) -> MachineExecution {
    let mut machine = target.unasked();
    if !target.asked() {
        return machine;
    }
    machine.asked_at_ms = Some(clock.now_ms());
    let node = target.machine;
    if target.job_grant {
        match client.job(node, &JobRequest::Node) {
            Ok(JobAnswer::Node(offer)) => machine.node = Some(node_offer(&offer)),
            Ok(answer) => machine.unreachable = Some(refused(MachineAsk::Node, &answer)),
            Err(error) => {
                machine.unreachable = Some(no_answer(MachineAsk::Node, &error));
                return machine;
            }
        }
        if machine.node.is_some() {
            match client.job(node, &JobRequest::Availability) {
                Ok(JobAnswer::Availability(gpus)) => {
                    machine.availability = Some(gpu_availability(&gpus));
                }
                Ok(answer) => {
                    machine.unreachable = Some(refused(MachineAsk::Availability, &answer));
                }
                Err(error) => {
                    machine.unreachable = Some(no_answer(MachineAsk::Availability, &error));
                    return machine;
                }
            }
        }
    }
    if target.job_status_grant {
        match live_keys(client, node) {
            Ok(keys) => machine.live_keys = Some(keys),
            Err(unreachable) => {
                if machine.unreachable.is_none() {
                    machine.unreachable = Some(unreachable);
                }
            }
        }
    }
    machine
}

/// Every key `node` holds that has not ended, read page by page.
fn live_keys(
    client: &dyn JobNodeClient,
    node: oneiron::EntityId,
) -> Result<Vec<MachineLiveKey>, MachineUnreachable> {
    let mut keys = Vec::new();
    let mut after = None;
    for _ in 0..MACHINE_EXECUTION_KEY_PAGES_MAX {
        let page = match client.job_status(node, &JobStatusRequest::Keys { after }) {
            Ok(JobStatusAnswer::Keys(page)) => page,
            Ok(answer) => return Err(status_refused(&answer)),
            Err(error) => return Err(no_answer(MachineAsk::Keys, &error)),
        };
        keys.extend(page.entries.iter().filter_map(|entry| {
            key_state(entry.state).map(|state| MachineLiveKey {
                key: entry.key.clone(),
                state,
            })
        }));
        match page.next {
            None => return Ok(keys),
            Some(next) => after = Some(next),
        }
    }
    Err(MachineUnreachable {
        ask: MachineAsk::Keys,
        reason: format!("more than {MACHINE_EXECUTION_KEY_PAGES_MAX} pages of keys"),
    })
}

fn no_answer(ask: MachineAsk, error: &NodeCallError) -> MachineUnreachable {
    MachineUnreachable {
        ask,
        reason: error.to_string(),
    }
}

/// What the machine answered on `oneiron/job/1` in place of what was asked.
fn refused(ask: MachineAsk, answer: &JobAnswer) -> MachineUnreachable {
    let reason = match answer {
        JobAnswer::Refused(refusal) => job_refusal_code(refusal).to_owned(),
        JobAnswer::Busy { retry_after_ms } => format!("busy, retry after {retry_after_ms} ms"),
        other => format!("answered {}", job_answer_kind(other)),
    };
    MachineUnreachable { ask, reason }
}

/// What the machine answered on `oneiron/job-status/1` in place of a page of keys.
fn status_refused(answer: &JobStatusAnswer) -> MachineUnreachable {
    let reason = match answer {
        JobStatusAnswer::Refused(refusal) => job_refusal_code(refusal).to_owned(),
        JobStatusAnswer::Busy { retry_after_ms } => {
            format!("busy, retry after {retry_after_ms} ms")
        }
        other => format!("answered {}", status_answer_kind(other)),
    };
    MachineUnreachable {
        ask: MachineAsk::Keys,
        reason,
    }
}

/// A key's state while it has not ended; `None` once it has.
const fn key_state(state: JobState) -> Option<MachineKeyState> {
    Some(match state {
        JobState::Held => MachineKeyState::Held,
        JobState::Accepted => MachineKeyState::Accepted,
        JobState::Staging => MachineKeyState::Staging,
        JobState::Launching => MachineKeyState::Launching,
        JobState::Running => MachineKeyState::Running,
        JobState::Ending => MachineKeyState::Ending,
        JobState::Ended => return None,
    })
}

fn node_offer(answer: &NodeAnswer) -> MachineNodeOffer {
    MachineNodeOffer {
        enabled: answer.enabled,
        paused: answer.paused.clone(),
        drained: answer.drained.clone(),
        templates: answer.templates.iter().map(template_offer).collect(),
        scopes: answer.scopes.iter().map(scope_report).collect(),
        disk_free_bytes: answer.disk_free_bytes,
        disk_reserved_bytes: answer.disk_reserved_bytes,
        disk_reserve_bytes: answer.disk_reserve_bytes,
        swept: answer.swept,
        engine_version: answer.engine_version.clone(),
    }
}

fn template_offer(template: &TemplateOffer) -> MachineTemplateOffer {
    MachineTemplateOffer {
        name: template.name.clone(),
        digest: template.digest.clone(),
        scopes: template.scopes.iter().copied().map(scope_class).collect(),
        network: template.network.clone(),
        returnable: template.returnable.clone(),
        require: template.require.clone(),
    }
}

fn scope_report(scope: &ScopeReport) -> MachineScopeReport {
    MachineScopeReport {
        class: scope_class(scope.class),
        capabilities: scope.capabilities.clone(),
    }
}

const fn scope_class(class: ScopeClass) -> MachineScopeClass {
    match class {
        ScopeClass::Host => MachineScopeClass::Host,
        ScopeClass::Container => MachineScopeClass::Container,
    }
}

fn gpu_availability(gpus: &GpuAvailability) -> MachineGpuAvailability {
    MachineGpuAvailability {
        measured_at_ms: gpus.measured_at_ms,
        paused: gpus.paused.clone(),
        drained: gpus.drained.clone(),
        disk: gpus.disk.as_ref().map(disk_reading),
        devices: gpus.devices.iter().map(gpu_device).collect(),
    }
}

const fn disk_reading(disk: &GpuDiskReading) -> MachineDiskReading {
    MachineDiskReading {
        free_bytes: disk.free_bytes,
        reserve_bytes: disk.reserve_bytes,
        claimed_bytes: disk.claimed_bytes,
    }
}

fn gpu_device(gpu: &GpuDeviceAvailability) -> MachineGpuDevice {
    MachineGpuDevice {
        device: gpu.device.clone(),
        state: match &gpu.state {
            GpuDeviceState::Free => MachineGpuState::Free,
            GpuDeviceState::Busy { pids } => MachineGpuState::Busy { pids: pids.clone() },
            GpuDeviceState::Quarantined { why, key } => MachineGpuState::Quarantined {
                why: why.clone(),
                key: key.clone(),
            },
            GpuDeviceState::Leased { key } => MachineGpuState::Leased { key: key.clone() },
            GpuDeviceState::Launched { key } => MachineGpuState::Launched { key: key.clone() },
            GpuDeviceState::Withheld => MachineGpuState::Withheld,
            GpuDeviceState::NotOffered => MachineGpuState::NotOffered,
        },
    }
}
