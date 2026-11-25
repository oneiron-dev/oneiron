//! The issuer's half of `vault.machines.execution.get` (pass 33 door 11): the issuer asks each
//! machine the engine named ([`MachineExecutionTarget`]) what it offers and then its GPUs, under
//! the held `oneiron/job/1` grant, and the keys it holds, under the held `oneiron/job-status/1`
//! grant, through its job calls ([`JobNodeClient`]), and shows what each said. The two
//! protocols are asked apart: a machine whose job route refuses or does not answer is still
//! asked its keys (EM-1 = A). Every machine asked is asked at once, one thread each, as
//! `vault.machines.status` asks ([`super::node_status`]); the issuer never asks itself, and
//! nothing is retried or ranked.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::task_verb::sdk::{
    MachineDiskReading, MachineExecution, MachineExecutionReply, MachineExecutionTarget,
    MachineGpuAvailability, MachineGpuDevice, MachineGpuState, MachineGpuView, MachineKeyState,
    MachineKeysView, MachineLiveKey, MachineNodeView,
};

use super::clock::IssuerClock;
use super::node_client::{JobNodeClient, NodeCallError};
use super::node_status::node_view;
use super::{job_answer_kind, job_refusal_code, status_answer_kind};
use crate::gpu_execution_node::availability::{
    GpuAvailability, GpuDeviceAvailability, GpuDeviceState, GpuDiskReading,
};
use crate::gpu_execution_node::wire::{
    JobAnswer, JobRequest, JobState, JobStatusAnswer, JobStatusRequest,
};

/// The most pages of keys one read takes from one machine. A bound on one read, as
/// `FETCH_MAX_BYTES` bounds one fetch: a page stays under the transport's 1 MiB message bound,
/// so a machine that keeps naming a next page cannot hold the read open. Past it the keys are
/// `unknown`.
pub const MACHINE_EXECUTION_KEY_PAGES_MAX: usize = 16;

/// Asks every machine of `targets` that the issuer asks, at once, through `client`, and answers
/// each in `targets`' order. Where this server asks none (`client` is why: not the issuer, no
/// runtime, no mesh), each ask says why. A call that could not start leaves its machine's asks
/// `not_asked`; a call that failed leaves them `unknown`. The calls block: run it on a blocking
/// thread.
#[must_use]
pub fn read_machine_execution(
    client: Result<Arc<dyn JobNodeClient>, &'static str>,
    clock: &dyn IssuerClock,
    targets: Vec<MachineExecutionTarget>,
) -> MachineExecutionReply {
    let mut machines: Vec<MachineExecution> = targets
        .iter()
        .map(MachineExecutionTarget::unasked)
        .collect();
    let client = match client {
        Ok(client) => client,
        Err(why) => {
            for (shown, target) in machines.iter_mut().zip(&targets) {
                not_asked(shown, target, why);
            }
            return MachineExecutionReply { machines };
        }
    };
    let client = client.as_ref();
    let read: Vec<(usize, MachineExecution)> = std::thread::scope(|scope| {
        let calls: Vec<_> = targets
            .iter()
            .enumerate()
            .filter(|(_, target)| target.asks_offer() || target.asks_keys())
            .map(|(index, target)| {
                let call = std::thread::Builder::new()
                    .name("machine-execution".to_owned())
                    .spawn_scoped(scope, move || read_machine(client, clock, target));
                (index, call)
            })
            .collect();
        calls
            .into_iter()
            .map(|(index, call)| {
                let target = &targets[index];
                let mut shown = target.unasked();
                match call.map(std::thread::ScopedJoinHandle::join) {
                    Ok(Ok(read)) => shown = read,
                    Ok(Err(_)) => failed(&mut shown, target, clock.now_ms()),
                    Err(_) => not_asked(&mut shown, target, "call_not_started"),
                }
                (index, shown)
            })
            .collect()
    });
    for (index, shown) in read {
        machines[index] = shown;
    }
    MachineExecutionReply { machines }
}

/// Each ask the issuer makes of `target`, `not_asked` with `why`.
fn not_asked(shown: &mut MachineExecution, target: &MachineExecutionTarget, why: &str) {
    if target.asks_offer() {
        shown.node = MachineNodeView::not_asked(why);
        shown.availability = MachineGpuView::not_asked(why);
    }
    if target.asks_keys() {
        shown.live_keys = MachineKeysView::not_asked(why);
    }
}

/// Each ask the issuer makes of `target`, `unknown`: the call to the machine failed.
fn failed(shown: &mut MachineExecution, target: &MachineExecutionTarget, at_ms: u64) {
    let error = || "the call to the machine failed".to_owned();
    if target.asks_offer() {
        shown.node = MachineNodeView::unknown(error(), at_ms);
        shown.availability = MachineGpuView::unknown(error(), at_ms);
    }
    if target.asks_keys() {
        shown.live_keys = MachineKeysView::unknown(error(), at_ms);
    }
}

/// One machine: its offer and then its GPUs under the job grant, its keys under the status
/// grant. Its GPUs are asked only once it answered its offer.
fn read_machine(
    client: &dyn JobNodeClient,
    clock: &dyn IssuerClock,
    target: &MachineExecutionTarget,
) -> MachineExecution {
    let mut shown = target.unasked();
    let machine = target.machine;
    if target.asks_offer() {
        let asked_at_ms = clock.now_ms();
        let answer = client.job(machine, &JobRequest::Node);
        let offered = matches!(answer, Ok(JobAnswer::Node(_)));
        shown.node = node_view(answer, asked_at_ms);
        shown.availability = if offered {
            let asked_at_ms = clock.now_ms();
            gpu_view(client.job(machine, &JobRequest::Availability), asked_at_ms)
        } else {
            MachineGpuView::not_asked("offer_not_answered")
        };
    }
    if target.asks_keys() {
        shown.live_keys = keys_view(client, machine, clock.now_ms());
    }
    shown
}

/// What one `Availability` call says about the machine's GPUs.
fn gpu_view(answer: Result<JobAnswer, NodeCallError>, asked_at_ms: u64) -> MachineGpuView {
    match answer {
        Ok(JobAnswer::Availability(gpus)) => {
            MachineGpuView::answered(gpu_availability(&gpus), asked_at_ms)
        }
        Ok(JobAnswer::Refused(refusal)) => {
            MachineGpuView::refused(job_refusal_code(&refusal).to_owned(), asked_at_ms)
        }
        Ok(other) => MachineGpuView::unknown(
            format!("the machine answered {}", job_answer_kind(&other)),
            asked_at_ms,
        ),
        Err(error) => MachineGpuView::unknown(error.to_string(), asked_at_ms),
    }
}

/// Every key `machine` holds that has not ended, read page by page from `asked_at_ms`.
fn keys_view(client: &dyn JobNodeClient, machine: EntityId, asked_at_ms: u64) -> MachineKeysView {
    let mut keys = Vec::new();
    let mut after = None;
    for _ in 0..MACHINE_EXECUTION_KEY_PAGES_MAX {
        let page = match client.job_status(machine, &JobStatusRequest::Keys { after }) {
            Ok(JobStatusAnswer::Keys(page)) => page,
            Ok(JobStatusAnswer::Refused(refusal)) => {
                return MachineKeysView::refused(
                    job_refusal_code(&refusal).to_owned(),
                    asked_at_ms,
                );
            }
            Ok(other) => {
                return MachineKeysView::unknown(
                    format!("the machine answered {}", status_answer_kind(&other)),
                    asked_at_ms,
                );
            }
            Err(error) => return MachineKeysView::unknown(error.to_string(), asked_at_ms),
        };
        keys.extend(page.entries.iter().filter_map(|entry| {
            key_state(entry.state).map(|state| MachineLiveKey {
                key: entry.key.clone(),
                state,
            })
        }));
        match page.next {
            None => return MachineKeysView::answered(keys, asked_at_ms),
            Some(next) => after = Some(next),
        }
    }
    MachineKeysView::unknown(
        format!("more than {MACHINE_EXECUTION_KEY_PAGES_MAX} pages of keys"),
        asked_at_ms,
    )
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
