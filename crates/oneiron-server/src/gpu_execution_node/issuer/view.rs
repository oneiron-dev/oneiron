//! The four status fields of door 8 for a job the `vault_machine` backend runs (pass 33 row R4):
//! built from the job row, its chunk's `JOB_DISPATCH` and `JOB_OBSERVATION`, at the time asked.
//! An unreachable node is never read as gone: the newest receipt stands, marked stale, and the
//! money stays held (T26).

use oneiron::Vault;
use oneiron::gpu_job::{
    GpuJob, GpuJobAccounting, GpuJobLifecycle, GpuJobNodeReport, GpuJobNodeView, GpuJobObserved,
    GpuJobOutputView, GpuJobOutputsView, GpuJobState,
};
use oneiron::job_dispatch::{DispatchClose, JobDispatch, JobObservation};

use crate::gpu_execution_node::wire::{
    DeviceRelease, JobEnd, JobReceipt, JobState, OutputsState, SignedJobReceipt,
};

/// The view of `job` at `now_ms`, with the host's job step of `step_ms`; `None` when its chunk
/// was never dispatched by this issuer and its inputs name no machine.
#[must_use]
pub fn node_view(vault: &Vault, job: &GpuJob, now_ms: u64, step_ms: u64) -> Option<GpuJobNodeView> {
    let chunk = job.chunk()?;
    let dispatch = vault.job_dispatch(&chunk.idempotency_key).ok().flatten();
    let machine = match &dispatch {
        Some(row) => row.machine,
        None => {
            super::vault_machine_inputs(&chunk.quote.inputs)
                .ok()?
                .machine
        }
    };
    let observation = vault.job_observation(&chunk.idempotency_key).ok().flatten();
    let receipt = observation
        .as_ref()
        .and_then(|observation| {
            oneiron_organ_protocol::from_slice::<SignedJobReceipt>(&observation.receipt).ok()
        })
        .map(|signed| signed.receipt);
    // A setting that cannot be read counts as stale: the view never claims a fresh sight it
    // cannot judge.
    let stale_after_steps = vault
        .machine_job_settings(machine)
        .ok()
        .map(|settings| settings.stale_after_steps);
    let observed = observation.as_ref().map(|observation| {
        let ended = receipt
            .as_ref()
            .is_some_and(|receipt| receipt.state == JobState::Ended);
        let age_ms = now_ms.saturating_sub(observation.observed_at_ms);
        GpuJobObserved {
            at_ms: observation.observed_at_ms,
            stale: !ended
                && stale_after_steps
                    .is_none_or(|steps| age_ms > step_ms.saturating_mul(u64::from(steps))),
        }
    });
    Some(GpuJobNodeView {
        lifecycle: lifecycle_of(job, receipt.as_ref()),
        machine: machine.to_hex(),
        node: receipt.as_ref().map(report_of),
        accounting: accounting_of(job, dispatch.as_ref(), observation.as_ref(), observed),
        observed,
    })
}

/// Where the job stands, with the machine's newest receipt: a job the host runs whose key the
/// machine holds but has not launched (no receipt yet, or one whose workload never started and
/// is not running) is `assigned`. The job row alone cannot tell: its chunk gets its resource
/// in the same write that makes it `Running`.
fn lifecycle_of(job: &GpuJob, receipt: Option<&JobReceipt>) -> GpuJobLifecycle {
    match GpuJobLifecycle::of(job) {
        GpuJobLifecycle::Running
            if receipt
                .is_none_or(|receipt| !receipt.started && receipt.state != JobState::Running) =>
        {
            GpuJobLifecycle::Assigned
        }
        lifecycle => lifecycle,
    }
}

/// Where the money stands: settled once the job settled, or at zero once it ended unpaid;
/// written off; unconfirmed while the end cannot be confirmed (the node's history lost, a kill
/// it could not confirm, a node that does not answer an asked stop); else held.
fn accounting_of(
    job: &GpuJob,
    dispatch: Option<&JobDispatch>,
    observation: Option<&JobObservation>,
    observed: Option<GpuJobObserved>,
) -> GpuJobAccounting {
    let chunk = job.chunk();
    if dispatch.is_some_and(|row| matches!(row.closed, Some(DispatchClose::WrittenOff { .. }))) {
        return GpuJobAccounting::WrittenOff;
    }
    if let Some(units) = chunk.and_then(|chunk| chunk.settled_units) {
        return GpuJobAccounting::Settled { units };
    }
    // Over, and its chunk settled nothing: it ended unpaid (a host that lost its admission, a
    // refusal before any resource). Nothing holds its units any more, and it bills zero, as
    // the job's own `settled_units` sum counts it.
    if !job.state.is_live() {
        return GpuJobAccounting::Settled { units: 0 };
    }
    if dispatch.is_some_and(|row| row.history_lost_at_ms.is_some()) {
        return GpuJobAccounting::Unconfirmed {
            why: "history_lost".to_owned(),
        };
    }
    let receipt = observation.and_then(|observation| {
        oneiron_organ_protocol::from_slice::<SignedJobReceipt>(&observation.receipt).ok()
    });
    if receipt.as_ref().is_some_and(|signed| {
        matches!(signed.receipt.release, DeviceRelease::Unconfirmed { .. })
            && signed.receipt.state != JobState::Ended
    }) {
        return GpuJobAccounting::Unconfirmed {
            why: "kill_unconfirmed".to_owned(),
        };
    }
    if matches!(job.state, GpuJobState::Ending { .. }) && observed.is_none_or(|seen| seen.stale) {
        return GpuJobAccounting::Unconfirmed {
            why: "stop_not_confirmed".to_owned(),
        };
    }
    GpuJobAccounting::Held {
        units: chunk.map_or(0, |chunk| chunk.quote.units),
    }
}

/// The machine's receipt as the view shows it.
fn report_of(receipt: &JobReceipt) -> GpuJobNodeReport {
    let (end, end_detail) = receipt.end.as_ref().map_or((None, None), end_of);
    GpuJobNodeReport {
        state: state_name(receipt.state).to_owned(),
        started: receipt.started,
        end,
        end_detail,
        measured_secs: receipt.measured_secs,
        cutoff_at_ms: receipt.cutoff_at_ms,
        release: match &receipt.release {
            DeviceRelease::NotHeld => "not_held",
            DeviceRelease::Held => "held",
            DeviceRelease::Confirmed { .. } => "confirmed",
            DeviceRelease::Unconfirmed { .. } => "unconfirmed",
        }
        .to_owned(),
        outputs: match &receipt.outputs {
            OutputsState::Pending => GpuJobOutputsView::Pending,
            OutputsState::Hashed(outputs) => GpuJobOutputsView::Hashed {
                outputs: outputs
                    .iter()
                    .map(|output| GpuJobOutputView {
                        name: output.name.clone(),
                        sha256: output.sha256.clone(),
                        bytes: output.bytes,
                        returnable: output.returnable,
                    })
                    .collect(),
            },
            OutputsState::Failed { why } => GpuJobOutputsView::Failed { why: why.clone() },
        },
    }
}

fn state_name(state: JobState) -> &'static str {
    match state {
        JobState::Held => "held",
        JobState::Accepted => "accepted",
        JobState::Staging => "staging",
        JobState::Launching => "launching",
        JobState::Running => "running",
        JobState::Ending => "ending",
        JobState::Ended => "ended",
    }
}

/// An end's kind and detail.
fn end_of(end: &JobEnd) -> (Option<String>, Option<String>) {
    let (kind, detail) = match end {
        JobEnd::Exited { code } => ("exited", Some(code.to_string())),
        JobEnd::Signalled { signal } => ("signalled", Some(signal.to_string())),
        JobEnd::TimeLimit => ("time_limit", None),
        JobEnd::Continued => ("continued", None),
        JobEnd::MemoryLimit => ("memory_limit", None),
        JobEnd::DiskLimit => ("disk_limit", None),
        JobEnd::Stopped => ("stopped", None),
        JobEnd::Revoked => ("revoked", None),
        JobEnd::Withdrawn => ("withdrawn", None),
        JobEnd::Refused { reason } => ("refused", Some(reason.clone())),
        JobEnd::LaunchRefused { reason } => ("launch_refused", Some(reason.clone())),
        JobEnd::Lost { reason, .. } => ("lost", Some(reason.clone())),
    };
    (Some(kind.to_owned()), detail)
}
