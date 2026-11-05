//! Worker device reports and runtime status snapshots.
use super::{HOST, session};
use oneiron::llm::{InferenceCallReceipt, WorkerMode, WorkerStatus};
use oneiron_driver::{ExecutorRegistration, InferenceWorker, WorkerActivity};
use serde_json::Value as JsonValue;
use std::sync::PoisonError;
use std::sync::atomic::Ordering;

/// Retains a sanitized physical receipt on the worker that made it.
pub(in crate::models) fn report_receipt(
    worker_id: &str,
    epoch: &str,
    receipt: InferenceCallReceipt,
) {
    if let Some(host) = HOST.get() {
        if let Some(hosted) = host.lock().get(worker_id) {
            hosted.worker.record_receipt(epoch, receipt);
        }
    }
}

/// Registers or refreshes one executor's idle row. Managed custody exists
/// only when this process may launch that worker; other work is recorded as
/// external and is never an unload target. Only the row's hosted instance
/// registers (FIX 13845): a replaced row's old clone registers nothing.
pub(in crate::models) fn register_device_executor(worker: &InferenceWorker, idle: bool) {
    let Some(host) = HOST.get() else {
        return;
    };
    let worker_id = worker.spec().worker_id.as_str();
    let workers = host.lock();
    let Some((device, external)) = workers
        .get(worker_id)
        .filter(|hosted| hosted.worker.same_instance(worker))
        .and_then(|hosted| {
            let device = hosted.row.launch.as_ref()?.device.clone()?;
            let managed = hosted.row.mode == WorkerMode::Managed
                && host.launch_permitted.load(Ordering::SeqCst);
            Some((device, !managed))
        })
    else {
        return;
    };
    host.admission(&device)
        .register_executor(ExecutorRegistration {
            worker_id: worker_id.to_owned(),
            external,
            idle,
        });
}

/// Publishes one worker-reported activity snapshot to both admission and
/// the supervisor without deriving either side from the other.
pub(in crate::models) fn report_device_activity(
    worker: &InferenceWorker,
    activity: WorkerActivity,
) {
    register_device_executor(worker, activity.is_idle());
    worker.report(activity);
}

/// Cross-checks a worker's own device capacity report with the pre-load
/// query. The first valid report fills an unknown; a mismatch keeps the
/// device query and logs rather than silently rewriting capacity. Only the
/// row's hosted instance reports (FIX 13884): a replaced row's old clone
/// fills nothing.
pub(in crate::models) fn report_device_stats(worker: &InferenceWorker, stats: &JsonValue) {
    let Some(host) = HOST.get() else {
        return;
    };
    let worker_id = worker.spec().worker_id.as_str();
    let workers = host.lock();
    let Some(device) = workers
        .get(worker_id)
        .filter(|hosted| hosted.worker.same_instance(worker))
        .and_then(|hosted| hosted.row.launch.as_ref()?.device.clone())
    else {
        return;
    };
    let ledger = host.ledger(&device);
    let rows = stats.get("devices").and_then(JsonValue::as_array);
    let cuda_device = format!("cuda:{device}");
    let row = rows.and_then(|rows| {
        rows.iter()
            .find(|row| {
                row.get("device")
                    .and_then(JsonValue::as_str)
                    .is_some_and(|name| name == device.as_str() || name == cuda_device.as_str())
            })
            .or_else(|| (rows.len() == 1).then(|| rows.first()).flatten())
    });
    let Some(bytes) = row
        .and_then(|row| row.get("capacity_bytes"))
        .and_then(JsonValue::as_u64)
    else {
        return;
    };
    let capacity = bytes.saturating_add((1_u64 << 20) - 1) / (1_u64 << 20);
    match ledger.capacity() {
        None => ledger.set_capacity(Some(capacity)),
        Some(existing) if existing != capacity => {
            tracing::warn!(worker = worker_id, device = %device, existing, reported = capacity, "worker and host device capacities differ");
        }
        Some(_) => {}
    }
}

/// Takes up the configured `[models.sessions]` policy (I1 = C).
pub(in crate::models) fn prepare_policy(
    policy: crate::config::models::sessions::SessionPreparePolicy,
) {
    #[cfg(unix)]
    session::set_prepare_policy(policy);
    #[cfg(not(unix))]
    let _ = policy;
}

/// The next turn's prepared tails as this process stands; `None` off Unix.
pub(in crate::models) fn prepared_tail_status() -> Option<super::super::status::PreparedTailStatus>
{
    #[cfg(unix)]
    let status = Some(session::prepared_tail_status());
    #[cfg(not(unix))]
    let status = None;
    status
}

/// Sealed snapshot parking as this process stands; `None` off Unix.
pub(in crate::models) fn snapshot_status() -> Option<super::super::SnapshotStatus> {
    #[cfg(unix)]
    let status = Some(session::snapshot_status());
    #[cfg(not(unix))]
    let status = None;
    status
}

/// Each row's status as its supervisor holds it now.
pub(in crate::models) fn refresh(statuses: &mut [WorkerStatus]) {
    let Some(host) = HOST.get() else {
        return;
    };
    let workers = host.lock();
    for status in statuses {
        if let Some(hosted) = workers.get(&status.worker_id) {
            *status = hosted.worker.status();
        }
    }
}

/// Copies every device queue and ledger into owner-facing status. No probe.
pub(in crate::models) fn refresh_devices(statuses: &mut Vec<super::super::status::DeviceStatus>) {
    let Some(host) = HOST.get() else {
        statuses.clear();
        return;
    };
    let admissions = host
        .admissions
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .values()
        .cloned()
        .collect::<Vec<_>>();
    *statuses = admissions
        .into_iter()
        .map(|admission| super::super::status::DeviceStatus::from_snapshot(admission.snapshot()))
        .collect();
}
