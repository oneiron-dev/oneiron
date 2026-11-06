//! The drafter serving binding's half inside the worker host (FIX 14976):
//! which managed worker serves a drafter target here, and the supervised
//! restart that hands it a vault's own draft.
//!
//! A vault's draft is applied only to a managed EXL3 worker this process
//! launches, while this process serves one vault (a plain or embedded
//! serve). A managed per-vault process never launches the worker it calls:
//! that worker is another process's, shared by every vault. An external
//! worker is the operator's and is never restarted. There the binding is not
//! applied, the worker keeps what it serves, and the reason says why. No path
//! here rewrites a shared worker's draft or the configured row.
//!
//! Applying is the managed row replacement `configure` runs for a changed
//! row: a new supervisor, launched with the vault's verified load set as its
//! draft, takes the row, and its predecessor drains and stops before it
//! starts. The hosted row stays the configured one, so configuring the same
//! config again keeps the replacement, and a changed config replaces it with
//! stock.
//!
//! A drafter target matches a worker by its current launch's pins: the
//! target model is the backend model digest, the tokenizer the tokenizer
//! digest, and the runtime the worker kind's wire name (`exl3`).

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::drafter::{DrafterTarget, DrafterUnservedReason};
use oneiron::llm::run_admission::WorkContext;
use oneiron::llm::{
    CacheIdentity, ResourceClass, WorkCancel, WorkClass, WorkPhysical, WorkerKind, WorkerMode,
    WorkerReadiness,
};
use oneiron_driver::{InferenceWorker, WorkEnvelope, WorkRequest};

use super::{BoundWork, HOST, Hosted, LaunchSlot, is_current, stop_device_admission_if_unused};
use crate::config::models::{ArtifactSource, WorkerArtifact};
use crate::models::drafter_serving::{EXL3_DRAFTER_RUNTIME, VaultLoadSet};

/// A managed EXL3 worker this process may hand a vault's draft.
pub(in crate::models) struct DraftSeat {
    /// Its row's configured id.
    pub(in crate::models) worker_id: String,
    /// Its current supervisor.
    pub(in crate::models) worker: InferenceWorker,
    /// The vault load set that supervisor launches with; `None` for the
    /// row's stock draft.
    pub(in crate::models) draft: Option<Arc<VaultLoadSet>>,
}

/// Whether `identity` names `target`'s model and tokenizer.
fn names_target(identity: &CacheIdentity, target: &DrafterTarget) -> bool {
    identity
        .model
        .as_ref()
        .is_some_and(|model| model.as_str() == target.model)
        && identity
            .tokenizer
            .as_ref()
            .is_some_and(|tokenizer| tokenizer.as_str() == target.tokenizer)
}

/// The pins each worker row's last launch here named, by worker id: a
/// replacement that has not launched yet is matched by them.
static LAUNCHED_PINS: Mutex<BTreeMap<String, CacheIdentity>> = Mutex::new(BTreeMap::new());

fn launched_pins() -> MutexGuard<'static, BTreeMap<String, CacheIdentity>> {
    LAUNCHED_PINS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `hosted`'s current launch's pins, kept as row `id`'s last; `None` before
/// it launches.
fn current_launch_pins(id: &str, hosted: &Hosted) -> Option<CacheIdentity> {
    let pins = hosted.slot.as_ref().and_then(|slot| {
        slot.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|record| record.pins.clone())
    })?;
    launched_pins().insert(id.to_owned(), pins.clone());
    Some(pins)
}

/// What row `id`'s worker serves as its identity: its current launch's
/// pins, else its row's last launch's here, else what its last
/// qualification observed, else its row's configured pins.
fn served_identity(id: &str, hosted: &Hosted) -> CacheIdentity {
    if let Some(pins) = current_launch_pins(id, hosted) {
        return pins;
    }
    if let Some(pins) = launched_pins().get(id) {
        return pins.clone();
    }
    match hosted.worker.status().readiness {
        WorkerReadiness::Ready { observed } => observed.identity,
        _ => hosted.row.expected.clone(),
    }
}

/// The managed EXL3 worker of this process that serves `target`, when a
/// vault's draft may be applied to it; `vaults` is how many vaults this
/// process serves drafters for. Otherwise why not, the most precise reason
/// any row gives.
pub(in crate::models) fn draft_seat(
    target: &DrafterTarget,
    vaults: usize,
) -> Result<DraftSeat, DrafterUnservedReason> {
    let Some(host) = HOST.get() else {
        return Err(DrafterUnservedReason::NoServingWorker);
    };
    let permitted = host.launch_permitted.load(Ordering::SeqCst);
    let workers = host.lock();
    let mut refused = None;
    for (id, hosted) in workers.iter() {
        let row = &hosted.row;
        if !matches!(row.kind, WorkerKind::Exl3 | WorkerKind::LlamaCpp) {
            continue;
        }
        let managed_exl3 = row.mode == WorkerMode::Managed && row.kind == WorkerKind::Exl3;
        if managed_exl3 && !permitted && target.runtime == EXL3_DRAFTER_RUNTIME {
            // A managed per-vault process: the worker it calls is launched
            // by another process, for every vault.
            refused = refused.or(Some(DrafterUnservedReason::UnsupportedSharedWorker));
            continue;
        }
        if !names_target(&served_identity(id, hosted), target) {
            continue;
        }
        if row.mode == WorkerMode::External {
            refused = Some(DrafterUnservedReason::UnsupportedExternalWorker);
            continue;
        }
        if row.kind != WorkerKind::Exl3 || target.runtime != EXL3_DRAFTER_RUNTIME {
            refused = Some(DrafterUnservedReason::UnsupportedRuntime);
            continue;
        }
        if vaults != 1 {
            refused = Some(DrafterUnservedReason::UnsupportedSharedWorker);
            continue;
        }
        if row
            .launch
            .as_ref()
            .is_none_or(|launch| launch.draft.is_none())
        {
            // The deployment serves this target with no draft at all.
            refused = refused.or(Some(DrafterUnservedReason::NoServingWorker));
            continue;
        }
        return Ok(DraftSeat {
            worker_id: id.clone(),
            worker: hosted.worker.clone(),
            draft: hosted.draft.clone(),
        });
    }
    Err(refused.unwrap_or(DrafterUnservedReason::NoServingWorker))
}

/// The drafter target a nightly retrain exports its corpus for (FIX
/// 14973): the first managed EXL3 worker this process launches whose row
/// serves a draft, by the model and tokenizer it serves. `None` when this
/// process launches none: a managed per-vault process, only external or
/// llama.cpp workers, or no draft at all.
pub(in crate::models) fn retrain_target() -> Option<DrafterTarget> {
    let host = HOST.get()?;
    if !host.launch_permitted.load(Ordering::SeqCst) {
        return None;
    }
    let workers = host.lock();
    workers.iter().find_map(|(id, hosted)| {
        let row = &hosted.row;
        if row.mode != WorkerMode::Managed || row.kind != WorkerKind::Exl3 {
            return None;
        }
        if row
            .launch
            .as_ref()
            .is_none_or(|launch| launch.draft.is_none())
        {
            return None;
        }
        let identity = served_identity(id, hosted);
        Some(DrafterTarget {
            model: identity.model?.as_str().to_owned(),
            tokenizer: identity.tokenizer?.as_str().to_owned(),
            runtime: EXL3_DRAFTER_RUNTIME.to_owned(),
        })
    })
}

/// The resource class a drafter training job queues under on its device:
/// the chat target's, whose GPU it shares.
const DRAFTER_TRAINING_RESOURCE: ResourceClass = ResourceClass::Chat;

/// A drafter training job's ticket on the device work line of the managed
/// EXL3 worker this process launches for `target` (FIX 14974): background
/// work of `envelope`, held by `holder`, on the same line that worker's
/// calls queue on, so the device admission decides when it runs beside
/// serving and may unload an idle worker to make room. `None` where this
/// process launches no such worker or its row names no device: the job then
/// runs unmediated, as a call to such a row does.
pub(in crate::models) fn drafter_training_work(
    target: &DrafterTarget,
    holder: &str,
    envelope: WorkEnvelope,
    cancel: &WorkCancel,
) -> Option<BoundWork> {
    let host = HOST.get()?;
    if !host.launch_permitted.load(Ordering::SeqCst) {
        return None;
    }
    let device = {
        let workers = host.lock();
        workers.iter().find_map(|(id, hosted)| {
            let row = &hosted.row;
            if row.mode != WorkerMode::Managed
                || row.kind != WorkerKind::Exl3
                || !names_target(&served_identity(id, hosted), target)
            {
                return None;
            }
            row.launch.as_ref()?.device.clone()
        })?
    };
    let admission = host.admission(&device);
    let mut request = WorkRequest::new(holder, DRAFTER_TRAINING_RESOURCE, holder);
    request.class = WorkClass::Background;
    request.physical = WorkPhysical::KeylessOwnServer;
    request.deadline = None;
    request.envelope = envelope;
    request.cancel = cancel.shared();
    request.cancel_changed = cancel.shared_notify();
    let ticket = admission.enqueue(request);
    Some(BoundWork {
        ticket: Some(ticket),
        context: WorkContext {
            class: WorkClass::Background,
            physical: WorkPhysical::KeylessOwnServer,
            cancel: cancel.clone(),
            ..WorkContext::default()
        },
        armed: true,
    })
}

/// Hands `worker_id`'s managed EXL3 row a new supervisor whose launch loads
/// `draft` in place of the row's stock draft (the stock one for `None`),
/// through the managed row replacement: the predecessor drains and stops,
/// then the new one starts. Returns the new supervisor, or the current one
/// when it already launches `draft`. `None` when the row is no managed EXL3
/// row this process launches, or off a Tokio runtime.
pub(in crate::models) fn replace_draft(
    worker_id: &str,
    draft: Option<Arc<VaultLoadSet>>,
) -> Option<InferenceWorker> {
    let host = HOST.get()?;
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    if !host.launch_permitted.load(Ordering::SeqCst) {
        return None;
    }
    let (old, new, old_device) = {
        let mut workers = host.lock();
        let hosted = workers.get(worker_id)?;
        if hosted.row.mode != WorkerMode::Managed || hosted.row.kind != WorkerKind::Exl3 {
            return None;
        }
        if hosted.draft == draft {
            return Some(hosted.worker.clone());
        }
        let row = hosted.row.clone();
        let provider = hosted.provider.clone();
        let mut launch_row = row.clone();
        if let (Some(launch), Some(set)) = (launch_row.launch.as_mut(), draft.as_ref()) {
            launch.draft = Some(WorkerArtifact {
                source: ArtifactSource::VaultLoadSet(Arc::clone(set)),
                offline_dir: Some(set.dir.clone()),
            });
        }
        let (worker, slot) = host.supervisor(&launch_row, &provider);
        let worker = worker.with_predecessor(&hosted.worker);
        let replacement = Hosted {
            row,
            provider,
            worker: worker.clone(),
            slot,
            draft,
        };
        let old = workers.insert(worker_id.to_owned(), replacement)?;
        let old_device = old
            .row
            .launch
            .as_ref()
            .and_then(|launch| launch.device.clone());
        (old.worker, worker, old_device)
    };
    let started = new.clone();
    runtime.spawn(async move {
        old.retire().await;
        if let Some(device) = old_device {
            stop_device_admission_if_unused(host, &device);
        }
        host.begin(&new);
    });
    Some(started)
}

/// Each hosted row whose supervisor launches a load set of vault `vault`,
/// by its worker id.
pub(in crate::models) fn vault_drafts(vault: &[u8; 32]) -> Vec<(String, Arc<VaultLoadSet>)> {
    let Some(host) = HOST.get() else {
        return Vec::new();
    };
    host.lock()
        .iter()
        .filter_map(|(id, hosted)| {
            let draft = hosted.draft.as_ref()?;
            (draft.vault == *vault).then(|| (id.clone(), Arc::clone(draft)))
        })
        .collect()
}

/// Returns to stock every hosted row whose supervisor launches a vault's own
/// load set: vault `vault`'s, or any vault's for `None`. Returns how many
/// rows were replaced.
pub(in crate::models) fn clear_vault_drafts(vault: Option<&[u8; 32]>) -> usize {
    let Some(host) = HOST.get() else {
        return 0;
    };
    let rows: Vec<String> = host
        .lock()
        .iter()
        .filter(|(_, hosted)| {
            hosted
                .draft
                .as_ref()
                .is_some_and(|draft| vault.is_none_or(|vault| draft.vault == *vault))
        })
        .map(|(id, _)| id.clone())
        .collect();
    rows.iter()
        .filter(|id| replace_draft(id, None).is_some())
        .count()
}

/// Waits until every managed EXL3 worker this process launches has a launch
/// record, against whose pins a target is matched, or has failed. A row
/// launched here before (a replacement not launched yet) does not wait: its
/// last launch's pins match. At once where this process launches none.
pub(in crate::models) async fn launch_records() {
    let Some(host) = HOST.get() else {
        return;
    };
    if !host.launch_permitted.load(Ordering::SeqCst) {
        return;
    }
    let pending: Vec<(InferenceWorker, Arc<LaunchSlot>)> = {
        let workers = host.lock();
        let mut pending = Vec::new();
        for (id, hosted) in workers.iter() {
            let Some(slot) = hosted.native_slot() else {
                continue;
            };
            if current_launch_pins(id, hosted).is_none() && !launched_pins().contains_key(id) {
                pending.push((hosted.worker.clone(), Arc::clone(slot)));
            }
        }
        pending
    };
    for (worker, slot) in pending {
        loop {
            let mut changes = worker.subscribe_changed();
            let recorded = slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some();
            let failed = matches!(worker.status().readiness, WorkerReadiness::Failed { .. });
            if recorded || failed || !is_current(&worker) {
                break;
            }
            if changes.changed().await.is_err() {
                break;
            }
        }
    }
}
