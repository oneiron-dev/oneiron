//! Configured worker lookups and launch evidence.
use super::{ExternalWorker, HOST};
use crate::config::models::{ProviderConfig, WorkerConfig};
use oneiron::llm::{WorkerKind, WorkerMode};
use oneiron_driver::InferenceWorker;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::PoisonError;
use std::sync::atomic::Ordering;

/// The managed worker a rung on `provider` calling `wire_model` is bound
/// to, when this process launches it. `None` leaves the rung as it is today.
pub(in crate::models) fn managed_worker(
    provider: &str,
    wire_model: &str,
) -> Option<InferenceWorker> {
    let host = HOST.get()?;
    if !host.launch_permitted.load(Ordering::Relaxed) {
        return None;
    }
    let workers = host.lock();
    workers
        .values()
        .find(|hosted| {
            hosted.row.mode == WorkerMode::Managed
                && hosted.row.binding.provider == provider
                && hosted.row.binding.model == wire_model
        })
        .map(|hosted| hosted.worker.clone())
}

/// The external chat workers on `provider_name` bound at construction: for
/// each provided row that still matches its hosted row and provider exactly,
/// the actual worker and its row's manifest pin, keyed by wire model. A row
/// whose endpoint names a different target than its provider's base URL
/// stays out, as do media rows. The map holds bound workers and their pins
/// only, never secrets.
pub(in crate::models) fn external_workers(
    provider_name: &str,
    provider: &ProviderConfig,
    rows: &[WorkerConfig],
) -> BTreeMap<String, ExternalWorker> {
    let Some(host) = HOST.get() else {
        return BTreeMap::new();
    };
    let workers = host.lock();
    let mut bound = BTreeMap::new();
    for row in rows {
        if row.binding.provider != provider_name
            || row.mode != WorkerMode::External
            || row.endpoint.as_deref().is_some_and(|endpoint| {
                endpoint.trim_end_matches('/') != provider.base_url.trim_end_matches('/')
            })
            || !matches!(row.kind, WorkerKind::LlamaCpp | WorkerKind::Exl3)
        {
            continue;
        }
        let Some(hosted) = workers.get(&row.id) else {
            continue;
        };
        if hosted.row != *row || hosted.provider != *provider {
            continue;
        }
        bound.insert(
            row.binding.model.clone(),
            ExternalWorker {
                worker: hosted.worker.clone(),
                launch_manifest_sha256: hosted.row.launch_manifest_sha256.clone(),
            },
        );
    }
    bound
}

/// Whether `worker` is still its row's hosted supervisor: a replaced row's
/// old clone is not. The host lock is released before the caller probes.
pub(in crate::models) fn is_current(worker: &InferenceWorker) -> bool {
    HOST.get()
        .and_then(|host| {
            host.lock()
                .get(&worker.spec().worker_id)
                .map(|hosted| hosted.worker.same_instance(worker))
        })
        .unwrap_or(false)
}

/// Whether a managed EXL3 worker this process launches is bound to
/// `provider`: its chat transport then reaches that worker over its native
/// socket (`models/native_exl3`).
pub(in crate::models) fn serves_native(provider: &str) -> bool {
    let Some(host) = HOST.get() else {
        return false;
    };
    if !host.launch_permitted.load(Ordering::Relaxed) {
        return false;
    }
    host.lock()
        .values()
        .any(|hosted| hosted.native_slot().is_some() && hosted.row.binding.provider == provider)
}

/// What an HTTP answer from a managed EXL3 worker must echo to keep a
/// verified-artifacts claim (FIX 9296): the manifest digest of the launch
/// this host started and the epoch the worker qualified with, each absent
/// when that fact has no current record. Outer `None` is only a call no
/// managed EXL3 worker is bound to.
#[derive(Clone, Debug)]
pub(in crate::models) struct ManagedLaunchEvidence {
    pub(in crate::models) manifest_sha256: Option<String>,
    pub(in crate::models) backend_epoch: Option<String>,
}

/// The managed EXL3 worker bound to `provider` calling `wire_model`, as its
/// slot and readiness stand now, without waiting: `None` only when no
/// managed EXL3 worker is bound there. A bound worker with no launch record
/// or no ready epoch still returns `Some`, with those facts `None`, so its
/// answers downgrade verification instead of passing unfiltered. Two
/// snapshots racing only lose verification, never a refusal.
pub(in crate::models) fn managed_http_evidence(
    provider: &str,
    wire_model: &str,
) -> Option<ManagedLaunchEvidence> {
    let host = HOST.get()?;
    let (worker, slot) = {
        let workers = host.lock();
        let hosted = workers.values().find(|hosted| {
            hosted.native_slot().is_some()
                && hosted.row.binding.provider == provider
                && hosted.row.binding.model == wire_model
        })?;
        (hosted.worker.clone(), Arc::clone(hosted.native_slot()?))
    };
    let manifest_sha256 = slot
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map(|record| record.manifest_sha256.clone());
    let backend_epoch = match worker.status().readiness {
        oneiron::llm::WorkerReadiness::Ready { observed } => observed
            .identity
            .backend_epoch
            .as_ref()
            .map(|epoch| epoch.as_str().to_owned()),
        _ => None,
    };
    Some(ManagedLaunchEvidence {
        manifest_sha256,
        backend_epoch,
    })
}
