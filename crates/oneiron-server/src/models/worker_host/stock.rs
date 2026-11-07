//! The Coach's read-only view of the weight files for a captured managed
//! worker. It never installs, starts, probes or retargets a worker.
use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError};

use oneiron::llm::{WorkerKind, WorkerMode};
use oneiron_driver::InferenceWorker;
use serde_json::{Value, json};

use super::{HOST, Ordering, install};
use crate::config::models::{ProviderConfig, WorkerArtifact, WorkerConfig};
use crate::model_artifacts::install::{ArtifactStore, artifacts_root};

pub(in crate::models) struct StockWeights {
    worker: InferenceWorker,
    artifact: WorkerArtifact,
    store: Arc<ArtifactStore>,
}

/// Capture the exact hosted row and worker, as the call routes do. A later
/// reconfiguration cannot replace this runtime's evidence supplier.
pub(in crate::models) fn capture(
    rows: &[WorkerConfig],
    providers: &BTreeMap<String, ProviderConfig>,
) -> BTreeMap<String, StockWeights> {
    let Some(host) = HOST.get() else {
        return BTreeMap::new();
    };
    if !host.launch_permitted.load(Ordering::Relaxed) {
        return BTreeMap::new();
    }
    let mut unique = BTreeMap::new();
    for row in rows {
        unique
            .entry(row.model.as_str())
            .and_modify(|one| *one = false)
            .or_insert(true);
    }
    let captured: Vec<_> = {
        let workers = host.lock();
        rows.iter()
            .filter_map(|row| {
                if !unique[row.model.as_str()]
                    || row.mode != WorkerMode::Managed
                    || !matches!(row.kind, WorkerKind::LlamaCpp | WorkerKind::Exl3)
                {
                    return None;
                }
                let hosted = workers.get(&row.id)?;
                let provider = providers.get(&row.binding.provider)?;
                if hosted.row != *row || hosted.provider != *provider {
                    return None;
                }
                Some((row.clone(), hosted.worker.clone()))
            })
            .collect()
    };
    captured
        .into_iter()
        .filter_map(|(row, worker)| {
            let launch = row.launch?;
            let root = artifacts_root(launch.models_dir.as_deref()).ok()?;
            let store = {
                let mut stores = host.stores.lock().unwrap_or_else(PoisonError::into_inner);
                Arc::clone(
                    stores
                        .entry(root.clone())
                        .or_insert_with(|| Arc::new(ArtifactStore::new(root))),
                )
            };
            Some((
                row.model.as_str().to_owned(),
                StockWeights {
                    worker,
                    artifact: launch.weights,
                    store,
                },
            ))
        })
        .collect()
}

impl StockWeights {
    /// Every declared file must still match its size and SHA-256. The
    /// installer's existing stamp cache avoids hashing unchanged files.
    /// Unknown or mismatched files produce no positive claim; no network,
    /// repair, readiness check or inference call runs here.
    pub(in crate::models) fn read(&self) -> Option<Value> {
        let spec = self.worker.spec();
        let manifest = install::weights_manifest(&self.artifact, spec.kind, false).ok()?;
        let dir = match &self.artifact.offline_dir {
            Some(dir) => dir.clone(),
            None => self.store.install_dir(&manifest).ok()?,
        };
        let installed = self.store.verify_dir(&manifest, &dir).ok()?;
        Some(json!({
            "model": spec.model.as_str(),
            "worker": spec.worker_id,
            "manifest_sha256": installed.manifest_digest,
            "total_bytes": installed.total_bytes,
            "manifest": manifest,
        }))
    }
}
