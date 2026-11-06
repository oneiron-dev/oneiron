//! The drafter evaluator's incarnations (FIX 14975): managed EXL3 workers
//! launched from the vault's own serving row, each with the draft one arm of
//! an evaluation names (the target alone, the stock draft, or a vault's own
//! load set), on the same target, runtime, template, settings and depth.
//!
//! An evaluator incarnation is never a hosted row: no route, no ladder and
//! no other vault reaches it, so no serving call is ever sent to it. It runs
//! under its own row id (the serving row's, then [`EVALUATOR_ROW_SUFFIX`]),
//! listens on a loopback port of its own and answers its own native socket;
//! the launch, its verification, its qualification and device admission are
//! the managed row's own, through the same supervisor. It is only made where
//! a vault's draft may be applied ([`super::draft_seat`]): a managed EXL3
//! worker this process launches for its one vault.
//!
//! A vault lock retires every evaluator incarnation of the vault
//! ([`retire_vault_evaluators`]) before its plaintext goes.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::drafter::{DrafterTarget, DrafterUnservedReason};
use oneiron_driver::InferenceWorker;

use super::{HOST, LaunchSlot, draft_seat, stop_device_admission_if_unused};
use crate::config::models::{ArtifactSource, ProviderConfig, WorkerArtifact, WorkerConfig};
use crate::models::drafter_serving::VaultLoadSet;

/// What an evaluator incarnation's row id ends with, after its serving
/// row's id.
const EVALUATOR_ROW_SUFFIX: &str = "-drafter-eval";

/// Each live evaluator incarnation, by its row id: its vault and its
/// supervisor.
static EVALUATORS: Mutex<BTreeMap<String, ([u8; 32], InferenceWorker)>> =
    Mutex::new(BTreeMap::new());

fn evaluators() -> MutexGuard<'static, BTreeMap<String, ([u8; 32], InferenceWorker)>> {
    EVALUATORS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The serving row an evaluation's incarnations are launched from.
pub(in crate::models) struct EvaluatorSeat {
    worker_id: String,
    row: WorkerConfig,
    provider: ProviderConfig,
}

impl EvaluatorSeat {
    /// The provider the row is bound to.
    pub(in crate::models) fn provider(&self) -> &ProviderConfig {
        &self.provider
    }

    /// The provider's configured name.
    pub(in crate::models) fn provider_name(&self) -> &str {
        &self.row.binding.provider
    }

    /// The wire model the row serves.
    pub(in crate::models) fn wire_model(&self) -> &str {
        &self.row.binding.model
    }

    /// The row's current serving supervisor and its current launch's native
    /// socket, when it has one: what an observation after an activation
    /// replays on.
    pub(in crate::models) fn serving_endpoint(&self) -> Option<(InferenceWorker, PathBuf)> {
        let host = HOST.get()?;
        let workers = host.lock();
        let hosted = workers.get(&self.worker_id)?;
        let socket = hosted
            .native_slot()?
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()?
            .native_socket
            .clone()?;
        Some((hosted.worker.clone(), socket))
    }
}

/// What drafts in one evaluator incarnation.
pub(in crate::models) enum EvaluatorDraft {
    /// No draft: the target alone.
    TargetOnly,
    /// The row's configured stock draft.
    Stock,
    /// A vault's own load set, verified at the launch's install.
    Vault(Arc<VaultLoadSet>),
}

/// One live evaluator incarnation.
pub(in crate::models) struct EvaluatorIncarnation {
    row_id: String,
    worker: InferenceWorker,
    slot: Arc<LaunchSlot>,
    device: Option<String>,
}

impl EvaluatorIncarnation {
    pub(in crate::models) fn worker(&self) -> &InferenceWorker {
        &self.worker
    }

    /// Its current launch's native socket; `None` before it launched or
    /// where the launch has none.
    pub(in crate::models) fn socket(&self) -> Option<PathBuf> {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()?
            .native_socket
            .clone()
    }

    /// The digest of its current launch's manifest.
    pub(in crate::models) fn manifest_sha256(&self) -> Option<String> {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|record| record.manifest_sha256.clone())
    }

    /// Drains and stops it, and gives its device back.
    pub(in crate::models) async fn retire(self) {
        self.worker.retire().await;
        evaluators().remove(&self.row_id);
        if let (Some(host), Some(device)) = (HOST.get(), self.device.as_deref()) {
            stop_device_admission_if_unused(host, device);
        }
    }
}

/// The serving row of this process an evaluation of `target` launches its
/// incarnations from, as [`super::draft_seat`] finds it; `vaults` is how many
/// vaults this process serves drafters for. Otherwise why not.
pub(in crate::models) fn evaluator_seat(
    target: &DrafterTarget,
    vaults: usize,
) -> Result<EvaluatorSeat, DrafterUnservedReason> {
    let seat = draft_seat(target, vaults)?;
    let host = HOST.get().ok_or(DrafterUnservedReason::NoServingWorker)?;
    let workers = host.lock();
    let hosted = workers
        .get(&seat.worker_id)
        .ok_or(DrafterUnservedReason::NoServingWorker)?;
    Ok(EvaluatorSeat {
        worker_id: seat.worker_id.clone(),
        row: hosted.row.clone(),
        provider: hosted.provider.clone(),
    })
}

/// A loopback port free on `host` now, for an evaluator incarnation to
/// listen on.
fn free_loopback_port(host: &str) -> Option<u16> {
    let listener = TcpListener::bind((host, 0)).ok()?;
    listener.local_addr().ok().as_ref().map(SocketAddr::port)
}

/// `base_url` with its port replaced by `port`.
fn with_port(base_url: &str, port: u16) -> Option<String> {
    let (scheme, rest) = base_url.split_once("://")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = match authority.find(']') {
        Some(end) => &authority[..=end],
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host),
    };
    if path.is_empty() {
        Some(format!("{scheme}://{host}:{port}"))
    } else {
        Some(format!("{scheme}://{host}:{port}/{path}"))
    }
}

/// Launches an evaluator incarnation of `seat`'s row for vault `vault`, with
/// `draft` in place of the row's draft: the row's own launch, under the
/// evaluator's row id, on a free loopback port, with no idle stop. `None`
/// when this process launches no worker, off a Tokio runtime, or with no
/// free port.
pub(in crate::models) fn launch_evaluator(
    seat: &EvaluatorSeat,
    vault: [u8; 32],
    draft: EvaluatorDraft,
) -> Option<EvaluatorIncarnation> {
    let host = HOST.get()?;
    tokio::runtime::Handle::try_current().ok()?;
    let mut row = seat.row.clone();
    row.id = format!("{}{EVALUATOR_ROW_SUFFIX}", seat.worker_id);
    let launch = row.launch.as_mut()?;
    let port = free_loopback_port(&launch.listen_host)?;
    launch.listen_port = port;
    launch.idle_stop_secs = None;
    match draft {
        EvaluatorDraft::TargetOnly => launch.draft = None,
        EvaluatorDraft::Stock => {}
        EvaluatorDraft::Vault(set) => {
            launch.draft = Some(WorkerArtifact {
                offline_dir: Some(set.dir.clone()),
                source: ArtifactSource::VaultLoadSet(set),
            });
        }
    }
    let device = launch.device.clone();
    let mut provider = seat.provider.clone();
    provider.base_url = with_port(&provider.base_url, port)?;
    let (worker, slot) = host.supervisor(&row, &provider);
    let slot = slot?;
    evaluators().insert(row.id.clone(), (vault, worker.clone()));
    host.begin(&worker);
    Some(EvaluatorIncarnation {
        row_id: row.id,
        worker,
        slot,
        device,
    })
}

/// Retires every evaluator incarnation of vault `vault`, on the current
/// runtime: a vault lock's, before its plaintext goes.
pub(in crate::models) fn retire_vault_evaluators(vault: &[u8; 32]) {
    let workers: Vec<InferenceWorker> = evaluators()
        .values()
        .filter(|(owner, _)| owner == vault)
        .map(|(_, worker)| worker.clone())
        .collect();
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    for worker in workers {
        runtime.spawn(async move {
            worker.retire().await;
        });
    }
}
