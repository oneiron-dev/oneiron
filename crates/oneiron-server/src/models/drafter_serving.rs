//! The vault's own drafter, served (FIX 14976, FIX 12569 slice 4): the host
//! seam that serves each target's drafter binding, stock or a retained
//! version at a binding generation, on this process's managed EXL3 worker,
//! by a supervised restart of that worker with the version's sealed draft.
//! There is no hot swap in this release.
//!
//! [`install_drafter_serving`] attaches one host to each vault this server
//! serves. Its task serves the vault's plans (`apply_drafter_binding` for
//! each bound target) at start-up, once every managed EXL3 worker has its
//! launch record, and again on each notice the engine sends after commit:
//! a revert, a policy set or an erase that moved a binding, and an unlock. A
//! missed notice is caught at the next one or at the next start-up.
//!
//! Applying a version: its sealed load set is opened through the vault's
//! own artifact custody into a fresh private directory under the vault's
//! `drafter-serving/`, every file's length and BLAKE3 checked. The worker's
//! row gets a new supervisor whose launch takes that directory as its draft
//! (`--draft-dir`) after checking every file again and the target's pins,
//! and whose launch manifest names the draft's identity; its predecessor
//! drains and stops first (`worker_host::replace_draft`). Once the new
//! incarnation qualifies with that identity in its answers, the transition
//! is recorded in a write that checks the binding's generation, the policy
//! and the version's erase state again: a revert or an erase that landed
//! meanwhile wins, and the newer plan applies next. Until then the status
//! names the old incarnation. A new incarnation is a new epoch: the old one's
//! sessions go with it, and a kept snapshot carries no draft state
//! (`deploy/house-model/exl3_session/snapshot.py`), so none depends on the
//! draft. A load set that does not verify, or an incarnation that does not
//! qualify with it, puts stock back until the binding moves again.
//!
//! Only a process that launches the worker for its one vault applies a
//! binding. A shared worker (several vaults in this process, or a managed
//! per-vault process that calls a worker another process launched) and an
//! external one keep what they serve, and the status says why. A second
//! vault served here puts every private draft back to stock.
//!
//! Plaintext: a vault lock puts the vault's private drafts back to stock and
//! removes their directories before the key drops; each pass removes every
//! directory whose version may no longer serve (an erase, a revert away, a
//! policy change); start-up removes every leftover. A vault's own drafter
//! never enters the shared model-artifact install or its cache.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use oneiron::drafter::{
    DrafterArtifactFile, DrafterServedView, DrafterServing, DrafterServingPlan,
    DrafterServingPlans, DrafterServingRuntime, DrafterTarget, DrafterUnservedReason,
    drafter_file_name_is_plain, drafter_load_set_blake3,
};
use oneiron::llm::{WorkerFailure, WorkerKind, WorkerReadiness};
use oneiron::{EntityId, Vault};
use oneiron_driver::{InferenceWorker, LaunchFailure};
use tokio::runtime::Handle;
use tokio::sync::Notify;

use super::worker_host::{self, DraftSeat};

/// The runtime a drafter target names for a managed EXL3 worker: the worker
/// kind's wire name.
pub(super) const EXL3_DRAFTER_RUNTIME: &str = "exl3";

/// What an EXL3 answer's draft identity opens with when the launch loads a
/// vault's own load set; the load set's BLAKE3 follows, in hex.
const VAULT_DRAFT_IDENTITY_PREFIX: &str = "load-set-blake3:";

/// What it opens with when the launch loads the row's stock draft; the
/// SHA-256 of the draft's install record follows, in hex.
const STOCK_DRAFT_IDENTITY_PREFIX: &str = "manifest-sha256:";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A vault drafter version's load set, materialised in the vault's private
/// `drafter-serving/` directory and verified there. Only the drafter
/// serving seam makes one; no config file names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultLoadSet {
    /// The vault whose drafter it is.
    pub vault: [u8; 32],
    /// The target it was trained for.
    pub target: DrafterTarget,
    pub version: EntityId,
    /// The binding generation it was applied at.
    pub generation: u64,
    /// Its private plaintext directory.
    pub dir: PathBuf,
    pub files: Vec<DrafterArtifactFile>,
    pub load_set_blake3: [u8; 32],
}

impl VaultLoadSet {
    /// The draft identity a launch that loads it names, and every answer of
    /// that launch echoes.
    #[must_use]
    pub(super) fn identity(&self) -> String {
        format!(
            "{VAULT_DRAFT_IDENTITY_PREFIX}{}",
            hex(&self.load_set_blake3)
        )
    }

    /// Whether it drafts for the EXL3 target whose backend model digest is
    /// `model` and whose tokenizer digest is `tokenizer`.
    #[must_use]
    pub(super) fn fits(&self, model: &str, tokenizer: Option<&str>) -> bool {
        self.target.runtime == EXL3_DRAFTER_RUNTIME
            && self.target.model == model
            && tokenizer == Some(self.target.tokenizer.as_str())
    }
}

/// The draft identity a launch that loads the stock draft installed under
/// the install record `record_sha256` names.
#[must_use]
pub(super) fn stock_draft_identity(record_sha256: &str) -> String {
    format!("{STOCK_DRAFT_IDENTITY_PREFIX}{record_sha256}")
}

/// Whether `identity` is one a launch that loads a row's stock draft names
/// (FIX 14975: the evaluator's stock arm).
#[cfg(unix)]
#[must_use]
pub(super) fn is_stock_draft_identity(identity: &str) -> bool {
    identity.starts_with(STOCK_DRAFT_IDENTITY_PREFIX)
}

/// Checks `set` at a launch's install: an EXL3 worker loads it; its digest
/// is the one its files give; every file it names is a plain name in its
/// directory, of its length and BLAKE3; and the directory holds nothing
/// else. Any failure is permanent: the worker parks until its row is
/// replaced, and the serving seam puts stock back.
pub(super) async fn verify_vault_load_set(
    set: &Arc<VaultLoadSet>,
    kind: WorkerKind,
) -> Result<Arc<VaultLoadSet>, LaunchFailure> {
    if kind != WorkerKind::Exl3 {
        return Err(LaunchFailure::permanent(
            WorkerFailure::KindMismatch,
            "only an EXL3 worker loads a vault's own drafter",
        ));
    }
    let set = Arc::clone(set);
    tokio::task::spawn_blocking(move || check_load_set(&set).map(|()| set))
        .await
        .map_err(|error| LaunchFailure::transient(WorkerFailure::LoadFailed, error.to_string()))?
}

fn check_load_set(set: &VaultLoadSet) -> Result<(), LaunchFailure> {
    let mismatch = |what: &str| {
        LaunchFailure::permanent(
            WorkerFailure::ModelMismatch,
            format!("the vault's drafter load set {what}"),
        )
    };
    let unreadable = |error: std::io::Error| {
        LaunchFailure::permanent(
            WorkerFailure::LoadFailed,
            format!("the vault's drafter load set is unreadable: {error}"),
        )
    };
    match drafter_load_set_blake3(&set.files) {
        Ok(digest) if digest == set.load_set_blake3 => {}
        _ => return Err(mismatch("does not hash to its digest")),
    }
    let mut names = BTreeSet::new();
    for file in &set.files {
        if !drafter_file_name_is_plain(&file.name) || !names.insert(file.name.as_str()) {
            return Err(mismatch("names a file that is not one plain name"));
        }
        let mut input = std::fs::File::open(set.dir.join(&file.name)).map_err(unreadable)?;
        let mut hasher = blake3::Hasher::new();
        let read = std::io::copy(&mut input, &mut hasher).map_err(unreadable)?;
        if read != file.bytes || hasher.finalize().as_bytes() != &file.blake3 {
            return Err(mismatch("holds a file that is not the one it names"));
        }
    }
    for entry in std::fs::read_dir(&set.dir).map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        let named = entry
            .file_name()
            .to_str()
            .is_some_and(|name| names.contains(name));
        if !named {
            return Err(mismatch("holds a file it does not name"));
        }
    }
    Ok(())
}

/// Each vault this process serves drafters for, by its id.
static SERVED_VAULTS: Mutex<BTreeMap<[u8; 32], Weak<VaultDrafterHost>>> =
    Mutex::new(BTreeMap::new());

/// [`SERVED_VAULTS`], its dropped hosts left out.
fn served_vaults() -> MutexGuard<'static, BTreeMap<[u8; 32], Weak<VaultDrafterHost>>> {
    let mut vaults = SERVED_VAULTS.lock().unwrap_or_else(PoisonError::into_inner);
    vaults.retain(|_, host| host.strong_count() > 0);
    vaults
}

/// How many vaults this process serves drafters for (FIX 14975).
#[cfg(unix)]
pub(super) fn served_vault_count() -> usize {
    served_vaults().len()
}

/// The runtime vault `vault`'s drafter host runs on, when one is attached
/// here (FIX 14975: the evaluator's tasks run on it).
#[cfg(unix)]
pub(super) fn vault_runtime(vault: &[u8; 32]) -> Option<Handle> {
    served_vaults()
        .get(vault)
        .and_then(Weak::upgrade)
        .map(|host| host.runtime.clone())
}

/// One vault's drafter serving host.
struct VaultDrafterHost {
    vault: Weak<Vault>,
    /// The vault's id, as its load sets name it.
    id: [u8; 32],
    /// Wakes the host's task: one notice is kept while a pass runs.
    wake: Arc<Notify>,
    /// The runtime the host's task runs on.
    runtime: Handle,
    state: Mutex<HostState>,
}

#[derive(Default)]
struct HostState {
    /// What each bound target serves now, as this host last saw it.
    served: BTreeMap<DrafterTarget, DrafterServedView>,
    /// The binding generation whose apply failed, and why, by target: not
    /// tried again until the binding moves.
    failed: BTreeMap<DrafterTarget, (u64, DrafterUnservedReason)>,
    /// A replacement not yet recorded, by target: the binding generation and
    /// the load set it launches (`None` for stock).
    pending: BTreeMap<DrafterTarget, (u64, Option<[u8; 32]>)>,
}

impl Drop for VaultDrafterHost {
    fn drop(&mut self) {
        // The task holds the host weakly: woken, it finds it gone and ends.
        self.wake.notify_one();
    }
}

impl DrafterServingRuntime for VaultDrafterHost {
    fn bindings_moved(&self) {
        self.wake.notify_one();
    }

    fn vault_locking(&self) {
        {
            let _entered = self.runtime.enter();
            worker_host::clear_vault_drafts(Some(&self.id));
            // FIX 14975: no evaluator incarnation keeps a private head either.
            #[cfg(unix)]
            worker_host::retire_vault_evaluators(&self.id);
        }
        if let Some(vault) = self.vault.upgrade() {
            vault.remove_drafter_plaintext(&BTreeSet::new());
        }
        {
            let mut state = self.lock();
            state.pending.clear();
            for row in state.served.values_mut() {
                if matches!(row.serving, Some(DrafterServing::Version(_))) {
                    row.serving = Some(DrafterServing::Stock);
                    row.generation = None;
                    row.draft_digest = None;
                }
                row.reason = Some(DrafterUnservedReason::VaultLocked);
            }
        }
        self.wake.notify_one();
    }

    fn served(&self) -> Vec<DrafterServedView> {
        let drafts = worker_host::vault_drafts(&self.id);
        self.lock()
            .served
            .values()
            .cloned()
            .map(|mut row| {
                // A configuration change that replaced the row put stock back.
                if let Some(DrafterServing::Version(version)) = row.serving
                    && !row.applying
                    && !drafts.iter().any(|(worker, draft)| {
                        row.worker.as_deref() == Some(worker.as_str()) && draft.version == version
                    })
                {
                    row.serving = Some(DrafterServing::Stock);
                    row.generation = None;
                    row.draft_digest = None;
                    row.reason = Some(DrafterUnservedReason::Superseded);
                }
                row
            })
            .collect()
    }
}

/// Runs `work` on the vault off the runtime.
pub(super) async fn blocking<T, F>(vault: &Arc<Vault>, work: F) -> oneiron::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Vault) -> oneiron::Result<T> + Send + 'static,
{
    let vault = Arc::clone(vault);
    tokio::task::spawn_blocking(move || work(&vault))
        .await
        .unwrap_or_else(|_| {
            Err(oneiron::Error::InvalidConfig(
                "a drafter serving step stopped before it finished".into(),
            ))
        })
}

/// The epoch and the draft identity `worker`'s qualified incarnation names.
fn incarnation(worker: &InferenceWorker) -> (Option<String>, Option<String>) {
    match worker.status().readiness {
        WorkerReadiness::Ready { observed } => (
            observed
                .identity
                .backend_epoch
                .as_ref()
                .map(|epoch| epoch.as_str().to_owned()),
            observed.identity.draft_weights_digest,
        ),
        _ => (None, None),
    }
}

impl VaultDrafterHost {
    fn lock(&self) -> MutexGuard<'_, HostState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes `target`'s row by `change`.
    fn note(&self, target: &DrafterTarget, change: impl FnOnce(&mut DrafterServedView)) {
        let mut state = self.lock();
        let row = state
            .served
            .entry(target.clone())
            .or_insert_with(|| DrafterServedView::unknown(target.clone(), None));
        change(row);
    }

    /// Whether `plan` serves as this host last proved it.
    fn proved(&self, plan: &DrafterServingPlan) -> bool {
        self.lock().served.get(&plan.target).is_some_and(|row| {
            !row.applying
                && row.serving == Some(plan.serving)
                && row.generation == Some(plan.generation)
        })
    }

    /// Removes every plaintext directory of this vault but those its rows'
    /// current supervisors launch and whose versions may still serve.
    fn remove_plaintext(&self, vault: &Vault, plans: &DrafterServingPlans) {
        let keep: BTreeSet<PathBuf> = worker_host::vault_drafts(&self.id)
            .into_iter()
            .filter(|(_, draft)| plans.retained.contains(&draft.load_set_blake3))
            .map(|(_, draft)| draft.dir.clone())
            .collect();
        vault.remove_drafter_plaintext(&keep);
    }

    /// One pass: reads the plans, removes plaintext that may no longer stay,
    /// and serves each bound target's plan. A notice that cuts a wait ends
    /// the pass early; the next pass reads the plans again.
    async fn pass(&self) {
        // A target is matched by its worker's launch pins: at start-up each
        // managed EXL3 worker writes its first launch record. The vault is
        // not held while this waits.
        worker_host::launch_records().await;
        let Some(vault) = self.vault.upgrade() else {
            return;
        };
        let plans = match blocking(&vault, Vault::drafter_serving_plans).await {
            Ok(plans) => plans,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the vault's drafter plans did not read; the next notice retries"
                );
                return;
            }
        };
        let vaults = served_vaults().len();
        if vaults != 1 {
            let _entered = self.runtime.enter();
            worker_host::clear_vault_drafts(Some(&self.id));
        }
        self.remove_plaintext(&vault, &plans);
        let targets: BTreeSet<&DrafterTarget> =
            plans.plans.iter().map(|plan| &plan.target).collect();
        {
            let mut state = self.lock();
            state.served.retain(|target, _| targets.contains(target));
            state.failed.retain(|target, _| targets.contains(target));
            state.pending.retain(|target, _| targets.contains(target));
        }
        for plan in &plans.plans {
            if !self.apply_drafter_binding(&vault, plan, vaults).await {
                break;
            }
        }
        self.remove_plaintext(&vault, &plans);
    }

    /// Opens `plan`'s version into a fresh private directory, checked file
    /// by file; `None`, with a warning, when it does not open or verify.
    async fn materialize(
        &self,
        vault: &Arc<Vault>,
        plan: &DrafterServingPlan,
    ) -> Option<Arc<VaultLoadSet>> {
        let load_set = plan.load_set.as_ref()?;
        let digest = load_set.load_set_blake3;
        let owned = plan.clone();
        let made = blocking(vault, move |vault| {
            let dir = vault.new_drafter_serving_dir(&digest)?;
            vault.materialize_drafter_load_set(&owned, &dir)
        })
        .await;
        match made {
            Ok(made) => Some(Arc::new(VaultLoadSet {
                vault: self.id,
                target: plan.target.clone(),
                version: load_set.version,
                generation: plan.generation,
                dir: made.dir,
                files: made.files,
                load_set_blake3: made.load_set_blake3,
            })),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a drafter version's load set did not open; stock keeps serving"
                );
                None
            }
        }
    }

    /// An apply of `plan` on `worker_id` failed for `reason`: stock goes
    /// back, and this generation is not tried again until the binding moves.
    fn fail(&self, plan: &DrafterServingPlan, worker_id: &str, reason: DrafterUnservedReason) {
        let _ = worker_host::replace_draft(worker_id, None);
        let mut state = self.lock();
        state.pending.remove(&plan.target);
        state
            .failed
            .insert(plan.target.clone(), (plan.generation, reason));
        let row = state
            .served
            .entry(plan.target.clone())
            .or_insert_with(|| DrafterServedView::unknown(plan.target.clone(), None));
        row.serving = Some(DrafterServing::Stock);
        row.generation = None;
        row.draft_digest = None;
        row.worker = Some(worker_id.to_owned());
        row.epoch = None;
        row.applying = false;
        row.reason = Some(reason);
    }

    /// Serves `plan` on this process's managed worker for its target: stock,
    /// or the version's load set at the plan's generation, by a supervised
    /// restart of that worker (`worker_host::replace_draft`), recorded once
    /// the new incarnation proves the draft's identity. Where the worker may
    /// not take a vault's draft, its row says why and nothing changes.
    /// Returns `false` when a notice cut its wait.
    async fn apply_drafter_binding(
        &self,
        vault: &Arc<Vault>,
        plan: &DrafterServingPlan,
        vaults: usize,
    ) -> bool {
        let seat: DraftSeat = match worker_host::draft_seat(&plan.target, vaults) {
            Ok(seat) => seat,
            Err(reason) => {
                self.note(&plan.target, |row| {
                    *row = DrafterServedView::unknown(plan.target.clone(), Some(reason));
                });
                return true;
            }
        };
        let want = plan
            .load_set
            .as_ref()
            .map(|load_set| load_set.load_set_blake3);
        let have = seat.draft.as_ref().map(|draft| draft.load_set_blake3);
        let pending = self.lock().pending.get(&plan.target).copied();
        if want == have && (self.proved(plan) || (want.is_none() && pending.is_none())) {
            // What serves is what the plan says; nothing to restart.
            let (epoch, draft_digest) = incarnation(&seat.worker);
            self.note(&plan.target, |row| {
                row.serving = Some(plan.serving);
                row.generation = Some(plan.generation);
                row.draft_digest = draft_digest;
                row.worker = Some(seat.worker_id.clone());
                row.epoch = epoch;
                row.applying = false;
                row.reason = plan.held;
            });
            return true;
        }
        let failed = self.lock().failed.get(&plan.target).copied();
        if let Some((generation, reason)) = failed
            && generation == plan.generation
        {
            self.note(&plan.target, |row| row.reason = Some(reason));
            return true;
        }
        self.note(&plan.target, |row| {
            row.applying = true;
            row.worker = Some(seat.worker_id.clone());
        });
        let (worker, draft) = if want == have {
            (seat.worker.clone(), seat.draft.clone())
        } else {
            let draft = match plan.load_set {
                None => None,
                Some(_) => match self.materialize(vault, plan).await {
                    Some(draft) => Some(draft),
                    None => {
                        self.fail(
                            plan,
                            &seat.worker_id,
                            DrafterUnservedReason::LoadSetUnverified,
                        );
                        return true;
                    }
                },
            };
            let Some(worker) = worker_host::replace_draft(&seat.worker_id, draft.clone()) else {
                self.note(&plan.target, |row| {
                    row.applying = false;
                    row.reason = Some(DrafterUnservedReason::Superseded);
                });
                return true;
            };
            self.lock()
                .pending
                .insert(plan.target.clone(), (plan.generation, want));
            (worker, draft)
        };
        // The old incarnation serves until the new one qualifies; a notice
        // that moves the plans meanwhile cuts the wait.
        let ready = tokio::select! {
            ready = worker.ensure_ready() => ready,
            () = self.wake.notified() => {
                self.wake.notify_one();
                return false;
            }
        };
        if ready.is_err() {
            if worker_host::is_current(&worker) {
                self.fail(plan, &seat.worker_id, DrafterUnservedReason::WorkerRejected);
            } else {
                // Another replacement took the row.
                self.lock().pending.remove(&plan.target);
                self.note(&plan.target, |row| {
                    row.reason = Some(DrafterUnservedReason::Superseded);
                });
            }
            return true;
        }
        let (epoch, draft_digest) = incarnation(&worker);
        if let Some(draft) = draft.as_ref()
            && draft_digest.as_deref() != Some(draft.identity().as_str())
        {
            self.fail(plan, &seat.worker_id, DrafterUnservedReason::WorkerRejected);
            return true;
        }
        let target = plan.target.clone();
        let (generation, serving) = (plan.generation, plan.serving);
        let recorded_digest = draft_digest.clone();
        let recorded = blocking(vault, move |vault| {
            vault.record_drafter_served(&target, generation, serving, recorded_digest)
        })
        .await;
        self.lock().pending.remove(&plan.target);
        match recorded {
            Ok(true) => {
                self.lock().failed.remove(&plan.target);
                self.note(&plan.target, |row| {
                    row.serving = Some(serving);
                    row.generation = Some(generation);
                    row.draft_digest = draft_digest;
                    row.worker = Some(seat.worker_id.clone());
                    row.epoch = epoch;
                    row.applying = false;
                    row.reason = plan.held;
                });
            }
            Ok(false) => {
                // A revert, an erase, a policy set or a lock overtook it.
                self.note(&plan.target, |row| {
                    row.applying = true;
                    row.reason = Some(DrafterUnservedReason::Superseded);
                });
                self.wake.notify_one();
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a drafter serving transition was not recorded; the next notice retries"
                );
                self.note(&plan.target, |row| row.applying = true);
            }
        }
        true
    }
}

/// The host task of one vault: a pass at start, then one per notice, until
/// the host is dropped.
async fn serve_vault(host: Weak<VaultDrafterHost>, wake: Arc<Notify>) {
    loop {
        {
            let Some(host) = host.upgrade() else {
                return;
            };
            host.pass().await;
        }
        wake.notified().await;
    }
}

/// The process's workers were configured (at start-up, or a changed config
/// replaced a row with stock): every served vault's host serves its
/// bindings again.
pub(super) fn workers_configured() {
    let hosts: Vec<Arc<VaultDrafterHost>> =
        served_vaults().values().filter_map(Weak::upgrade).collect();
    for host in hosts {
        host.wake.notify_one();
    }
}

/// The drafter target this process's nightly retrain exports its corpus
/// for (FIX 14973): the first managed EXL3 worker it launches with a draft;
/// `None` when it launches none.
pub(crate) fn drafter_retrain_target() -> Option<DrafterTarget> {
    worker_host::retrain_target()
}

/// Attaches this process's drafter serving host to `vault`: its leftover
/// plaintext goes, and its task serves the vault's bindings from start-up
/// on. A second vault served here puts every private draft back to stock,
/// since no worker here may serve one vault's draft to another. Off a Tokio
/// runtime nothing is attached, and the status says no host serves.
pub(crate) fn install_drafter_serving(vault: &Arc<Vault>) {
    let Ok(runtime) = Handle::try_current() else {
        tracing::debug!("no runtime to serve this vault's drafter bindings on; stock serves");
        return;
    };
    let id = vault.vault_key_vault_id();
    // Start-up: only the directories a live supervisor of this process
    // launches stay (an embedded serve restarted over the same vault).
    let keep: BTreeSet<PathBuf> = worker_host::vault_drafts(&id)
        .into_iter()
        .map(|(_, draft)| draft.dir.clone())
        .collect();
    vault.remove_drafter_plaintext(&keep);
    let wake = Arc::new(Notify::new());
    let host = Arc::new(VaultDrafterHost {
        vault: Arc::downgrade(vault),
        id,
        wake: Arc::clone(&wake),
        runtime: runtime.clone(),
        state: Mutex::default(),
    });
    let others: Vec<Arc<VaultDrafterHost>> = {
        let mut vaults = served_vaults();
        vaults.insert(id, Arc::downgrade(&host));
        if vaults.len() > 1 {
            vaults.values().filter_map(Weak::upgrade).collect()
        } else {
            Vec::new()
        }
    };
    let runtime_port: Arc<dyn DrafterServingRuntime> = host.clone();
    vault.attach_drafter_serving(runtime_port);
    if !others.is_empty() {
        let _entered = runtime.enter();
        worker_host::clear_vault_drafts(None);
        for other in others {
            other.wake.notify_one();
        }
    }
    runtime.spawn(serve_vault(Arc::downgrade(&host), wake));
}
