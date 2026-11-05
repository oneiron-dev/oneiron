//! The drafter serving binding (FIX 14976, FIX 12569 slice 4): the engine's
//! side of a host that serves each target's binding on its own managed
//! worker.
//!
//! A host attaches a [`DrafterServingRuntime`] to the vault
//! ([`Vault::attach_drafter_serving`]). The engine tells it, after commit and
//! best effort, when a binding moves (a revert, a policy set, an erase) and
//! when the vault unlocks ([`Vault::notify_drafter_serving`]), and, before
//! the vault key drops, when the vault locks. A missed notice is caught at
//! the host's next start-up or its next notice.
//!
//! The host reads what to serve ([`Vault::drafter_serving_plans`]): each
//! bound target's version when it may serve now (qualified, its artifact key
//! live, the policy on, no excluded world in its ancestry, the vault
//! unlocked), else stock. For a version it materialises the sealed load set
//! into a fresh private directory under the vault's `drafter-serving/`
//! ([`Vault::materialize_drafter_load_set`]), every file's length and BLAKE3
//! checked as it is opened, and hands that directory to its worker's launch
//! as the draft. Once the new worker incarnation proves the expected draft
//! identity, the host records the transition ([`Vault::record_drafter_served`]):
//! that write checks the binding's generation, the policy and the version's
//! erase state again, so a revert or an erase that landed meanwhile wins over
//! the stale apply.
//!
//! The status door shows what each target's worker serves now
//! ([`DrafterServedView`]) and, where a binding is not applied, why
//! ([`DrafterUnservedReason`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError};

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::{
    BINDINGS, DrafterActor, DrafterArtifactFile, DrafterBinding, DrafterEventKind, DrafterPolicy,
    DrafterServing, DrafterTarget, DrafterVersion, DrafterVersionState, ancestry_names_world,
    drafter_load_set_blake3, invalid, policy_in_txn, record_event_in_txn, versions_by_id,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::drafter_custody::drafter_artifact_retained_in_txn;
use crate::world_keys::VaultKeyStatus;

/// The host's side of a vault's drafter serving. Each call returns at once;
/// the host applies on a task of its own.
pub trait DrafterServingRuntime: Send + Sync {
    /// A binding, the policy or the lock state moved: read the plans again
    /// and serve them.
    fn bindings_moved(&self);

    /// The vault is locking: its private drafters stop serving, and their
    /// plaintext directories are removed before this returns. The worker's
    /// restart to stock runs on the host's task.
    fn vault_locking(&self);

    /// What each target the host serves for this vault serves now.
    fn served(&self) -> Vec<DrafterServedView>;
}

/// Why a target's binding is not what serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterUnservedReason {
    /// No host that serves the vault's bindings is attached here.
    NoServingHost,
    /// No managed worker of this process serves the target's pins with a
    /// draft.
    NoServingWorker,
    /// The worker that serves the target is shared: this process serves
    /// several vaults, or it calls a worker another process launches for
    /// every vault. Its draft is never rewritten.
    UnsupportedSharedWorker,
    /// The worker is the operator's external endpoint, never restarted by
    /// the engine.
    UnsupportedExternalWorker,
    /// The worker's runtime loads no vault drafter in this release.
    UnsupportedRuntime,
    /// The vault is locked: no private drafter serves while it is.
    VaultLocked,
    /// The bound version may not serve now: not qualified, its artifact key
    /// gone, the policy off, or an excluded world in its ancestry.
    VersionNotServable,
    /// The version's sealed load set did not open or did not verify.
    LoadSetUnverified,
    /// The new worker incarnation did not qualify with the expected draft
    /// identity; stock serves until the binding moves again.
    WorkerRejected,
    /// The binding moved while it was applied; the newer one applies next.
    Superseded,
}

/// What one target's worker serves now, as the host's worker proved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterServedView {
    pub target: DrafterTarget,
    /// What the worker's current incarnation serves: stock or a version;
    /// `None` where this host does not know (a shared or external worker).
    pub serving: Option<DrafterServing>,
    /// The binding generation that serving was applied at.
    pub generation: Option<u64>,
    /// The draft identity the incarnation's answers name.
    pub draft_digest: Option<String>,
    /// The worker that serves the target, by its configured id.
    pub worker: Option<String>,
    /// The incarnation's backend epoch.
    pub epoch: Option<String>,
    /// Whether an apply is under way: the incarnation named here serves
    /// until the new one qualifies.
    pub applying: bool,
    /// Why the binding is not what serves; `None` when it is.
    pub reason: Option<DrafterUnservedReason>,
}

impl DrafterServedView {
    /// A target this host has not served yet.
    #[must_use]
    pub fn unknown(target: DrafterTarget, reason: Option<DrafterUnservedReason>) -> Self {
        Self {
            target,
            serving: None,
            generation: None,
            draft_digest: None,
            worker: None,
            epoch: None,
            applying: false,
            reason,
        }
    }
}

/// One version's sealed load set, as a plan names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrafterLoadSetPlan {
    pub version: EntityId,
    /// The sealed artifact's random id.
    pub artifact: [u8; 16],
    pub files: Vec<DrafterArtifactFile>,
    pub load_set_blake3: [u8; 32],
}

/// What a host serves for one bound target, as the records stand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrafterServingPlan {
    pub target: DrafterTarget,
    /// The binding's generation the plan was read at.
    pub generation: u64,
    /// What serves: the binding's version where it may serve now, else
    /// stock.
    pub serving: DrafterServing,
    /// The version's load set, when a version serves.
    pub load_set: Option<DrafterLoadSetPlan>,
    /// Why the binding's version does not serve, when it names one that may
    /// not now.
    pub held: Option<DrafterUnservedReason>,
}

/// Every bound target's plan, read in one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrafterServingPlans {
    pub plans: Vec<DrafterServingPlan>,
    /// The load sets of every version that is not erased and keeps its key:
    /// a plaintext directory of any other goes at once. Empty while the vault
    /// is locked.
    pub retained: BTreeSet<[u8; 32]>,
    pub locked: bool,
}

/// What [`Vault::materialize_drafter_load_set`] wrote and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrafterMaterialized {
    pub dir: PathBuf,
    pub files: Vec<DrafterArtifactFile>,
    pub load_set_blake3: [u8; 32],
}

/// `version`'s load set, when it may serve now in `txn`: qualified, its
/// artifact kept and its key live, the policy on and no excluded world in
/// its ancestry. Otherwise why not.
fn servable(
    store: &Store,
    txn: &RoTxn<'_>,
    policy: &DrafterPolicy,
    versions: &BTreeMap<EntityId, DrafterVersion>,
    version: &DrafterVersion,
) -> Result<std::result::Result<DrafterLoadSetPlan, DrafterUnservedReason>> {
    let refused = Err(DrafterUnservedReason::VersionNotServable);
    if version.state != DrafterVersionState::Qualified || !policy.enabled {
        return Ok(refused);
    }
    let Some(artifact) = version.artifact.as_ref() else {
        return Ok(refused);
    };
    if !drafter_artifact_retained_in_txn(store, txn, &version.id, &artifact.key_ref)?
        || ancestry_names_world(versions, version, &policy.excluded_worlds)
    {
        return Ok(refused);
    }
    Ok(Ok(DrafterLoadSetPlan {
        version: version.id,
        artifact: artifact.id,
        files: artifact.files.clone(),
        load_set_blake3: artifact.load_set_blake3,
    }))
}

/// `binding`'s plan in `txn`, `locked` the vault's lock state.
fn plan_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    policy: &DrafterPolicy,
    versions: &BTreeMap<EntityId, DrafterVersion>,
    binding: &DrafterBinding,
    locked: bool,
) -> Result<DrafterServingPlan> {
    let mut plan = DrafterServingPlan {
        target: binding.target.clone(),
        generation: binding.generation,
        serving: DrafterServing::Stock,
        load_set: None,
        held: None,
    };
    let DrafterServing::Version(id) = binding.serving else {
        return Ok(plan);
    };
    let found = versions
        .get(&id)
        .filter(|version| version.target == binding.target);
    let Some(version) = found else {
        plan.held = Some(DrafterUnservedReason::VersionNotServable);
        return Ok(plan);
    };
    match servable(store, txn, policy, versions, version)? {
        Err(reason) => plan.held = Some(reason),
        Ok(_) if locked => plan.held = Some(DrafterUnservedReason::VaultLocked),
        Ok(load_set) => {
            plan.serving = binding.serving;
            plan.load_set = Some(load_set);
        }
    }
    Ok(plan)
}

impl Vault {
    /// Attaches the host that serves this vault's drafter bindings, in place
    /// of any before it.
    pub fn attach_drafter_serving(&self, runtime: Arc<dyn DrafterServingRuntime>) {
        *self
            .store
            .drafter_serving
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(runtime);
    }

    fn drafter_serving_runtime(&self) -> Option<Arc<dyn DrafterServingRuntime>> {
        self.store
            .drafter_serving
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Tells the attached host, after a commit, that a binding, the policy
    /// or the lock state moved. Best effort: nothing without a host, and a
    /// host that misses it catches up at its next start-up or notice.
    pub fn notify_drafter_serving(&self) {
        if let Some(runtime) = self.drafter_serving_runtime() {
            runtime.bindings_moved();
        }
    }

    /// The drafter half of a vault lock, before the key drops: the attached
    /// host stops serving the vault's private drafters and removes their
    /// plaintext.
    pub(crate) fn drafter_serving_locking(&self) {
        if let Some(runtime) = self.drafter_serving_runtime() {
            runtime.vault_locking();
        }
        // FIX 14975: an evaluation's plaintext goes too; the host retired its
        // evaluator workers in `vault_locking`.
        self.remove_drafter_evaluation_plaintext();
    }

    /// What each bound target's worker serves now: the attached host's view,
    /// a bound target it has not served yet as unknown, or each binding as
    /// not served here when no host is attached.
    pub(super) fn drafter_served(&self, bindings: &[DrafterBinding]) -> Vec<DrafterServedView> {
        let Some(runtime) = self.drafter_serving_runtime() else {
            return bindings
                .iter()
                .map(|binding| {
                    DrafterServedView::unknown(
                        binding.target.clone(),
                        Some(DrafterUnservedReason::NoServingHost),
                    )
                })
                .collect();
        };
        let mut served = runtime.served();
        for binding in bindings {
            if !served.iter().any(|row| row.target == binding.target) {
                served.push(DrafterServedView::unknown(binding.target.clone(), None));
            }
        }
        served
    }

    /// The host's read of what to serve: each bound target's plan, and the
    /// load sets whose plaintext may stay, in one snapshot.
    ///
    /// # Errors
    /// Storage and custody faults.
    pub fn drafter_serving_plans(&self) -> Result<DrafterServingPlans> {
        let locked = self.vault_key_status()? == VaultKeyStatus::Locked;
        let store = &self.store;
        let txn = store.env.read_txn()?;
        let policy = policy_in_txn(store, &txn)?;
        let versions = versions_by_id(store, &txn)?;
        let mut retained = BTreeSet::new();
        if !locked {
            for version in versions.values() {
                if version.state == DrafterVersionState::Erased {
                    continue;
                }
                if let Some(artifact) = version.artifact.as_ref()
                    && drafter_artifact_retained_in_txn(
                        store,
                        &txn,
                        &version.id,
                        &artifact.key_ref,
                    )?
                {
                    retained.insert(artifact.load_set_blake3);
                }
            }
        }
        let mut plans = Vec::new();
        for (_, binding) in BINDINGS.scan(store, &txn)? {
            plans.push(plan_in_txn(
                store, &txn, &policy, &versions, &binding, locked,
            )?);
        }
        Ok(DrafterServingPlans {
            plans,
            retained,
            locked,
        })
    }

    /// The host's door to materialise `plan`'s version into the new private
    /// directory `dir` (one [`Self::new_drafter_serving_dir`] named): the
    /// binding must still serve the version at the plan's generation, the
    /// version still servable with the same artifact, and the vault
    /// unlocked; then its sealed files are opened under its live key, each
    /// file's length and BLAKE3 and the load set's digest checked. On any
    /// failure nothing stays in `dir`.
    ///
    /// # Errors
    /// A plan that names no version, a binding or version that moved, a
    /// retired key, a damaged load set, and storage, custody and I/O faults.
    pub fn materialize_drafter_load_set(
        &self,
        plan: &DrafterServingPlan,
        dir: &Path,
    ) -> Result<DrafterMaterialized> {
        let load_set = plan
            .load_set
            .as_ref()
            .ok_or_else(|| invalid("the drafter serving plan names no version"))?;
        if self.vault_key_status()? == VaultKeyStatus::Locked {
            return Err(invalid("the vault is locked: no private drafter serves"));
        }
        {
            let store = &self.store;
            let txn = store.env.read_txn()?;
            let binding = BINDINGS
                .get(store, &txn, &plan.target.key()?)?
                .unwrap_or_else(|| DrafterBinding::stock(plan.target.clone()));
            let policy = policy_in_txn(store, &txn)?;
            let versions = versions_by_id(store, &txn)?;
            if binding.generation != plan.generation
                || plan_in_txn(store, &txn, &policy, &versions, &binding, false)?
                    .load_set
                    .as_ref()
                    != Some(load_set)
            {
                return Err(invalid("the drafter binding moved since its plan was read"));
            }
        }
        if drafter_load_set_blake3(&load_set.files)? != load_set.load_set_blake3 {
            return Err(Error::CorruptedIndex("drafter load set"));
        }
        let sealing = self
            .drafter_artifact_sealing(&load_set.version)?
            .ok_or_else(|| invalid("the drafter version's artifact key is no longer live"))?;
        if sealing.artifact() != load_set.artifact {
            return Err(invalid(
                "the drafter version's artifact moved since its plan was read",
            ));
        }
        self.open_drafter_load_set(&sealing, &load_set.files, dir)?;
        Ok(DrafterMaterialized {
            dir: dir.to_path_buf(),
            files: load_set.files.clone(),
            load_set_blake3: load_set.load_set_blake3,
        })
    }

    /// The host's door to record that a new worker incarnation proved it
    /// serves `target`'s binding at `generation`: `serving`, with the draft
    /// identity its answers name. In one write the binding must still sit at
    /// `generation` and, for a version, still point at it, the version still
    /// servable (qualified, its key live, the policy on, no excluded world)
    /// and the vault unlocked; then one `served` event is written. A stale
    /// apply, which a revert, an erase, a policy set or a lock overtook,
    /// writes nothing and returns `false`: the host applies the newer plan.
    ///
    /// # Errors
    /// Storage and custody faults.
    pub fn record_drafter_served(
        &self,
        target: &DrafterTarget,
        generation: u64,
        serving: DrafterServing,
        draft_digest: Option<String>,
    ) -> Result<bool> {
        if serving != DrafterServing::Stock && self.vault_key_status()? == VaultKeyStatus::Locked {
            return Ok(false);
        }
        let key = target.key()?;
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            let binding = BINDINGS
                .get(store, txn, &key)?
                .unwrap_or_else(|| DrafterBinding::stock(target.clone()));
            if binding.generation != generation || binding.target != *target {
                return Ok(false);
            }
            if let DrafterServing::Version(id) = serving {
                if binding.serving != serving {
                    return Ok(false);
                }
                let policy = policy_in_txn(store, txn)?;
                let versions = versions_by_id(store, txn)?;
                let Some(version) = versions.get(&id) else {
                    return Ok(false);
                };
                if servable(store, txn, &policy, &versions, version)?.is_err() {
                    return Ok(false);
                }
            }
            record_event_in_txn(
                store,
                txn,
                DrafterActor::Host,
                DrafterEventKind::Served {
                    target: target.clone(),
                    serving,
                    generation,
                    draft_digest,
                },
                None,
                at,
            )?;
            Ok(true)
        })
    }
}
