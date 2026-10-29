//! The host's side of each served vault's snapshot lifecycle (DESIGN-V2 §7
//! "On vault lock", V2-R3): the port a vault attaches, through which its
//! lock and its erases reach this process's sessions.
//!
//! A lock arrives with the vault's snapshot admission already closed, so no
//! session of it is created, forked, committed or transferred again. Every
//! session of the vault, on every worker, is retired and its release sent
//! at once, and ONE total bound (the owner's `lock_release_timeout_ms`, 10 s
//! by default) covers every answer, never a bound per handle. A worker that
//! has not acknowledged by then is aborted: its process group killed and
//! reaped with no drain, its leases and handles revoked, and its next
//! incarnation launched by its supervisor. Another vault's call on that
//! worker fails as a cut, under its caller's own retry authority, never a
//! hang. The sealed catalog stays. The receipt names worker ids, epochs and
//! outcomes only, and claims no zeroisation.
//!
//! A session created, forked or committed while a lock ran is not kept: its
//! work registers only under the admission it was granted, rechecked under
//! the registry's lock, and a handle that missed it is released at once.
//!
//! An erase drops every session of its vault: no session's dependency set
//! is kept here, so the whole epoch goes. Its releases run on the caller's
//! runtime or the one this port was installed on; a worker that does not
//! acknowledge one is aborted, as a lock aborts it.
//!
//! The host's plaintext copies of a vault's snapshots (a park's region and
//! buffer, a restore's buffer and region) are counted per vault, and their
//! owners drop them once the admission they ran under is gone or their op
//! is cut. A lock waits for them inside the same total bound, after the
//! releases that cut their ops, and its receipt says how many there were
//! and how many were still held when it answered.
//!
//! A vault first served here has its kept snapshots brought back in step
//! (its startup candidates), and a budget that is off or zero purges them.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

use oneiron::inference_snapshot::retention::SnapshotBudget;
use oneiron::inference_snapshot::{
    SnapshotAdmission, SnapshotFuture, SnapshotRelease, SnapshotRuntime, SnapshotWorkerAbort,
};
use oneiron::llm::{SessionInvalidation, SessionTarget, VaultRef};
use oneiron::{EntityId, Vault};
use oneiron_driver::InferenceWorker;
use tokio::runtime::Handle;
use tokio::task::JoinSet;

use super::registry::{self, Place};
use crate::config::models::snapshots::SnapshotPolicy;
use crate::models::{SnapshotReceipt, SnapshotSkips, SnapshotStatus};

/// This process's side of every served vault's snapshot lifecycle.
#[derive(Default)]
struct Snapshots {
    /// The policy the models config last resolved, read without any lock
    /// the release path holds.
    policy: RwLock<Arc<SnapshotPolicy>>,
    /// Each vault that attached the port, held weakly.
    vaults: Mutex<BTreeMap<VaultRef, Weak<Vault>>>,
    lock_restarts: AtomicU64,
    erase_owed: AtomicU64,
    last_lock: Mutex<Option<SnapshotReceipt>>,
    counts: Counts,
    /// The runtime the port was first installed on: an erase's releases
    /// run there when its caller is on none.
    runtime: OnceLock<Handle>,
}

static SNAPSHOTS: OnceLock<Snapshots> = OnceLock::new();

/// What this process's parks and restores did since it started.
#[derive(Default)]
struct Counts {
    parks: AtomicU64,
    seals: AtomicU64,
    opens: AtomicU64,
    imports: AtomicU64,
    replays: AtomicU64,
    restores_cold: AtomicU64,
    skips: [AtomicU64; 7],
}

/// One park or restore event, as the status counts it.
#[derive(Clone, Copy)]
pub(super) enum Counted {
    /// A published checkpoint exported to be parked.
    Park,
    /// A parked snapshot sealed and kept.
    Seal,
    /// A kept snapshot opened for a restore.
    Open,
    /// A restore imported and made ready.
    Import,
    /// A restored session whose first attach fell below the frontier its
    /// snapshot named: the suffix past the state it carried was replayed.
    Replay,
    /// A restore that matched a kept snapshot and ran cold.
    RestoreCold,
    Skipped(Skip),
}

/// Why a candidate was not parked.
#[derive(Clone, Copy)]
pub(super) enum Skip {
    /// The vault's budget is off, zero, or full of pinned snapshots.
    Budget,
    /// The size it would take, or its device's room, is not known.
    UnknownRoom,
    /// Its device has no room for the copy past the headroom.
    NoRoom,
    /// It depends on a world whose sealed copies the owner keeps local.
    KeptLocal,
    /// It is larger than the vault's whole budget.
    Oversize,
    /// What it was computed with is not named whole.
    Unsupported,
    /// Its checkpoint restores slower than it recomputes: too short to
    /// pay back its transfer.
    Short,
}

/// Counts `event`.
pub(super) fn count(event: Counted) {
    let counts = &snapshots().counts;
    let counter = match event {
        Counted::Park => &counts.parks,
        Counted::Seal => &counts.seals,
        Counted::Open => &counts.opens,
        Counted::Import => &counts.imports,
        Counted::Replay => &counts.replays,
        Counted::RestoreCold => &counts.restores_cold,
        Counted::Skipped(skip) => &counts.skips[skip as usize],
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

fn snapshots() -> &'static Snapshots {
    SNAPSHOTS.get_or_init(Snapshots::default)
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn policy() -> Arc<SnapshotPolicy> {
    Arc::clone(
        &snapshots()
            .policy
            .read()
            .unwrap_or_else(PoisonError::into_inner),
    )
}

/// The owner's sealed-snapshot budget for `vault` now.
pub(super) fn budget(vault: &VaultRef) -> SnapshotBudget {
    policy().for_vault(&vault.0).budget()
}

/// The open vault `vault` names, while it is attached here.
pub(super) fn vault(vault: &VaultRef) -> Option<Arc<Vault>> {
    guard(&snapshots().vaults)
        .get(vault)
        .and_then(Weak::upgrade)
}

/// Takes up `policy`, as a model runtime built from the config resolved it:
/// the next lock's bound and the status read it.
pub(in crate::models::worker_host) fn set_policy(policy: &SnapshotPolicy) {
    *snapshots()
        .policy
        .write()
        .unwrap_or_else(PoisonError::into_inner) = Arc::new(policy.clone());
}

/// The port every served vault attaches.
struct HostPort;

impl SnapshotRuntime for HostPort {
    fn release_bound(&self, vault: VaultRef) -> Duration {
        policy().for_vault(&vault.0).lock_release_timeout
    }

    fn release_vault(&self, vault: VaultRef, _closed: u64) -> SnapshotFuture<'_, SnapshotRelease> {
        let bound = self.release_bound(vault);
        Box::pin(async move {
            let release = lock_vault(vault, bound).await;
            *guard(&snapshots().last_lock) = Some(SnapshotReceipt {
                bound_ms: u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
                released: release.released,
                aborted: release.aborted.clone(),
                timed_out: release.timed_out,
                elapsed_ms: release.elapsed_ms,
                host_copies: release.host_copies,
                host_copies_left: release.host_copies_left,
            });
            release
        })
    }

    fn invalidate(&self, vault: VaultRef, ids: &[EntityId]) {
        invalidate(vault, ids);
    }
}

/// Attaches the host's port to `vault`: its lock waits for this process's
/// release, and its erases drop its sessions here. Its kept snapshots are
/// brought back in step on a task of their own.
pub(in crate::models::worker_host) fn install(vault: &Arc<Vault>) {
    if let Ok(runtime) = Handle::try_current() {
        let _ = snapshots().runtime.set(runtime);
    }
    let id = VaultRef(vault.vault_key_vault_id());
    guard(&snapshots().vaults).insert(id, Arc::downgrade(vault));
    vault.attach_snapshot_runtime(Arc::new(HostPort));
    reconcile(id, Arc::downgrade(vault));
}

/// The startup candidates of `vault`: a row whose body is missing or cut
/// short retires, a body no row names goes, and a budget that is off or
/// zero purges every row (FIX 11214). Off any runtime it waits for the
/// first park, whose reserve purges too.
fn reconcile(id: VaultRef, vault: Weak<Vault>) {
    let runtime = Handle::try_current()
        .ok()
        .or_else(|| snapshots().runtime.get().cloned());
    let Some(runtime) = runtime else {
        return;
    };
    runtime.spawn_blocking(move || {
        let Some(vault) = vault.upgrade() else {
            return;
        };
        let reconciled = vault.reconcile_inference_snapshots().and_then(|_| {
            let budget = budget(&id);
            if budget.limit() == 0 {
                vault.snapshot_ledger().enforce_budget(budget, 0, &[])?;
            }
            Ok(())
        });
        if let Err(error) = reconciled {
            tracing::warn!(
                kind = ?error.kind(),
                "a vault's kept inference snapshots were not brought in step; housekeeping retries"
            );
        }
    });
}

/// What session work on a vault was admitted under.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Admitted {
    /// A vault that never attached the port: it admits as before.
    Unattached,
    /// The vault's snapshot admission: its lock generation and its erase
    /// generation.
    Granted(SnapshotAdmission),
}

/// What `vault` admits session work under now; `None` once a lock closed
/// its snapshot admission, until an unlock opens a new one. Work admitted
/// under one registers only while it is still the same: the caller reads
/// it again under the registry's lock.
pub(super) fn admission(vault: &VaultRef) -> Option<Admitted> {
    let attached = guard(&snapshots().vaults)
        .get(vault)
        .and_then(Weak::upgrade);
    match attached {
        None => Some(Admitted::Unattached),
        Some(vault) => vault.snapshot_admission().map(Admitted::Granted),
    }
}

/// Releases every session of `vault` under one total `bound`, then aborts
/// each incarnation that still owes a release.
async fn lock_vault(vault: VaultRef, bound: Duration) -> SnapshotRelease {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + bound;
    let host_copies = registry::host_copies(&vault);
    let mut owed: BTreeMap<(String, String), (InferenceWorker, u64)> = BTreeMap::new();
    let mut releases = JoinSet::new();
    for (target, place) in registry::retire_vault(&vault) {
        let key = (place.worker.spec().worker_id.clone(), place.epoch.clone());
        owed.entry(key.clone())
            .or_insert_with(|| (place.worker.clone(), 0))
            .1 += 1;
        releases.spawn(async move {
            let acked = registry::release_acked(target, place, SessionInvalidation::Evicted).await;
            (key, acked)
        });
    }
    let mut released = 0;
    let mut timed_out = false;
    loop {
        match tokio::time::timeout_at(deadline, releases.join_next()).await {
            Ok(Some(Ok((key, true)))) => {
                released += 1;
                if let Some(entry) = owed.get_mut(&key) {
                    entry.1 = entry.1.saturating_sub(1);
                    if entry.1 == 0 {
                        owed.remove(&key);
                    }
                }
            }
            // A release refused or cut stays owed.
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                timed_out = true;
                break;
            }
        }
    }
    releases.abort_all();
    // The releases cut every export or import in flight; their owners drop
    // what they hold, inside the same bound.
    registry::copies_dropped(&vault, deadline).await;
    // Every abort starts at once, each on a task of its own that also does
    // its cleanup, so it finishes even when the engine stops waiting.
    let aborts: Vec<_> = owed
        .into_iter()
        .map(|((worker_id, epoch), (worker, _))| {
            tokio::spawn(async move {
                let reaped = worker.abort_incarnation(&epoch).await;
                registry::forget(&worker_id, &epoch);
                snapshots().lock_restarts.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    worker = %worker_id,
                    reaped,
                    "a vault lock aborted a model worker that did not release its sessions"
                );
                SnapshotWorkerAbort {
                    worker_id,
                    epoch,
                    reaped,
                }
            })
        })
        .collect();
    let mut aborted = Vec::new();
    for abort in aborts {
        if let Ok(abort) = abort.await {
            aborted.push(abort);
        }
    }
    SnapshotRelease {
        released,
        aborted,
        timed_out,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        host_copies,
        host_copies_left: registry::host_copies(&vault),
    }
}

/// An erase committed in `vault`: every session of it goes at once, its
/// releases on tasks of their own, on the caller's runtime or else the one
/// the port was installed on. With neither, they stay owed and counted.
fn invalidate(vault: VaultRef, ids: &[EntityId]) {
    if ids.is_empty() {
        return;
    }
    let retired = registry::retire_vault(&vault);
    if retired.is_empty() {
        return;
    }
    snapshots()
        .erase_owed
        .fetch_add(retired.len() as u64, Ordering::Relaxed);
    let runtime = Handle::try_current()
        .ok()
        .or_else(|| snapshots().runtime.get().cloned());
    let Some(runtime) = runtime else {
        tracing::warn!(
            owed = retired.len(),
            "an erase's model session releases have no runtime to run on; they stay owed"
        );
        return;
    };
    for (target, place) in retired {
        runtime.spawn(erase_release(target, place));
    }
}

/// One erase release: sent and answered, or else its worker's incarnation
/// aborted and forgotten, as a lock does. Only then is it no longer owed.
async fn erase_release(target: SessionTarget, place: Place) {
    let worker = place.worker.clone();
    let worker_id = worker.spec().worker_id.clone();
    let epoch = place.epoch.clone();
    if !registry::release_acked(target, place, SessionInvalidation::SourceWithdrawn).await {
        let reaped = worker.abort_incarnation(&epoch).await;
        registry::forget(&worker_id, &epoch);
        tracing::warn!(
            worker = %worker_id,
            reaped,
            "an erase aborted a model worker that did not release its sessions"
        );
    }
    snapshots().erase_owed.fetch_sub(1, Ordering::Relaxed);
}

/// Sealed snapshot parking as this process stands, over the vaults it
/// serves.
pub(in crate::models::worker_host) fn status() -> SnapshotStatus {
    let policy = policy();
    let vaults: Vec<Arc<Vault>> = guard(&snapshots().vaults)
        .values()
        .filter_map(Weak::upgrade)
        .collect();
    let counts = &snapshots().counts;
    let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    let skip = |skip: Skip| read(&counts.skips[skip as usize]);
    let mut status = SnapshotStatus {
        enabled: policy.default.enabled,
        disk_budget_bytes: policy.default.disk_bytes,
        snapshots: Some(0),
        sealed_bytes: Some(0),
        in_flight_bytes: Some(0),
        evicted: Some(0),
        skipped: Some(0),
        release_owed: registry::release_owed(),
        erase_copies_pending: snapshots().erase_owed.load(Ordering::Relaxed),
        lock_restarts: snapshots().lock_restarts.load(Ordering::Relaxed),
        last_lock: guard(&snapshots().last_lock).clone(),
        parks: read(&counts.parks),
        seals: read(&counts.seals),
        opens: read(&counts.opens),
        imports: read(&counts.imports),
        replays: read(&counts.replays),
        restores_cold: read(&counts.restores_cold),
        skips: SnapshotSkips {
            budget: skip(Skip::Budget),
            unknown_room: skip(Skip::UnknownRoom),
            no_room: skip(Skip::NoRoom),
            kept_local: skip(Skip::KeptLocal),
            oversize: skip(Skip::Oversize),
            unsupported: skip(Skip::Unsupported),
            short: skip(Skip::Short),
        },
    };
    let add = |total: &mut Option<u64>, part: Option<u64>| {
        *total = total
            .zip(part)
            .map(|(total, part)| total.saturating_add(part));
    };
    for vault in vaults {
        let usage = vault.snapshot_ledger().usage().ok();
        let in_flight = usage.map(|usage| usage.reserved_bytes.saturating_add(usage.staged_bytes));
        add(&mut status.snapshots, usage.map(|usage| usage.snapshots));
        add(
            &mut status.sealed_bytes,
            usage.and_then(|usage| usage.sealed_bytes),
        );
        add(&mut status.in_flight_bytes, in_flight);
        add(&mut status.evicted, usage.map(|usage| usage.evicted));
        add(&mut status.skipped, usage.map(|usage| usage.skipped));
    }
    status
}
