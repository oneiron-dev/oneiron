//! The coordinator's registry: for each managed worker, the incarnation its
//! sessions live on, whether that incarnation serves sessions, its sessions
//! by binding, and those whose release is still owed. In memory only: a new
//! epoch empties it, and nothing here is persisted or restored.
//!
//! Each session is in one phase (V2-R3): ready, a parking candidate once it
//! published under a whole dependency set, parking while its checkpoint is
//! exported and sealed, or restoring while a sealed snapshot is imported
//! into it. A session restored from a kept snapshot holds that snapshot's
//! retention pin until its release is acknowledged or its incarnation is
//! reaped. Every plaintext copy the host holds of a vault's snapshot (a
//! region or a buffer) is a [`HostCopy`] counted against that vault, so a
//! lock can wait for its vault's to go.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Instant;

use oneiron::EntityId;
use oneiron::inference_snapshot::SnapshotId;
use oneiron::llm::{
    CanonicalCheckpointRef, ManifestDigest, MessageStamp, SessionBinding, SessionDrop,
    SessionHandle, SessionInvalidation, SessionKey, SessionOp, SessionReleased, SessionResidency,
    SessionTarget, VaultRef,
};
use oneiron_driver::InferenceWorker;
use serde_json::Value as JsonValue;
use tokio::sync::Notify;

use super::{CheckpointAuthority, SnapshotScope, lifecycle, policy};
use crate::models::native_exl3::{OpFault, session_send};

/// Every managed worker's sessions, by worker id: held by the process's one
/// worker host, beside the supervisors.
#[derive(Default)]
pub(in crate::models::worker_host) struct Registry(Mutex<BTreeMap<String, Worker>>);

/// Where a worker's sessions are reached: its current incarnation's socket
/// and epoch, and its supervisor, whose activity the answers feed.
#[derive(Clone)]
pub(super) struct Place {
    pub(super) socket: PathBuf,
    pub(super) epoch: String,
    pub(super) worker: InferenceWorker,
}

/// Whether an incarnation serves sessions, once its hello was read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Serves {
    Unasked,
    No,
    /// It serves every op a session needs, and those of `Ops` it names.
    Yes(Ops),
}

/// The optional ops an incarnation serves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Ops {
    /// `session.restore`.
    pub(super) restore: bool,
    /// `session.export` and `session.import`, in the snapshot format this
    /// side speaks.
    pub(super) snapshot: bool,
}

/// One worker incarnation's sessions.
pub(super) struct Worker {
    pub(super) place: Place,
    pub(super) serves: Serves,
    pub(super) sessions: BTreeMap<SessionBinding, Session>,
    /// Sessions dropped whose release the worker has not yet answered:
    /// their bytes stay charged until it does.
    releasing: BTreeMap<SessionHandle, Owed>,
    /// FIX 10632: the bindings whose history window slid, each with the
    /// canonical path (message stamps) its last turn read. Their turns run
    /// plain until a turn's path extends the one marked.
    pub(super) sliding: BTreeMap<SessionBinding, Vec<MessageStamp>>,
}

/// A session whose release is owed: its vault, the target its release
/// names, the bytes it holds until the worker answers, and the kept
/// snapshot it was restored from, pinned until then.
struct Owed {
    vault: VaultRef,
    target: SessionTarget,
    residency: SessionResidency,
    lease: Option<SnapshotId>,
}

/// Where a session stands for parking and restore.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    /// Serving turns.
    Ready,
    /// Published under a whole dependency set, unused since `since`: a
    /// sweep parks it once it has idled long enough, or under pressure.
    Candidate { since: Instant },
    /// Its checkpoint is being exported and sealed. A turn that comes for
    /// it takes it back, and the park lets it be.
    Parking,
    /// A kept snapshot is being imported into it: no turn forks it until
    /// it is published.
    Restoring,
}

/// What a session's published checkpoint was admitted under, kept for its
/// park: the turn's authority, the scope a snapshot of it is kept under,
/// and the reply that ended it, by id.
pub(super) struct Basis {
    pub(super) authority: Arc<dyn CheckpointAuthority>,
    pub(super) scope: SnapshotScope,
    pub(super) head: EntityId,
    pub(super) message: EntityId,
}

/// One session: its key, its handle on the incarnation, the generation the
/// host expects, what it published, and the turn whose commit it awaits.
pub(super) struct Session {
    pub(super) key: SessionKey,
    pub(super) handle: SessionHandle,
    pub(super) generation: u64,
    pub(super) published: Option<CanonicalCheckpointRef>,
    pub(super) residency: SessionResidency,
    pub(super) pending: Option<PendingTurn>,
    /// Why its published checkpoint stopped serving, seen at a fork: it is
    /// dropped instead of advanced.
    pub(super) stale: Option<SessionInvalidation>,
    /// The path (message stamps) its published checkpoint holds: the
    /// canonical messages, the newest user message and the reply of the
    /// turn it succeeded. A later turn's canonical path attaches only when
    /// it starts with it (FIX 10632).
    pub(super) path: Vec<MessageStamp>,
    pub(super) phase: Phase,
    /// What its published checkpoint was admitted under, when a park may
    /// keep a snapshot of it.
    pub(super) basis: Option<Arc<Basis>>,
    /// The kept snapshot it was restored from, pinned until its release.
    pub(super) lease: Option<SnapshotId>,
    /// The frontier a restore published, until its first fork: an attach
    /// below it replayed the suffix past the state the snapshot carried.
    pub(super) restored: Option<u64>,
}

impl Session {
    pub(super) fn target(&self) -> SessionTarget {
        SessionTarget {
            handle: self.handle,
            binding: self.key.binding(),
        }
    }
}

/// A turn that ran on a session, kept until its reply is committed: its
/// manifest, the canonical path it forked at (wire messages), its newest
/// user message, its tools, and the checkpoint it forked from.
pub(super) struct PendingTurn {
    pub(super) manifest: ManifestDigest,
    pub(super) canonical: Vec<JsonValue>,
    pub(super) newest: JsonValue,
    pub(super) tools: Option<JsonValue>,
    pub(super) base: Option<CanonicalCheckpointRef>,
}

pub(super) fn lock() -> MutexGuard<'static, BTreeMap<String, Worker>> {
    super::super::host()
        .sessions
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// `worker_id`'s entry for the incarnation at `place`. Another epoch or
/// socket starts it empty: the sessions of the incarnation that ended went
/// with it, and nothing is sent to it.
pub(super) fn bind<'a>(
    workers: &'a mut BTreeMap<String, Worker>,
    worker_id: &str,
    place: &Place,
) -> &'a mut Worker {
    let current = workers.get(worker_id).is_some_and(|worker| {
        worker.place.epoch == place.epoch && worker.place.socket == place.socket
    });
    if !current {
        let ended = workers.insert(
            worker_id.to_owned(),
            Worker {
                place: place.clone(),
                serves: Serves::Unasked,
                sessions: BTreeMap::new(),
                releasing: BTreeMap::new(),
                sliding: BTreeMap::new(),
            },
        );
        // The incarnation that ended was reaped: its leases go with it.
        if let Some(ended) = ended {
            unpin(ended.leases());
        }
    }
    workers
        .get_mut(worker_id)
        .unwrap_or_else(|| unreachable!("the entry was just bound"))
}

/// `worker_id`'s entry when it is still the incarnation at `place`; `None`
/// once another has replaced it.
pub(super) fn current<'a>(
    workers: &'a mut BTreeMap<String, Worker>,
    worker_id: &str,
    place: &Place,
) -> Option<&'a mut Worker> {
    workers
        .get_mut(worker_id)
        .filter(|worker| worker.place.epoch == place.epoch && worker.place.socket == place.socket)
}

impl Worker {
    /// Takes the session at `binding` out of service: no turn reaches it
    /// again, and its release is owed until [`release`] hears the worker.
    pub(super) fn retire(&mut self, binding: &SessionBinding) -> Option<(SessionTarget, Place)> {
        let session = self.sessions.remove(binding)?;
        let owed = self.owe(
            session.key.anchor.vault,
            session.target(),
            session.residency,
        );
        if let Some(entry) = self.releasing.get_mut(&session.handle) {
            entry.lease = session.lease;
        }
        Some(owed)
    }

    /// Owes the release of `target`, a handle of `vault` holding
    /// `residency`, whether or not a session of it was registered: its
    /// target and place, for that release.
    pub(super) fn owe(
        &mut self,
        vault: VaultRef,
        target: SessionTarget,
        residency: SessionResidency,
    ) -> (SessionTarget, Place) {
        self.releasing.insert(
            target.handle,
            Owed {
                vault,
                target: target.clone(),
                residency,
                lease: None,
            },
        );
        (target, self.place.clone())
    }

    /// The kept snapshots this incarnation's sessions and owed releases
    /// hold pinned, by vault.
    fn leases(&self) -> Vec<(VaultRef, SnapshotId)> {
        self.sessions
            .values()
            .filter_map(|session| Some((session.key.anchor.vault, session.lease?)))
            .chain(
                self.releasing
                    .values()
                    .filter_map(|owed| Some((owed.vault, owed.lease?))),
            )
            .collect()
    }

    /// The bindings of every other session on `key`'s conversation: one
    /// conversation keeps one session per incarnation.
    pub(super) fn rivals(&self, key: &SessionKey) -> Vec<(SessionBinding, SessionInvalidation)> {
        self.sessions
            .iter()
            .filter(|(_, session)| {
                session.key.anchor.vault == key.anchor.vault
                    && session.key.anchor.conversation == key.anchor.conversation
                    && session.key.binding() != key.binding()
            })
            .map(|(binding, session)| (*binding, policy::replaced(&session.key, key)))
            .collect()
    }

    /// The unique bytes this incarnation's sessions hold, those still being
    /// released among them; `None` when any of them is unmeasured.
    fn held_bytes(&self) -> Option<u64> {
        self.sessions
            .values()
            .map(|session| session.residency)
            .chain(self.releasing.values().map(|owed| owed.residency))
            .try_fold(0_u64, |total, residency| {
                residency
                    .unique_bytes
                    .map(|bytes| total.saturating_add(bytes))
            })
    }
}

/// Sends a retired session's `session.drop` and waits for the worker's
/// release; only then does it leave the accounting. A worker that does not
/// answer keeps it charged until its incarnation ends.
pub(super) async fn release(target: SessionTarget, place: Place, reason: SessionInvalidation) {
    let _ = release_acked(target, place, reason).await;
}

/// [`release`], answering whether the worker acknowledged it.
pub(super) async fn release_acked(
    target: SessionTarget,
    place: Place,
    reason: SessionInvalidation,
) -> bool {
    let handle = target.handle;
    let body = SessionDrop {
        target,
        op_id: policy::next_op_id(),
        reason,
    };
    let answer: Result<SessionReleased, OpFault> = session_send(
        &place.socket,
        &place.epoch,
        SessionOp::Drop,
        &body,
        None,
        &place.worker,
    )
    .await;
    let released = match answer {
        Ok(answer) => answer.released,
        Err(OpFault::Refused(code)) => code == "unknown_session",
        Err(OpFault::Cut) => false,
    };
    if !released {
        tracing::info!(?reason, "a model session's release was not answered");
        return false;
    }
    let lease = {
        let mut workers = lock();
        let worker = workers
            .values_mut()
            .find(|worker| worker.place.epoch == place.epoch);
        worker.and_then(|worker| {
            let owed = worker.releasing.remove(&handle);
            tracing::debug!(
                ?reason,
                held_bytes = ?worker.held_bytes(),
                "a model session was released"
            );
            owed.and_then(|owed| Some((owed.vault, owed.lease?)))
        })
    };
    unpin(lease);
    true
}

/// Drops the retention pin of each kept snapshot `leases` names.
fn unpin(leases: impl IntoIterator<Item = (VaultRef, SnapshotId)>) {
    for (vault, id) in leases {
        if let Some(vault) = lifecycle::vault(&vault) {
            vault.snapshot_ledger().unpin(&id);
        }
    }
}

/// Takes every session of `vault`, on every worker, out of service, its
/// release owed from now on: the target and place of each release `vault`
/// owes, those owed before this among them, so each is sent again.
pub(super) fn retire_vault(vault: &VaultRef) -> Vec<(SessionTarget, Place)> {
    let mut workers = lock();
    let mut retired = Vec::new();
    for worker in workers.values_mut() {
        let bindings: Vec<SessionBinding> = worker
            .sessions
            .iter()
            .filter(|(_, session)| session.key.anchor.vault == *vault)
            .map(|(binding, _)| *binding)
            .collect();
        for binding in bindings {
            worker.retire(&binding);
        }
        retired.extend(
            worker
                .releasing
                .values()
                .filter(|owed| owed.vault == *vault)
                .map(|owed| (owed.target.clone(), worker.place.clone())),
        );
    }
    retired
}

/// Forgets `worker_id`'s incarnation `epoch`, which an abort ended: its
/// sessions and owed releases went with its process, and so do their
/// leases.
pub(super) fn forget(worker_id: &str, epoch: &str) {
    let ended = {
        let mut workers = lock();
        if workers
            .get(worker_id)
            .is_some_and(|worker| worker.place.epoch == epoch)
        {
            workers.remove(worker_id)
        } else {
            None
        }
    };
    if let Some(ended) = ended {
        unpin(ended.leases());
    }
}

/// The releases sent and not yet acknowledged, over every worker.
pub(super) fn release_owed() -> u64 {
    lock()
        .values()
        .map(|worker| worker.releasing.len() as u64)
        .sum()
}

/// [`release`] on a task of its own.
pub(super) fn release_later(target: SessionTarget, place: Place, reason: SessionInvalidation) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(release(target, place, reason));
    }
}

/// Retires the session at `binding` on `worker_id`'s incarnation `epoch`,
/// if it is still there, and releases it on a task of its own.
pub(super) fn drop_session(
    worker_id: &str,
    epoch: &str,
    binding: &SessionBinding,
    reason: SessionInvalidation,
) {
    let retired = {
        let mut workers = lock();
        workers
            .get_mut(worker_id)
            .filter(|worker| worker.place.epoch == epoch)
            .and_then(|worker| worker.retire(binding))
    };
    if let Some((target, place)) = retired {
        release_later(target, place, reason);
    }
}

/// Sends one session op to `place`; a fault is the reason its session goes.
pub(super) async fn send<B: serde::Serialize, R: serde::de::DeserializeOwned>(
    place: &Place,
    op: SessionOp,
    body: &B,
    conversation: Option<&JsonValue>,
) -> Result<R, SessionInvalidation> {
    session_send(
        &place.socket,
        &place.epoch,
        op,
        body,
        conversation,
        &place.worker,
    )
    .await
    .map_err(|fault| match fault {
        OpFault::Refused(code) => policy::refused(&code),
        OpFault::Cut => SessionInvalidation::Evicted,
    })
}

/// The host's plaintext copies of each vault's snapshots, counted while
/// they live.
#[derive(Default)]
struct Copies {
    live: Mutex<BTreeMap<VaultRef, u64>>,
    dropped: Notify,
}

static COPIES: OnceLock<Copies> = OnceLock::new();

fn copies() -> &'static Copies {
    COPIES.get_or_init(Copies::default)
}

/// One plaintext copy of a vault's snapshot the host holds (a region an
/// export passed or an import sends, or a buffer read from one or opened
/// from a sealed body), counted against its vault until it drops.
pub(super) struct HostCopy<T> {
    vault: VaultRef,
    copy: Option<T>,
}

impl<T> HostCopy<T> {
    /// Counts `copy` against `vault` from now until it drops.
    pub(super) fn hold(vault: VaultRef, copy: T) -> Self {
        *copies()
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(vault)
            .or_insert(0) += 1;
        Self {
            vault,
            copy: Some(copy),
        }
    }

    pub(super) fn get(&self) -> &T {
        self.copy
            .as_ref()
            .unwrap_or_else(|| unreachable!("a copy is held until it drops"))
    }
}

impl<T> Drop for HostCopy<T> {
    /// The copy goes first; only then does its count drop.
    fn drop(&mut self) {
        drop(self.copy.take());
        let copies = copies();
        {
            let mut live = copies.live.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = live.get_mut(&self.vault) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    live.remove(&self.vault);
                }
            }
        }
        copies.dropped.notify_waiters();
    }
}

/// The plaintext copies of `vault`'s snapshots the host holds now.
pub(super) fn host_copies(vault: &VaultRef) -> u64 {
    copies()
        .live
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(vault)
        .copied()
        .unwrap_or(0)
}

/// Waits until the host holds no plaintext copy of `vault`'s snapshots, or
/// `deadline` passes: the copies still held then.
pub(super) async fn copies_dropped(vault: &VaultRef, deadline: tokio::time::Instant) -> u64 {
    loop {
        let dropped = copies().dropped.notified();
        let left = host_copies(vault);
        if left == 0 {
            return 0;
        }
        if tokio::time::timeout_at(deadline, dropped).await.is_err() {
            return host_copies(vault);
        }
    }
}
