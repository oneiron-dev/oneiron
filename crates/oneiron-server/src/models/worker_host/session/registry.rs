//! The coordinator's registry: for each managed worker, the incarnation its
//! sessions live on, whether that incarnation serves sessions, its sessions
//! by binding, and those whose release is still owed. In memory only: a new
//! epoch empties it, and nothing here is persisted or restored.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use oneiron::llm::{
    CanonicalCheckpointRef, ManifestDigest, SessionBinding, SessionDrop, SessionHandle,
    SessionInvalidation, SessionKey, SessionOp, SessionReleased, SessionResidency, SessionTarget,
};
use oneiron_driver::InferenceWorker;
use serde_json::Value as JsonValue;

use super::policy;
use crate::models::native_exl3::{OpFault, session_send};

static REGISTRY: OnceLock<Mutex<BTreeMap<String, Worker>>> = OnceLock::new();

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
    /// It serves every op a session needs; `restore` too, when it says so.
    Yes {
        restore: bool,
    },
}

/// One worker incarnation's sessions.
pub(super) struct Worker {
    pub(super) place: Place,
    pub(super) serves: Serves,
    pub(super) sessions: BTreeMap<SessionBinding, Session>,
    /// Sessions dropped whose release the worker has not yet answered:
    /// their bytes stay charged until it does.
    releasing: BTreeMap<SessionHandle, SessionResidency>,
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
    REGISTRY
        .get_or_init(Mutex::default)
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
        workers.insert(
            worker_id.to_owned(),
            Worker {
                place: place.clone(),
                serves: Serves::Unasked,
                sessions: BTreeMap::new(),
                releasing: BTreeMap::new(),
            },
        );
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
        self.releasing.insert(session.handle, session.residency);
        Some((session.target(), self.place.clone()))
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
            .chain(self.releasing.values().copied())
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
        return;
    }
    let mut workers = lock();
    if let Some(worker) = workers
        .values_mut()
        .find(|worker| worker.place.epoch == place.epoch)
    {
        worker.releasing.remove(&handle);
        tracing::debug!(
            ?reason,
            held_bytes = ?worker.held_bytes(),
            "a model session was released"
        );
    }
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
