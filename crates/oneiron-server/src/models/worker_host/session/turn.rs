//! A turn on a session: the session for its key reused or created, a
//! working branch forked at the frontier the worker verified for the turn's
//! canonical path, and the `session` field its `session.generate` carries.
//! Any step that does not hold leaves the turn to run as it always did.
//!
//! A turn whose canonical path no longer starts with the path its
//! session's published checkpoint succeeded (the history window slid, so
//! the attach would fall below every retained snapshot) runs as a plain
//! generate, with no create, fork or suffix commit, and so does every next
//! turn on that binding until one's path extends the last one's: a cached
//! turn never costs more than a plain one there (FIX 10632). A vault whose
//! snapshot admission a lock closed gets no session at all, and a session
//! created or forked while a lock ran is not registered: the turn runs
//! plain, and a handle created for it is released.
//!
//! A turn whose binding has no session on the incarnation its lease
//! reached restores one from a kept snapshot when the worker imports them
//! (`restore.rs`), and otherwise creates one. A turn that finds its session
//! parking takes it back; one that finds it restoring runs plain.
use std::path::Path;

use oneiron::llm::{
    CanonicalCheckpointRef, ManifestDigest, MessageStamp, SegmentManifest, SessionBinding,
    SessionCreate, SessionCreated, SessionFork, SessionForked, SessionGenerate,
    SessionInvalidation, SessionKey, SessionOp, SessionOpStamp, SessionResidency, SessionRestore,
    SessionRestored, SessionTarget, WorkerDescriptor,
};
use serde_json::Value as JsonValue;

use super::lifecycle::{self, Admitted, Counted};
use super::policy;
use super::registry::{self, Ops, PendingTurn, Phase, Place, Serves, Session, send};
use super::restore;
use crate::models::native_exl3::session_capability;
use crate::models::worker_host::NativeRoute;

/// What a turn forks from: its session's handle, the generation the host
/// expects, and the checkpoint it published.
struct Opened {
    target: SessionTarget,
    generation: u64,
    published: Option<CanonicalCheckpointRef>,
}

/// Opens a session turn for a call to `route`'s incarnation `epoch` at
/// `socket`, whose lease saw `observed`, sending `conversation` with
/// `params`. `manifest` must describe the call's messages exactly, name its
/// conversation and leave an ephemeral tail after its canonical path.
/// Returns the `session` field of the call's `session.generate`, or `None`
/// to send it as a plain `generate`.
pub(in crate::models) async fn open_turn(
    route: &NativeRoute,
    socket: &Path,
    epoch: &str,
    observed: Option<&WorkerDescriptor>,
    manifest: &SegmentManifest,
    conversation: &JsonValue,
    params: &JsonValue,
) -> Option<JsonValue> {
    let messages = conversation.get("messages")?.as_array()?;
    let anchor = manifest.anchor()?;
    let admitted = lifecycle::admission(&anchor.vault)?;
    let cut = policy::canonical_cut(manifest)?;
    let newest = policy::newest_user(manifest).filter(|index| *index >= cut)?;
    if !policy::describes(manifest, messages) {
        return None;
    }
    let tools = conversation.get("tools").cloned();
    let key = SessionKey {
        anchor: anchor.clone(),
        identity: observed?.identity.clone(),
        conditioning: policy::conditioning(params, tools.as_ref()),
    };
    let worker_id = route.worker.spec().worker_id.clone();
    let place = Place {
        socket: socket.to_path_buf(),
        epoch: epoch.to_owned(),
        worker: route.worker.clone(),
    };
    let ops = serves(&worker_id, &place).await?;
    let path = manifest.messages().get(..cut)?;
    if !attaches(&worker_id, &place, &key, path) {
        return None;
    }
    let turn = Turn {
        manifest: manifest.digest(),
        path,
        admitted,
    };
    let opened = session(&worker_id, &place, &key, ops, &turn).await?;
    let binding = key.binding();
    let fork = SessionFork {
        target: opened.target.clone(),
        stamp: SessionOpStamp {
            op_id: policy::next_op_id(),
            generation: opened.generation,
        },
        expected: opened.published.clone(),
        canonical_messages: u64::try_from(cut).ok()?,
    };
    let forked: SessionForked = match send(&place, SessionOp::Fork, &fork, Some(conversation)).await
    {
        Ok(forked) => forked,
        Err(reason) => {
            registry::drop_session(&worker_id, epoch, &binding, reason);
            return None;
        }
    };
    let stale = policy::stale_after_fork(opened.published.as_ref(), anchor.head, &forked);
    {
        let mut workers = registry::lock();
        // A lock since the admission keeps the fork unregistered: the lock
        // retires the session, or already has.
        if lifecycle::admission(&anchor.vault) != Some(admitted) {
            return None;
        }
        let session = registry::current(&mut workers, &worker_id, &place)?
            .sessions
            .get_mut(&binding)
            .filter(|session| session.handle == opened.target.handle)?;
        session.residency = forked.residency;
        session.stale = stale;
        session.phase = Phase::Ready;
        // A restored session's first attach below the frontier it published
        // replayed the suffix past the state its snapshot carried.
        if let Some(frontier) = session.restored.take()
            && stale.is_none()
            && forked.frontier_tokens < frontier
        {
            lifecycle::count(Counted::Replay);
        }
        session.pending = Some(PendingTurn {
            manifest: *manifest.digest(),
            canonical: messages[..cut].to_vec(),
            newest: messages.get(newest)?.clone(),
            tools,
            base: opened.published,
        });
    }
    serde_json::to_value(SessionGenerate {
        target: opened.target,
        branch: forked.branch,
        op_id: policy::next_op_id(),
    })
    .ok()
}

/// Whether a turn on `key` whose canonical path is `path` may run on a
/// session (FIX 10632). A binding marked sliding runs plain until a turn's
/// path extends the marked one, which clears the mark. A session whose
/// published checkpoint succeeded a path this one does not start with
/// cannot be attached at all: it is retired, the binding is marked, and
/// the turn runs plain.
fn attaches(worker_id: &str, place: &Place, key: &SessionKey, path: &[MessageStamp]) -> bool {
    let binding = key.binding();
    let retired = {
        let mut workers = registry::lock();
        let worker = registry::bind(&mut workers, worker_id, place);
        if let Some(marked) = worker.sliding.get(&binding) {
            let extends = path.starts_with(marked);
            if extends {
                worker.sliding.remove(&binding);
            } else {
                worker.sliding.insert(binding, path.to_vec());
            }
            return extends;
        }
        let slid = worker
            .sessions
            .get(&binding)
            .is_some_and(|session| session.published.is_some() && !path.starts_with(&session.path));
        if !slid {
            return true;
        }
        worker.sliding.insert(binding, path.to_vec());
        worker.retire(&binding)
    };
    if let Some((target, at)) = retired {
        registry::release_later(target, at, SessionInvalidation::PathChanged);
    }
    false
}

/// Whether the incarnation at `place` serves sessions, from its hello the
/// first time it is asked; the optional ops it serves when it does.
async fn serves(worker_id: &str, place: &Place) -> Option<Ops> {
    let known = registry::bind(&mut registry::lock(), worker_id, place).serves;
    let serves = match known {
        Serves::Unasked => {
            let capability = session_capability(&place.socket).await;
            let serves = match &capability {
                Some(capability) if policy::serves_sessions(capability) => Serves::Yes(Ops {
                    restore: capability.serves(SessionOp::Restore),
                    snapshot: capability.serves(SessionOp::Export)
                        && capability.serves(SessionOp::Import),
                }),
                _ => Serves::No,
            };
            if let Some(worker) = registry::current(&mut registry::lock(), worker_id, place) {
                worker.serves = serves;
            }
            serves
        }
        known => known,
    };
    match serves {
        Serves::Yes(ops) => Some(ops),
        Serves::Unasked | Serves::No => None,
    }
}

/// The turn a session is opened for: its manifest, its canonical path
/// (message stamps), and what its vault admitted it under.
struct Turn<'a> {
    manifest: &'a ManifestDigest,
    path: &'a [MessageStamp],
    admitted: Admitted,
}

/// The session `key` names on `place`, reused when it still serves (and,
/// when the worker moved its checkpoint off the device and serves
/// `restore`, brought back), or else restored from a kept snapshot, or
/// else created. Every other session on the same conversation, and a stale
/// one, is dropped first.
async fn session(
    worker_id: &str,
    place: &Place,
    key: &SessionKey,
    ops: Ops,
    turn: &Turn<'_>,
) -> Option<Opened> {
    let binding = key.binding();
    let (found, retired, restoring) = {
        let mut workers = registry::lock();
        let worker = registry::bind(&mut workers, worker_id, place);
        let mut retired = Vec::new();
        for (rival, reason) in worker.rivals(key) {
            retired.extend(
                worker
                    .retire(&rival)
                    .map(|(target, at)| (target, at, reason)),
            );
        }
        let stale = worker
            .sessions
            .get(&binding)
            .and_then(|session| session.stale);
        if let Some(reason) = stale {
            retired.extend(
                worker
                    .retire(&binding)
                    .map(|(target, at)| (target, at, reason)),
            );
        }
        let restoring = worker
            .sessions
            .get(&binding)
            .is_some_and(|session| session.phase == Phase::Restoring);
        let found = worker
            .sessions
            .get_mut(&binding)
            .filter(|_| !restoring)
            .map(|session| {
                // A park in flight lets the session be once a turn takes it.
                session.phase = Phase::Ready;
                (
                    Opened {
                        target: session.target(),
                        generation: session.generation,
                        published: session.published.clone(),
                    },
                    session.residency,
                )
            });
        (found, retired, restoring)
    };
    for (target, at, reason) in retired {
        registry::release_later(target, at, reason);
    }
    if restoring {
        return None;
    }
    match found {
        Some((opened, residency)) => {
            resident(worker_id, place, &binding, opened, residency, ops.restore).await
        }
        None => {
            let restored = if ops.snapshot {
                restore::restore(
                    worker_id,
                    place,
                    key,
                    turn.manifest,
                    turn.path,
                    turn.admitted,
                )
                .await
            } else {
                None
            };
            match restored {
                Some(restored) => Some(Opened {
                    target: restored.target,
                    generation: restored.generation,
                    published: Some(restored.checkpoint),
                }),
                None => create(worker_id, place, key, turn.admitted).await,
            }
        }
    }
}

/// `opened` as it may fork now: as it is when its checkpoint is resident or
/// it has none, brought back by `session.restore` when the worker serves
/// it, or else dropped.
async fn resident(
    worker_id: &str,
    place: &Place,
    binding: &SessionBinding,
    opened: Opened,
    residency: SessionResidency,
    restore: bool,
) -> Option<Opened> {
    let Some(checkpoint) = opened.published.clone() else {
        return Some(opened);
    };
    if residency.resident {
        return Some(opened);
    }
    let restored: Result<SessionRestored, SessionInvalidation> = if restore {
        let body = SessionRestore {
            target: opened.target.clone(),
            stamp: SessionOpStamp {
                op_id: policy::next_op_id(),
                generation: opened.generation,
            },
            checkpoint,
        };
        send(place, SessionOp::Restore, &body, None).await
    } else {
        Err(SessionInvalidation::ResidencyLost)
    };
    match restored {
        Ok(restored) if restored.residency.resident => {
            let mut workers = registry::lock();
            if let Some(session) = registry::current(&mut workers, worker_id, place)
                .and_then(|worker| worker.sessions.get_mut(binding))
            {
                session.residency = restored.residency;
            }
            Some(opened)
        }
        Ok(_) => {
            registry::drop_session(
                worker_id,
                &place.epoch,
                binding,
                SessionInvalidation::ResidencyLost,
            );
            None
        }
        Err(reason) => {
            registry::drop_session(worker_id, &place.epoch, binding, reason);
            None
        }
    }
}

/// A new session for `key` on `place`: not warm until a checkpoint is
/// published. It registers only while its vault admits under `admitted`,
/// read under the registry's lock; otherwise its handle is released.
async fn create(
    worker_id: &str,
    place: &Place,
    key: &SessionKey,
    admitted: Admitted,
) -> Option<Opened> {
    let body = SessionCreate {
        binding: key.binding(),
        op_id: policy::next_op_id(),
    };
    let created: SessionCreated = send(place, SessionOp::Create, &body, None).await.ok()?;
    let session = Session {
        key: key.clone(),
        handle: created.handle,
        generation: created.generation,
        published: None,
        residency: SessionResidency::default(),
        pending: None,
        stale: None,
        path: Vec::new(),
        phase: Phase::Ready,
        basis: None,
        lease: None,
        restored: None,
    };
    let opened = Opened {
        target: session.target(),
        generation: session.generation,
        published: None,
    };
    let refused = {
        let mut workers = registry::lock();
        let worker = registry::current(&mut workers, worker_id, place)?;
        if lifecycle::admission(&key.anchor.vault) == Some(admitted) {
            worker.sessions.insert(key.binding(), session);
            None
        } else {
            Some(worker.owe(key.anchor.vault, session.target(), session.residency))
        }
    };
    if let Some((target, at)) = refused {
        registry::release_later(target, at, SessionInvalidation::Evicted);
        return None;
    }
    Some(opened)
}
