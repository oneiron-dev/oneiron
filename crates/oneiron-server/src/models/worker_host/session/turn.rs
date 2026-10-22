//! A turn on a session: the session for its key reused or created, a
//! working branch forked at the frontier the worker verified for the turn's
//! canonical path, and the `session` field its `session.generate` carries.
//! Any step that does not hold leaves the turn to run as it always did.
use std::path::Path;

use oneiron::llm::{
    CanonicalCheckpointRef, SegmentManifest, SessionBinding, SessionCreate, SessionCreated,
    SessionFork, SessionForked, SessionGenerate, SessionInvalidation, SessionKey, SessionOp,
    SessionOpStamp, SessionResidency, SessionRestore, SessionRestored, SessionTarget,
    WorkerDescriptor,
};
use serde_json::Value as JsonValue;

use super::policy;
use super::registry::{self, PendingTurn, Place, Serves, Session, send};
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
    let restore = serves(&worker_id, &place).await?;
    let opened = session(&worker_id, &place, &key, restore).await?;
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
        let session = registry::current(&mut workers, &worker_id, &place)?
            .sessions
            .get_mut(&binding)
            .filter(|session| session.handle == opened.target.handle)?;
        session.residency = forked.residency;
        session.stale = stale;
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

/// Whether the incarnation at `place` serves sessions, from its hello the
/// first time it is asked; `Some(restore)` when it does.
async fn serves(worker_id: &str, place: &Place) -> Option<bool> {
    let known = registry::bind(&mut registry::lock(), worker_id, place).serves;
    let serves = match known {
        Serves::Unasked => {
            let capability = session_capability(&place.socket).await;
            let serves = match &capability {
                Some(capability) if policy::serves_sessions(capability) => Serves::Yes {
                    restore: capability.serves(SessionOp::Restore),
                },
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
        Serves::Yes { restore } => Some(restore),
        Serves::Unasked | Serves::No => None,
    }
}

/// The session `key` names on `place`, reused when it still serves (and,
/// when the worker moved its checkpoint off the device and serves
/// `restore`, brought back) or else created. Every other session on the
/// same conversation, and a stale one, is dropped first.
async fn session(
    worker_id: &str,
    place: &Place,
    key: &SessionKey,
    restore: bool,
) -> Option<Opened> {
    let binding = key.binding();
    let (found, retired) = {
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
        let found = worker.sessions.get(&binding).map(|session| {
            (
                Opened {
                    target: session.target(),
                    generation: session.generation,
                    published: session.published.clone(),
                },
                session.residency,
            )
        });
        (found, retired)
    };
    for (target, at, reason) in retired {
        registry::release_later(target, at, reason);
    }
    match found {
        Some((opened, residency)) => {
            resident(worker_id, place, &binding, opened, residency, restore).await
        }
        None => create(worker_id, place, key).await,
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
/// published.
async fn create(worker_id: &str, place: &Place, key: &SessionKey) -> Option<Opened> {
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
    };
    let opened = Opened {
        target: session.target(),
        generation: session.generation,
        published: None,
    };
    let mut workers = registry::lock();
    registry::current(&mut workers, worker_id, place)?
        .sessions
        .insert(key.binding(), session);
    Some(opened)
}
