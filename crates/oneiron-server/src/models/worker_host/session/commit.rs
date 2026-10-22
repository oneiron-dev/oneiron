//! A committed reply's canonical successor (DESIGN-V2 §3.2 steps 4-5): the
//! turn's canonical path with its newest user message and the reply is
//! appended and verified, only its new suffix is computed against the
//! retained prefix, the turn's authority is rechecked, and the successor is
//! published by compare-and-swap on the base checkpoint's token digest and
//! HEAD, all on a task of its own. Any step that does not hold drops the
//! session; the next turn then starts cold, never from unverified state.
use std::sync::Arc;

use oneiron::llm::{
    CanonicalCheckpointRef, ManifestDigest, SegmentManifest, SessionAppend, SessionAppended,
    SessionBinding, SessionCheckpoint, SessionCheckpointed, SessionInvalidation, SessionOp,
    SessionOpStamp, SessionSuffixCommit, SessionSuffixStaged, SessionTarget,
};
use serde_json::{Value as JsonValue, json};

use super::policy::{self, SuffixPlan};
use super::registry::{self, PendingTurn, Place, send};
use super::{AuthorityVerdict, CheckpointAuthority, ReplyCommit};

/// [`super::reply_committed`] on this platform: claims the turn's pending
/// successor and advances it on a task of its own.
pub(super) fn reply_committed(
    manifest: &SegmentManifest,
    commit: ReplyCommit,
    authority: Arc<dyn CheckpointAuthority>,
) {
    let Some(claimed) = claim(manifest.digest()) else {
        return;
    };
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(advance(claimed, commit, authority));
    }
}

/// A session's pending turn, taken for its commit.
struct Claimed {
    worker_id: String,
    place: Place,
    binding: SessionBinding,
    target: SessionTarget,
    generation: u64,
    pending: PendingTurn,
}

/// Takes the pending turn `digest` names from its session. A session whose
/// fork showed it stale is dropped instead.
fn claim(digest: &ManifestDigest) -> Option<Claimed> {
    let mut stale = None;
    let claimed = {
        let mut workers = registry::lock();
        workers.iter_mut().find_map(|(worker_id, worker)| {
            let (binding, session) = worker.sessions.iter_mut().find(|(_, session)| {
                session
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.manifest == *digest)
            })?;
            let binding = *binding;
            let pending = session.pending.take()?;
            if let Some(reason) = session.stale {
                stale = worker
                    .retire(&binding)
                    .map(|(target, place)| (target, place, reason));
                return None;
            }
            Some(Claimed {
                worker_id: worker_id.clone(),
                place: worker.place.clone(),
                binding,
                target: session.target(),
                generation: session.generation,
                pending,
            })
        })
    };
    if let Some((target, place, reason)) = stale {
        registry::release_later(target, place, reason);
    }
    claimed
}

/// The successor's path: the canonical messages the turn forked at, its
/// newest user message, then the reply as the log will read it.
fn successor(pending: PendingTurn, text: &str) -> JsonValue {
    let mut messages = pending.canonical;
    messages.push(pending.newest);
    messages.push(json!({ "role": "assistant", "content": text }));
    let mut conversation = json!({ "messages": messages });
    if let (Some(tools), Some(fields)) = (pending.tools, conversation.as_object_mut()) {
        fields.insert("tools".to_owned(), tools);
    }
    conversation
}

async fn advance(claimed: Claimed, commit: ReplyCommit, authority: Arc<dyn CheckpointAuthority>) {
    let Claimed {
        worker_id,
        place,
        binding,
        target,
        generation,
        pending,
    } = claimed;
    let base = pending.base.clone();
    let outcome = stage(&place, &target, generation, base.as_ref(), &commit, pending).await;
    let staged = match outcome {
        Ok(Some(staged)) => staged,
        Ok(None) => return,
        Err(reason) => {
            registry::drop_session(&worker_id, &place.epoch, &binding, reason);
            return;
        }
    };
    let verdict = tokio::task::spawn_blocking(move || authority.recheck(&commit)).await;
    let verdict = verdict.unwrap_or(AuthorityVerdict::Rejects(
        SessionInvalidation::DisclosureOrScope,
    ));
    if let AuthorityVerdict::Rejects(reason) = verdict {
        registry::drop_session(&worker_id, &place.epoch, &binding, reason);
        return;
    }
    let swappable = {
        let mut workers = registry::lock();
        registry::current(&mut workers, &worker_id, &place)
            .and_then(|worker| worker.sessions.get(&binding))
            .is_some_and(|session| {
                session.handle == target.handle
                    && session.generation == generation
                    && match (&session.published, &base) {
                        (Some(published), Some(base)) => published.same_point(base),
                        (None, None) => true,
                        _ => false,
                    }
            })
    };
    if !swappable {
        registry::drop_session(
            &worker_id,
            &place.epoch,
            &binding,
            SessionInvalidation::StaleHead,
        );
        return;
    }
    let body = SessionCheckpoint {
        target: target.clone(),
        stamp: SessionOpStamp {
            op_id: policy::next_op_id(),
            generation,
        },
        staged: staged.digest,
        publish: true,
    };
    let published: Result<SessionCheckpointed, SessionInvalidation> =
        send(&place, SessionOp::Checkpoint, &body, None).await;
    let published = match published {
        Ok(published) if published.ready && published.checkpoint.as_ref() == Some(&staged) => {
            published
        }
        Ok(_) => {
            registry::drop_session(
                &worker_id,
                &place.epoch,
                &binding,
                SessionInvalidation::StaleHead,
            );
            return;
        }
        Err(reason) => {
            registry::drop_session(&worker_id, &place.epoch, &binding, reason);
            return;
        }
    };
    let mut workers = registry::lock();
    if let Some(session) = registry::current(&mut workers, &worker_id, &place)
        .and_then(|worker| worker.sessions.get_mut(&binding))
        .filter(|session| session.handle == target.handle)
    {
        session.published = published.checkpoint;
        session.generation = published.generation;
        session.residency = published.residency;
    }
}

/// Appends the successor's path and computes its new suffix: the staged
/// checkpoint, or `None` when it adds nothing to what is published.
async fn stage(
    place: &Place,
    target: &SessionTarget,
    generation: u64,
    base: Option<&CanonicalCheckpointRef>,
    commit: &ReplyCommit,
    pending: PendingTurn,
) -> Result<Option<CanonicalCheckpointRef>, SessionInvalidation> {
    let path = successor(pending, &commit.text);
    let append = SessionAppend {
        target: target.clone(),
        stamp: SessionOpStamp {
            op_id: policy::next_op_id(),
            generation,
        },
        base: base.cloned(),
        head: Some(commit.head),
    };
    let appended: SessionAppended = send(place, SessionOp::Append, &append, Some(&path)).await?;
    match policy::suffix_plan(base, &appended) {
        SuffixPlan::Compute => {}
        SuffixPlan::Nothing => return Ok(None),
        SuffixPlan::Drop(reason) => return Err(reason),
    }
    let suffix = SessionSuffixCommit {
        target: target.clone(),
        stamp: SessionOpStamp {
            op_id: policy::next_op_id(),
            generation,
        },
    };
    let staged: SessionSuffixStaged = send(place, SessionOp::SuffixCommit, &suffix, None).await?;
    // The chain: a successor names its base and ends at the reply's HEAD;
    // one that does not is stale, repaired by dropping it, never trusted.
    let chained = staged.staged.parent == base.map(|base| base.digest)
        && staged.staged.head == Some(commit.head)
        && staged.staged.frontier_tokens == appended.staged_tokens;
    if !chained {
        return Err(SessionInvalidation::StaleHead);
    }
    tracing::debug!(
        computed_tokens = staged.computed_tokens,
        frontier_tokens = staged.staged.frontier_tokens,
        "a model session staged its canonical successor"
    );
    Ok(Some(staged.staged))
}
