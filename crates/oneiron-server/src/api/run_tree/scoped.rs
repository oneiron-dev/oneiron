//! The run tree as a caller's current read authority admits it (FIX 8220,
//! 8221): one projector for the intervention reply, its keyed replay and the
//! observe stream.
//!
//! The run tree's read authority is the run-tree GET's own: `core:read` on a
//! credential no record list narrows, still live now, whose read lane its
//! credential still builds where its connection sits. A caller that acts
//! without it keeps its act: the reply then carries no tree. The observe
//! stream judges it again before each snapshot it sends, at each
//! credential revoke this vault commits (FIX 10381), and when the vault's
//! authority-log head has moved, as a revoke another process wrote on the
//! same vault moves it (FIX 11743), and ends, with no final snapshot, once
//! it no longer holds.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::response::sse::Event;
use futures_util::{Stream, stream};
use tokio::sync::broadcast::{Receiver, error::RecvError};
use tokio::sync::watch;

use super::encode;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

/// Whether `auth` reads run trees now, as the run-tree GET admits it: the
/// read scope, no record narrowing, a credential still live (its revoke and
/// expiry folded), and a read lane its credential still builds at its
/// destination. Never rebuilt from the actor's class.
pub(super) fn reads_run_tree(server: &SyncServer, auth: &CoreAuth) -> bool {
    auth.require(CoreScope::Read).is_ok()
        && auth.require_unrestricted_record_scope().is_ok()
        && auth.credential_is_live(&server.vault)
        && crate::api::scoped_read_for_core_auth(&server.vault, auth).is_ok()
}

/// The tree of `run_id` as `auth` may read it now: `None` without read
/// authority, or when no snapshot could be made. An act's reply carries it
/// beside its committed effect and never fails for it (FIX 8220): a run id is
/// free text its proposer chose, so only the attempt id is logged.
pub(super) fn intervention_tree(
    server: &SyncServer,
    auth: &CoreAuth,
    run_id: &str,
    attempt_id: &str,
) -> Option<oneiron::RunTree> {
    if !reads_run_tree(server, auth) {
        return None;
    }
    match oneiron::RunTreeAdapter::new(&server.vault).read_run(run_id) {
        Ok(tree) => Some(tree),
        Err(error) => {
            tracing::error!(kind = ?error.kind(), attempt_id = %attempt_id, "core run tree intervention snapshot failed");
            None
        }
    }
}

/// How often an idle observe stream reads the vault's authority-log head
/// (FIX 11743): a revoke another process writes sends no notice to this
/// one, and the head's move is judged as a notice is. A read, never a
/// deadline: the stream ends only when its credential no longer holds.
const AUTHORITY_HEAD_POLL: Duration = Duration::from_secs(2);

/// The observe stream's state between emissions.
struct Observe {
    server: Arc<SyncServer>,
    auth: CoreAuth,
    receiver: Receiver<()>,
    /// The vault's credential revocation notice: an idle stream judges its
    /// credential again at each revoke, not only at its next change.
    revocations: watch::Receiver<u64>,
    /// The vault's authority-log head as the stream last read it; `None`
    /// when the read failed.
    authority_head: Option<u64>,
    run_id: String,
    previous: String,
    first: bool,
    done: bool,
}

/// The observe stream for `run_id`: `initial`, then each changed snapshot,
/// each sent only while `auth` still reads run trees (FIX 8221). The check
/// runs before the first emission and again after every wait, before the
/// tree is read for it, and at each revoke notice `revocations` hears (FIX
/// 10381); once it fails the stream ends.
pub(super) fn observe(
    server: Arc<SyncServer>,
    auth: CoreAuth,
    receiver: Receiver<()>,
    revocations: watch::Receiver<u64>,
    run_id: String,
    initial: String,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let authority_head = server.vault.authority_log_head().ok();
    let state = Observe {
        server,
        auth,
        receiver,
        revocations,
        authority_head,
        run_id,
        previous: initial,
        first: true,
        done: false,
    };
    stream::unfold(state, |mut state| async move {
        if state.done {
            return None;
        }
        if state.first {
            if !reads_run_tree(&state.server, &state.auth) {
                return None;
            }
            state.first = false;
            let event = Event::default()
                .event("run-tree")
                .data(state.previous.clone());
            return Some((Ok(event), state));
        }
        loop {
            tokio::select! {
                changed = state.receiver.recv() => match changed {
                    Ok(()) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return None,
                },
                revoked = state.revocations.changed() => {
                    // A revoke changes no tree: judge the credential and
                    // keep waiting while it still holds.
                    if revoked.is_err() || !reads_run_tree(&state.server, &state.auth) {
                        return None;
                    }
                    continue;
                }
                () = tokio::time::sleep(AUTHORITY_HEAD_POLL) => {
                    // FIX 11743: another process's revoke moves the head and
                    // sends no notice here; a moved head is judged as one.
                    let head = state.server.vault.authority_log_head().ok();
                    if head != state.authority_head {
                        state.authority_head = head;
                        if !reads_run_tree(&state.server, &state.auth) {
                            return None;
                        }
                    }
                    continue;
                }
            }
            if !reads_run_tree(&state.server, &state.auth) {
                return None;
            }
            let current = oneiron::RunTreeAdapter::new(&state.server.vault)
                .read_run(&state.run_id)
                .ok()
                .and_then(|tree| encode::run_tree_json(tree).ok());
            let Some(current) = current else {
                state.done = true;
                let event = Event::default().event("error").data("run_tree_read_failed");
                return Some((Ok(event), state));
            };
            // Co-commits and other runs carry only invalidations. They do
            // not expose names, counts or a frame for unrelated work.
            if current == state.previous {
                continue;
            }
            state.previous = current;
            let event = Event::default()
                .event("run-tree")
                .data(state.previous.clone());
            return Some((Ok(event), state));
        }
    })
}
