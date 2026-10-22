//! The run tree as a caller's current read authority admits it (FIX 8220,
//! 8221): one projector for the intervention reply, its keyed replay and the
//! observe stream.
//!
//! The run tree's read authority is the run-tree GET's own: `core:read` on a
//! credential no record list narrows, still live now, whose read lane its
//! credential still builds where its connection sits. A caller that acts
//! without it keeps its act: the reply then carries no tree. The observe
//! stream judges it again before each snapshot it sends, and ends, with no
//! final snapshot, once it no longer holds.

use std::convert::Infallible;
use std::sync::Arc;

use axum::response::sse::Event;
use futures_util::{Stream, stream};
use tokio::sync::broadcast::{Receiver, error::RecvError};

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

/// The observe stream's state between emissions.
struct Observe {
    server: Arc<SyncServer>,
    auth: CoreAuth,
    receiver: Receiver<()>,
    run_id: String,
    previous: String,
    first: bool,
    done: bool,
}

/// The observe stream for `run_id`: `initial`, then each changed snapshot,
/// each sent only while `auth` still reads run trees (FIX 8221). The check
/// runs before the first emission and again after every wait, before the
/// tree is read for it; once it fails the stream ends.
pub(super) fn observe(
    server: Arc<SyncServer>,
    auth: CoreAuth,
    receiver: Receiver<()>,
    run_id: String,
    initial: String,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let state = Observe {
        server,
        auth,
        receiver,
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
            match state.receiver.recv().await {
                Ok(()) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return None,
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
