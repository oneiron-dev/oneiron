//! Which facade row call keeps its verb hooks' records for its live session
//! only (FIX 4283; Engine ruling 10-19). The hooks run on every call; a call
//! that keeps no record keeps their receipts, saved runs, blocks, intents
//! and ask pauses with its session, in this process, never in the vault. The
//! engine's boundary decides ([`verb_hook_boundary::hook_session`]) from the
//! row and the principal-bound anonymous check, never from a header alone.

use oneiron::task_verb::verb_hook_boundary::{self, HookSession};
use oneiron::{EdgeActorClass, EntityId};

use super::{FacadeCall, facade_invocation};
use crate::api::credential_memory;
use crate::server::SyncServer;

/// The session a facade call of row `verb` keeps its verb hooks' records
/// for, when it keeps no record. A caller the facade binds an actor to
/// (`bound`) is judged on its credential's surface with the off-record
/// session its request names, as the row's own door reads it. One it binds
/// none to (a host's root, which names no person and so binds no session)
/// is judged by its row alone.
pub(super) fn facade_hook_session(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    bound: Option<(EntityId, EdgeActorClass)>,
    verb: &str,
) -> Option<HookSession> {
    let auth = call.auth();
    let memory = bound.and_then(|(actor, class)| {
        facade_invocation(
            credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality()),
            call,
        )
        .ok()
    });
    verb_hook_boundary::hook_session(memory.as_ref(), verb)
}
