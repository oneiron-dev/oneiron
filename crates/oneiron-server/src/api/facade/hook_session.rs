//! Which facade row call keeps its verb hooks' records and ask pauses for
//! its live session only (FIX 4283; Engine ruling 10-19). The hooks run on
//! every call; a call that keeps no record keeps their receipts, saved runs
//! and the call a hook's ask paused in the in-memory keep, under its live
//! session's key, never in the vault. The engine's boundary decides
//! ([`verb_hook_boundary::hook_session`]) from the row and the
//! principal-bound anonymous check, never from a header alone.

use oneiron::task_verb::verb_hook_boundary::{self, HookSession};
use oneiron::{EdgeActorClass, EntityId};

use super::{FacadeApiError, FacadeCall};
use crate::api::credential_memory;
use crate::server::SyncServer;

/// The session a facade call of row `verb` keeps its verb hooks' records
/// and ask pauses for, when it keeps no record. A caller the facade binds an
/// actor to (`bound`) is judged on its credential's surface with the
/// off-record session its request names, the invocation it names and the
/// hook pause it resumes beside it (`x-oneiron-hook-ask`), as the row's own
/// door reads them; a malformed room turn the row itself may not read never
/// turns that judgement off. One it binds none to (a host's root, which
/// names no person and so binds no session) is judged by its row alone.
///
/// # Errors
///
/// A malformed hook ask header; the boundary's refusal of a resume of a
/// hook pause that is gone.
pub(super) fn facade_hook_session(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    bound: Option<(EntityId, EdgeActorClass)>,
    verb: &str,
) -> Result<Option<HookSession>, FacadeApiError> {
    let auth = call.auth();
    let hook_ask = call.hook_ask()?;
    let memory = bound.map(|(actor, class)| {
        let memory = credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality());
        let memory = match call.session_ref() {
            Some(session_ref) => memory.in_off_record_session(session_ref),
            None => memory,
        };
        let memory = match hook_ask {
            Some(ask) => memory.with_hook_ask(ask),
            None => memory,
        };
        match call.invocation() {
            Ok(Some(invocation)) => memory.with_invocation(invocation),
            Ok(None) | Err(_) => memory,
        }
    });
    Ok(verb_hook_boundary::hook_session(memory.as_ref(), verb)?)
}
