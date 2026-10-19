//! The hook pause a chat turn's retry resumes (FIX 5526): the ask handle a
//! hook's Pending gave, named in `x-oneiron-hook-ask` beside the turn's
//! `x-oneiron-invocation`, as on the facade. It names the pause only: the
//! turn keeps its caller's credential and session. Only a turn that keeps no
//! record reads it, since only its hooks' pauses live in its session alone:
//! a pause it names that the session no longer holds refuses, never running
//! as a new turn. Any other turn resumes its saved ask by its invocation, as
//! before, and its header is not read.

use axum::http::HeaderMap;
use oneiron::EntityId;
use oneiron::memory::Memory;
use oneiron::task_verb::verb_hook_boundary;

/// The header a retry names the hook pause it resumes in.
const HOOK_ASK_HEADER: &str = "x-oneiron-hook-ask";

/// The hook pause a turn on `memory`, its caller's own surface, names as the
/// one it resumes: `None` for a turn that keeps its record, or names none.
pub(super) fn named(headers: &HeaderMap, memory: &Memory<'_>) -> Option<EntityId> {
    if !verb_hook_boundary::keeps_no_record(memory) {
        return None;
    }
    // A handle that is no 32-hex id names nothing: the turn runs as before
    // the header was read, never refused for it.
    let value = headers.get(HOOK_ASK_HEADER)?.to_str().ok()?;
    EntityId::from_hex(value).ok()
}

/// `memory`, a turn's surface under its invocation, naming the pause `ask`
/// it resumes, if it names one.
pub(super) fn resuming(memory: Memory<'_>, ask: Option<EntityId>) -> Memory<'_> {
    match ask {
        Some(ask) => memory.with_hook_ask(ask),
        None => memory,
    }
}
