//! The hook pause a chat turn's retry resumes (FIX 5526): the ask handle a
//! hook's Pending gave, named in `x-oneiron-hook-ask` beside the turn's
//! `x-oneiron-invocation`, as on the facade. It names the pause only: the
//! turn keeps its caller's credential and session. Only a turn that keeps no
//! record reads it, since only its hooks' pauses live in its session alone:
//! a pause it names that the session no longer holds refuses, never running
//! as a new turn. Any other turn resumes its saved ask by its invocation, as
//! before, and its header is not read.

use axum::http::{HeaderMap, StatusCode};
use oneiron::EntityId;
use oneiron::memory::Memory;
use oneiron::task_verb::verb_hook_boundary;

use super::{Refused, refused};

/// The header a retry names the hook pause it resumes in.
const HOOK_ASK_HEADER: &str = "x-oneiron-hook-ask";

/// The hook pause a turn on `memory`, its caller's own surface, names as the
/// one it resumes: `None` for a turn that keeps its record, or names none.
/// A handle that is no 32-hex id is refused, as a malformed invocation is.
pub(super) fn named(headers: &HeaderMap, memory: &Memory<'_>) -> Result<Option<EntityId>, Refused> {
    let Some(value) = headers.get(HOOK_ASK_HEADER) else {
        return Ok(None);
    };
    if !verb_hook_boundary::keeps_no_record(memory) {
        return Ok(None);
    }
    value
        .to_str()
        .ok()
        .and_then(|ask| EntityId::from_hex(ask).ok())
        .map(Some)
        .ok_or_else(|| {
            refused(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "x-oneiron-hook-ask is not the 32-hex handle a hook's Pending gave",
            )
        })
}

/// `memory`, a turn's surface under its invocation, naming the pause `ask`
/// it resumes, if it names one.
pub(super) fn resuming(memory: Memory<'_>, ask: Option<EntityId>) -> Memory<'_> {
    match ask {
        Some(ask) => memory.with_hook_ask(ask),
        None => memory,
    }
}
