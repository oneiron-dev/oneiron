//! Whether a chat turn signals its caller's durable sitting (FIX 5564;
//! Engine #1968: an anonymous off-record session writes no durable
//! receipt). A turn's app-open mints the canonical SESSION entity for its
//! actor and machine, or marks the one open, and its answer's end bumps its
//! activity. A turn in an anonymous off-record session does neither: its
//! user turn and its answer still bind the session key, for the witness and
//! the stream, and its hooks still run (FIX 5525).
//!
//! A sitting's own hooks (`host.session.open`, `host.session.close`) run
//! only around a sitting that opens and closes, so withholding the sitting
//! while one of them may run would keep it from running for that turn: a
//! narrowing. Until the Engine rules on running them session-only, such a
//! turn keeps today's path ([`ANONYMOUS_TURN_OPENS_HOOKED_SITTING`]).

use oneiron::Vault;
use oneiron::memory::Memory;
use oneiron::runtime_hooks::VerbCall;
use oneiron::task_verb::verb_hook_boundary;

/// Whether a turn in an anonymous off-record session still opens and bumps
/// its caller's durable sitting while a `host.session.open` or
/// `host.session.close` hook may run (FIX 5564, FIX 5525): true keeps
/// today's path for it, so those hooks run in the vault as on main; false
/// withholds the sitting then too, and they do not run for that turn. With
/// no such hook, an anonymous turn opens no sitting either way.
const ANONYMOUS_TURN_OPENS_HOOKED_SITTING: bool = true;

/// The host verbs a sitting's own open and close run their hooks under
/// (`session_lifecycle`, ARCH-0080 §5).
const SITTING_HOOK_VERBS: [&str; 2] = ["host.session.open", "host.session.close"];

/// Whether a turn on `memory`, its caller's own surface, signals its
/// sitting: its app-open, and its answer's activity. Every turn does but one
/// in an anonymous off-record session its principal is verified in (judged
/// on that surface, never a header), unless a sitting hook keeps today's
/// path ([`ANONYMOUS_TURN_OPENS_HOOKED_SITTING`]).
pub(super) fn signals_sitting(vault: &Vault, memory: &Memory<'_>) -> bool {
    !verb_hook_boundary::keeps_no_record(memory)
        || (ANONYMOUS_TURN_OPENS_HOOKED_SITTING
            && SITTING_HOOK_VERBS
                .iter()
                .any(|verb| VerbCall::may_run(vault, verb)))
}
