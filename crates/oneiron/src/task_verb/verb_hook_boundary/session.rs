//! The row boundary of a read a run serves in an off-record room (WILL L11-01
//! S01-2c): the sibling of [`super::row_pre`] and [`super::row_post`] for a
//! row the run's room answers through its own view.
//!
//! A rewrite meets the same check as on base: the row's own typed input.
//! The read then runs on the same key its door admitted for the caller, over
//! the same view of the room, so a ref a rewrite names is admitted as the
//! caller's own would be. The hooks run in the room
//! (`OffRecordSession::pre_verb_hooks_in_room`): a room saves no resume
//! target and lands no canonical work, so no call here is resumed by
//! settlement. A hook's ask pauses the call in RAM under the room's stretch,
//! and the run's same call, naming that pause, resumes it (FIX 5524). A
//! restrictive call keeps its landing, as on base;
//! the owner's notice of what hooks changed on one is base inbox work, and no
//! read the room serves is restrictive.

use serde_json::Value;

use crate::claim::ScopedReadActorKey;
use crate::code_run::SessionHookDisposition;
use crate::off_record::{OffRecordSession, SessionWriteRoute};
use crate::runtime_hooks::verb::RoomHookCall;
use crate::runtime_hooks::{InvocationId, VerbCall, VerbHookPre, VerbHookStop, hook_class};
use crate::task_verb::revoke_lands;
use crate::task_verb::sdk::validate_input;
use crate::{EntityId, Result, WriteActor};

use super::row_domain;

/// A chain's end in a room, and what each hook did.
type InRoom<T> = (
    std::result::Result<T, VerbHookStop>,
    Vec<SessionHookDisposition>,
);

/// The call of row `verb` by `actor` in a room: `invocation`, the step's own
/// (the effect boundary's [`InvocationId::of_run_step`]), and `key`, the
/// narrow key the run's door admitted for its caller, which every hook reads
/// under. Its scope is the room turn that key reads inside, if any, as
/// [`super::row_call`] names a handle's.
#[must_use]
pub(crate) fn session_row_call(
    actor: WriteActor,
    key: ScopedReadActorKey,
    verb: &str,
    invocation: InvocationId,
) -> VerbCall {
    VerbCall {
        verb: verb.to_owned(),
        invocation,
        actor: actor.entity_ref(),
        class: hook_class(actor.actor_class()),
        scope: key
            .room_turn()
            .map(|turn| format!("room:{}", turn.room.to_hex())),
        board_epoch: None,
        turn: None,
        domain: row_domain(verb),
        reader: Some(key),
    }
}

/// [`super::row_pre`] for `call` over its JSON `args` in `session`'s room,
/// on `route`, the route its run captured: a rewrite must pass the row's own
/// input check. A restrictive call's args that fail it give way to the
/// caller's own ([`revoke_lands::settle`]). A failed read of the hooks
/// refuses the read, as before 2c, when these reads refused while a hook was
/// bound. `resume` is the hook pause the run's call names as the one it
/// resumes, if any (FIX 5524).
///
/// # Errors
///
/// The room's authority refusals and storage errors; a hook's stop is the
/// answer's own.
pub(crate) fn session_row_pre(
    session: &OffRecordSession<'_>,
    route: &SessionWriteRoute,
    call: VerbCall,
    args: Value,
    resume: Option<EntityId>,
) -> Result<InRoom<VerbHookPre>> {
    let verb = call.verb.clone();
    let check = |args: &Value| validate_input(&verb, args).map_err(|error| error.to_string());
    let how = RoomHookCall {
        resume,
        ..RoomHookCall::default()
    };
    let (mut ended, hooks) = session.pre_verb_hooks_in_room(route, call, args, &check, how)?;
    if let Ok(pre) = &mut ended {
        revoke_lands::settle(pre, &|args| validate_input(&verb, args).is_ok());
    }
    Ok((ended, hooks))
}

/// [`super::row_post`] over the row's JSON `result` in the room: the
/// caller's view of it, which the run's record keeps, as base's row
/// boundary answers its door.
///
/// # Errors
///
/// As [`session_row_pre`].
pub(crate) fn session_row_post(
    session: &OffRecordSession<'_>,
    route: &SessionWriteRoute,
    pre: VerbHookPre,
    result: Value,
) -> Result<InRoom<Value>> {
    session.post_verb_hooks_in_room(route, pre, result, false)
}
