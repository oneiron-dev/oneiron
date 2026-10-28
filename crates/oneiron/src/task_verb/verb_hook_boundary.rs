//! The verb-hook boundary of one SDK row (ARCH-0080 §3, attach point 1).
//!
//! Every door that runs a row crosses it once: the generated `invoke`, the
//! MCP and code-mode dispatch, the HTTP routes that run a row themselves,
//! code mode's browser rows and the native handles that call the engine
//! directly. Each door wraps the row's own call, never a wrapper around it,
//! so a hook fires once per logical verb. A hook's stop reaches the caller as
//! a refusal whose `hook` carries the typed stop. A call the generated
//! `invoke` runs saves how to run it again with its ask, so settlement
//! resumes it (`Vault::drain_verb_asks`); a retry then answers what it
//! returned. A credential caller's call whose host bound its instrument and
//! door runs again through that door, once the host verified the credential
//! again. Any other call whose handle the drain can rebuild runs again as its
//! caller, wherever the caller sits, while the authority its ask saved still
//! stands: the owner still a live owner, or the same Grants under the same
//! ceiling.
//!
//! A call that keeps no record (a `no_record` row, or a call in an anonymous
//! off-record session its principal is verified in) runs its hooks as any
//! call does; only their records and their asks' pauses change place: the
//! in-memory keep, under its live session's key, for as long as the session
//! lives ([`hook_session`], FIX 4283). So does a call that serves a room
//! NOTE to a caller verified in its room ([`hook_session_for_call`], FIX
//! 4280).

use std::sync::Arc;

mod session;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::runtime_hooks::verb::{
    HOOK_RESULT_NOT_RETAINED, SessionHookKey, SessionHooks, VerbArgsCheck, VerbAskCredential,
    VerbHookStorage,
};
use crate::runtime_hooks::{
    InvocationId, VerbCall, VerbDomain, VerbHookPre, VerbHookStop, VerbResume,
};
use crate::task_verb::revoke_lands;
use crate::task_verb::sdk::{
    AgentVerb, NO_RECORD_ROWS, masked_reveal_reply, revealed_hook_view, validate_input,
};
use crate::work_line::TaskWorkTurn;
use crate::{EntityId, Vault};

/// What a session-only call's caller reads beside the Pending its hook's ask
/// left: the pause lives only while its session does, on this server.
pub const SESSION_PAUSE_NOTE: &str = "This call keeps no record, so its hook's pause lives only \
     while its session lasts on this server: once the ask is answered, retry with the same \
     invocation and this ask (header x-oneiron-hook-ask, MCP _meta.hook_ask) in the same \
     session. After the session ends or the server restarts, that retry is refused; call again.";

/// Where a call that keeps no record keeps its verb hooks' records and its
/// hooks' ask pauses: its live off-record session's key in the in-memory
/// keep, or the process's, never the vault (FIX 4283). Only
/// [`hook_session`] makes one for a call; a post chain keeps on its pre's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookSession {
    /// The keep's key: the live session the call's surface binds, or the
    /// process ([`Vault::session_hook_key`]).
    pub(crate) key: SessionHookKey,
    /// The pause the call names as the one it resumes, by its ask handle
    /// (`Memory::hook_ask`); `None` for a new call.
    pub(crate) resume: Option<EntityId>,
}

impl HookSession {
    /// The session a post chain, or a call that ended with no result, keeps
    /// on: its pre chain's key.
    fn kept(key: SessionHookKey) -> Self {
        Self { key, resume: None }
    }

    /// The one place a session-only call's storage reaches its chain: the
    /// session's own (`VerbHookStorage::Session`), never the vault's.
    fn with_storage<T>(&self, vault: &Vault, chain: impl FnOnce(VerbHookStorage<'_>) -> T) -> T {
        let hooks = SessionHooks::session_only(vault, self.key.clone()).resuming(self.resume);
        chain(VerbHookStorage::Session(&hooks))
    }
}

/// The session a call of row `verb` keeps its verb hooks' records and ask
/// pauses for when it keeps no record (FIX 4283; Engine ruling 10-19): a
/// `no_record` row (`NO_RECORD_ROWS`), or a call on `memory` in an anonymous
/// off-record session its principal is verified in
/// (`Memory::keeps_no_record`, never a raw header claim). Its hooks still
/// run. Their receipts and saved runs, and the call a hook's ask paused,
/// stay in the in-memory keep under the live session its surface binds, or
/// the process's when it binds none; none is written to the vault, and
/// settlement's drain never runs the call again: only its caller's retry
/// under the same key resumes it, and a retry that names a pause the keep no
/// longer holds refuses. `None` for every other call; such a call that names
/// a hook pause it resumes (`Memory::hook_ask`) where the vault saved none
/// refuses too ([`Vault::gone_hook_pause`]): that pause was a session-only
/// call's. `memory` is `None` for a host's own call that binds no surface:
/// the row alone decides.
///
/// # Errors
///
/// A resume of a pause that is gone; storage errors.
pub fn hook_session(memory: Option<&Memory<'_>>, verb: &str) -> MemoryResult<Option<HookSession>> {
    hook_session_kept(memory, verb, false)
}

/// [`hook_session`] of a call of row `verb` with `input`: a call that serves
/// a room NOTE (`vault.notes.read`, `.history` or `.editor.bind` of a NOTE
/// the room `memory` binds holds, for a principal verified in it, or an
/// editor's close of `held`, a room hold the engine minted; FIX 4280,
/// [`Vault::room_note_call_for`]) keeps its hooks' records for its session
/// too, never the vault. Every other call is judged as [`hook_session`]
/// judges it.
///
/// # Errors
///
/// As [`hook_session`].
pub fn hook_session_for_call(
    memory: Option<&Memory<'_>>,
    verb: &str,
    input: &Value,
    held: Option<&crate::off_record::RoomNoteHandle>,
) -> MemoryResult<Option<HookSession>> {
    let room_note = memory.is_some_and(|memory| memory.room_note_call(verb, input, held));
    hook_session_kept(memory, verb, room_note)
}

/// [`hook_session`], `room_note` the call serving a room NOTE.
fn hook_session_kept(
    memory: Option<&Memory<'_>>,
    verb: &str,
    room_note: bool,
) -> MemoryResult<Option<HookSession>> {
    let anonymous = room_note || memory.is_some_and(Memory::keeps_no_record);
    // A pause is resumed beside the invocation it paused; a call that names
    // none resumes nothing.
    let resume = memory.and_then(|memory| memory.invocation().and(memory.hook_ask()));
    if !anonymous && !NO_RECORD_ROWS.contains(&verb) {
        if let (Some(memory), Some(ask)) = (memory, resume)
            && let Some(invocation) = memory.invocation()
            && let Some(stop) = memory.vault().gone_hook_pause(invocation, ask)?
        {
            return Err(stopped(stop));
        }
        return Ok(None);
    }
    let key = match memory {
        Some(memory) => memory.vault().session_hook_key(memory.off_record_binding()),
        None => SessionHookKey::Process,
    };
    Ok(Some(HookSession { key, resume }))
}

/// Whether a call on `memory` sits in an anonymous off-record session its
/// principal is verified in (`Memory::keeps_no_record`, judged now on the
/// surface, never a raw header claim): a host keeps no durable record of
/// it, its sitting included (Engine #1968, FIX 5564).
#[must_use]
pub fn keeps_no_record(memory: &Memory<'_>) -> bool {
    memory.keeps_no_record()
}

/// The invocation a host door keeps in its own rows for the call `pre` ran
/// (FIX 5381): a session-only call's hidden id under its keep key
/// (`SessionHookKeep::hidden_invocation`), stable for its retries in this
/// process and session and never the caller's invocation; any other call's
/// own.
#[must_use]
pub fn door_invocation(vault: &Vault, pre: &VerbHookPre) -> InvocationId {
    let invocation = pre.call().invocation;
    match pre.session() {
        Some(key) => InvocationId(
            vault
                .verb_hook_state
                .session
                .hidden_invocation(key, invocation.0),
        ),
        None => invocation,
    }
}

/// [`door_invocation`] for a door that holds its caller's surface: the
/// invocation `memory` carries, hidden when a call of row `verb` on it keeps
/// no record, under the same key its hooks keep on. `None` when it carries
/// none.
#[must_use]
pub fn door_invocation_of(memory: &Memory<'_>, verb: &str) -> Option<InvocationId> {
    let invocation = memory.invocation()?;
    if !memory.keeps_no_record() && !NO_RECORD_ROWS.contains(&verb) {
        return Some(invocation);
    }
    let vault = memory.vault();
    let key = vault.session_hook_key(memory.off_record_binding());
    Some(InvocationId(
        vault
            .verb_hook_state
            .session
            .hidden_invocation(&key, invocation.0),
    ))
}

/// The pre chain of a call a host runs itself on `session` when it keeps no
/// record ([`hook_session`]), else on the vault: a host verb's chain or a
/// row's that runs outside the row boundary (FIX 5380). `turn` is the
/// task-work turn the calling operation holds, if any; a call on the vault
/// opens its ask on its author's own.
///
/// # Errors
///
/// Storage errors as they occur; a hook's own failure is never one.
pub fn hooks_pre(
    vault: &Vault,
    call: VerbCall,
    args: Value,
    check: VerbArgsCheck<'_>,
    session: Option<&HookSession>,
    turn: Option<Arc<TaskWorkTurn>>,
) -> crate::Result<Result<VerbHookPre, VerbHookStop>> {
    match session {
        Some(session) => session_pre(vault, call, args, check, session, turn),
        None => vault.pre_verb_hooks(call, args, check),
    }
}

/// The post chain over `result` wherever `pre`'s chain ran: a session-only
/// call's in its keep, any other's on the vault (FIX 5380).
///
/// # Errors
///
/// Storage errors as they occur; a hook's own failure is never one.
pub fn hooks_post(
    vault: &Vault,
    pre: VerbHookPre,
    result: Value,
) -> crate::Result<Result<Value, VerbHookStop>> {
    match pre.session().cloned().map(HookSession::kept) {
        Some(session) => session_post(vault, pre, result, &session),
        None => vault.post_verb_hooks(pre, result),
    }
}

/// [`Vault::verb_hooks`] for a call a host runs itself (FIX 5380): on
/// `session` when it keeps no record, its pre and post hooks' records and
/// pauses kept there only, and kept as well when `run` fails; else on the
/// vault, as today.
///
/// # Errors
///
/// What `run` returns, and storage errors as they occur.
pub fn verb_hooks_in<E: From<crate::Error>>(
    vault: &Vault,
    session: Option<&HookSession>,
    call: VerbCall,
    args: Value,
    check: VerbArgsCheck<'_>,
    run: impl FnOnce(Value) -> Result<Value, E>,
) -> Result<Result<Value, VerbHookStop>, E> {
    let Some(session) = session else {
        return vault.verb_hooks(call, args, check, run);
    };
    let pre = match session_pre(vault, call, args, check, session, None)? {
        Ok(pre) => pre,
        Err(VerbHookStop::Completed { result, .. }) => return Ok(Ok(result)),
        Err(stop) => return Ok(Err(stop)),
    };
    let result = match run(pre.args.clone()) {
        Ok(result) => result,
        Err(error) => {
            abort(vault, pre);
            return Err(error);
        }
    };
    Ok(session_post(vault, pre, result, session)?)
}

/// The pre chain of a session-only call ([`hook_session`]) a server door
/// runs itself: its hooks run as on any call, `check` re-admitting a
/// rewrite, and their records and ask pauses stay with `session`. Only its
/// caller's retry in that session resumes a paused call, using the answer
/// up once. A hook's ask, and the retry's read of it, run on `turn`, the
/// task-work turn the calling operation holds, if any (FIX 5383).
///
/// # Errors
///
/// Storage errors as they occur; a hook's own failure is never one.
pub fn session_pre(
    vault: &Vault,
    call: VerbCall,
    args: Value,
    check: VerbArgsCheck<'_>,
    session: &HookSession,
    turn: Option<Arc<TaskWorkTurn>>,
) -> crate::Result<Result<VerbHookPre, VerbHookStop>> {
    session.with_storage(vault, |storage| {
        vault.pre_verb_hooks_in(storage, call, args, check, turn)
    })
}

/// The post chain of a session-only call over its `result`: the caller's
/// view, its hooks' records kept with `session`, as its pre chain's were.
///
/// # Errors
///
/// Storage errors as they occur; a hook's own failure is never one.
pub fn session_post(
    vault: &Vault,
    pre: VerbHookPre,
    result: Value,
    session: &HookSession,
) -> crate::Result<Result<Value, VerbHookStop>> {
    session.with_storage(vault, |storage| {
        vault.post_verb_hooks_in(storage, pre, result)
    })
}

/// Keeps what `pre`'s chain held for a session-only call that ended with no
/// result for its post chain: its verb failed, was refused or parked. A call
/// that keeps its record holds nothing here. A failure to keep is logged:
/// the call's own error stands. A host door that ran `pre` itself calls it
/// when the door, its input's decode or its answer's encoding fails; no post
/// chain runs then (FIX 5527).
pub fn abort(vault: &Vault, pre: VerbHookPre) {
    let Some(session) = pre.session().cloned().map(HookSession::kept) else {
        return;
    };
    let verb = pre.call().verb.clone();
    if let Err(error) =
        session.with_storage(vault, |storage| vault.keep_verb_hooks_in(storage, pre))
    {
        tracing::warn!(%verb, %error, "a session-only call's pre hook records were not kept");
    }
}

/// The refusal a caller reads for a hook's stop. A session-only call's
/// Pending also says that its pause lives only while its session does
/// ([`SESSION_PAUSE_NOTE`]).
#[must_use]
pub fn stop_refusal(stop: VerbHookStop, session: Option<&HookSession>) -> MemoryError {
    let paused = session.is_some() && matches!(stop, VerbHookStop::Pending { .. });
    let mut error = stopped(stop);
    if paused {
        error.suggestions.push(SESSION_PAUSE_NOTE.to_owned());
    }
    error
}

pub(crate) use session::{session_row_call, session_row_post, session_row_pre};

/// A row's domain: a blocking hook that fails hides a read row's result and
/// sends any other row to an ask.
#[must_use]
pub fn row_domain(verb: &str) -> VerbDomain {
    if AgentVerb::from_name(verb).is_some_and(AgentVerb::writes) {
        VerbDomain::Write
    } else {
        VerbDomain::Read
    }
}

/// The call of row `verb` on `memory`: its actor and class, the invocation
/// its host bound or a fresh one, the caller's read key when a hook may run,
/// and the room a room turn runs in, as `room:<hex>` (the `<axis>:<value>`
/// form a hook's scope names).
///
/// # Errors
///
/// When a hook may run and the handle's read key does not build.
pub fn row_call(memory: &Memory<'_>, verb: &str) -> MemoryResult<VerbCall> {
    let mut call = VerbCall::for_memory(memory, verb, row_domain(verb))?;
    call.scope = memory
        .room_turn()
        .map(|turn| format!("room:{}", turn.room.to_hex()));
    Ok(call)
}

/// Runs the pre chain of row `verb` over its JSON `args`: the args to run it
/// with. A rewrite must pass the row's own input check, then the admission
/// its door bound on `memory`.
///
/// # Errors
///
/// A hook's stop, as the refusal the caller reads; storage errors.
pub fn row_pre(memory: &Memory<'_>, verb: &str, args: Value) -> MemoryResult<VerbHookPre> {
    let session = hook_session(Some(memory), verb)?;
    row_pre_resumable(
        memory,
        verb,
        args,
        None,
        None,
        validate_input,
        session.as_ref(),
    )?
    .map_err(|stop| stop_refusal(stop, session.as_ref()))
}

/// The run-bound browser projection of a row uses its original browser input,
/// not the facade's credential-bound live-run wrapper. All other hooks and
/// rewrite admission stay the same as [`row_pre`].
pub fn browser_row_pre(memory: &Memory<'_>, verb: &str, args: Value) -> MemoryResult<VerbHookPre> {
    let session = hook_session(Some(memory), verb)?;
    row_pre_resumable(
        memory,
        verb,
        args,
        None,
        None,
        crate::task_verb::sdk::validate_browser_input,
        session.as_ref(),
    )?
    .map_err(|stop| stop_refusal(stop, session.as_ref()))
}

/// [`row_pre`] with the stop as it is. `resume` is how settlement runs the
/// call again without its caller, and `credential` how it runs a credential
/// caller's through its door; a door that runs the row itself, not through
/// the generated `invoke`, passes `None` for both, since the drain could not
/// run it the way that door does. A hook's ask runs on the task-work turn
/// `memory`'s operation already holds, if any, never waiting for another. A
/// restrictive call's args that fail the row's input check give way to the
/// caller's own ([`revoke_lands::settle`]). A session-only call's `session`
/// takes its records, and it saves no way to run it again but its caller's
/// retry there.
fn row_pre_resumable(
    memory: &Memory<'_>,
    verb: &str,
    args: Value,
    resume: Option<VerbResume>,
    credential: Option<VerbAskCredential>,
    validate: fn(&str, &Value) -> MemoryResult<()>,
    session: Option<&HookSession>,
) -> MemoryResult<Result<VerbHookPre, VerbHookStop>> {
    if matches!(verb, "host.compact" | "host.wake" | "host.budget.hit") {
        memory.embedded_owner(verb)?.revalidate(memory.vault())?;
        crate::runtime_hooks::host_doors::admit_trigger(memory.vault(), verb, &args)?;
    }
    let check = |args: &Value| {
        validate(verb, args).map_err(|error| error.to_string())?;
        memory
            .rewrite_admit()
            .map_or(Ok(()), |admit| admit(verb, args))
    };
    let vault = memory.vault();
    let call = row_call(memory, verb)?;
    let turn = memory.task_work_turn();
    let mut ended = match (session, credential) {
        (Some(session), _) => session_pre(vault, call, args, &check, session, turn)?,
        (None, Some(credential)) => {
            vault.pre_verb_hooks_for_credential(call, args, &check, Some(credential), turn)?
        }
        (None, None) => vault.pre_verb_hooks_resumable(call, args, &check, resume, turn)?,
    };
    if let Ok(pre) = &mut ended {
        revoke_lands::settle(pre, &|args| validate(verb, args).is_ok());
    }
    Ok(ended)
}

/// Runs the post chain over the row's JSON `result`: the caller's view of it.
/// A write the row committed stays reported as committed: a storage failure
/// in its post chain is logged, not returned.
///
/// A `reveal.wait` answer's value never reaches a hook (OF-560): the chain
/// reads the answer with the secret's handle where the value was, and the
/// caller's view gets the value back where the chain left the handle.
///
/// # Errors
///
/// A hook's stop, as the refusal the caller reads; a read row's storage
/// errors.
pub fn row_post(vault: &Vault, pre: VerbHookPre, result: Value) -> MemoryResult<Value> {
    // The write committed: the owner hears what a hook changed on a
    // restrictive call, or what was ignored (FIX 5076).
    revoke_lands::notify(vault, &pre);
    // A session-only call's post chain keeps its records where its pre chain
    // kept them (FIX 4283).
    let session = pre.session().cloned().map(HookSession::kept);
    if let Some(masked) = masked_reveal_reply(&pre.call().verb, &result)
        && masked != result
    {
        let view = chain_post(vault, pre, masked.clone(), session.as_ref())?;
        return Ok(revealed_hook_view(view, &masked, &result));
    }
    chain_post(vault, pre, result, session.as_ref())
}

fn chain_post(
    vault: &Vault,
    pre: VerbHookPre,
    result: Value,
    session: Option<&HookSession>,
) -> MemoryResult<Value> {
    let post = |pre, result| match session {
        Some(session) => session_post(vault, pre, result, session),
        None => vault.post_verb_hooks(pre, result),
    };
    if pre.call().domain == VerbDomain::Read {
        return post(pre, result)?.map_err(stopped);
    }
    let verb = pre.call().verb.clone();
    let committed = result.clone();
    match post(pre, result) {
        Ok(view) => view.map_err(stopped),
        Err(error) => {
            tracing::warn!(%verb, %error, "a committed write's post hooks failed");
            Ok(committed)
        }
    }
}

/// The pre chain, the row and the post chain for one call on JSON: `run`
/// gets the args every rewrite left. The generated `invoke` is its one
/// caller, so a call on a surface settlement can rebuild saves its resume
/// target with an ask, and a call settlement already ran answers what it
/// returned: a credential caller's reference first, else its plain caller's.
/// A plain `reveal.wait` saves none: settlement would keep the value it
/// returned, so the caller's retry resumes it.
///
/// # Errors
///
/// What `run` returns, and what [`row_pre`] and [`row_post`] return; the
/// error a call settlement ran failed with.
pub fn row(
    memory: &Memory<'_>,
    verb: &str,
    args: Value,
    run: impl FnOnce(Value) -> MemoryResult<Value>,
) -> MemoryResult<Value> {
    // Bound on every call: a retry of a call an ask parked meets its saved
    // reference whether or not a hook takes the verb now. A credential
    // caller's reference comes first; else a handle the drain can rebuild is
    // its plain target; else only the caller's retry resumes it.
    let credential = memory.verb_ask_credential();
    let resume = memory
        .plain_resume()
        .filter(|_| credential.is_none() && verb != AgentVerb::RevealWait.as_str())
        .map(VerbResume::Row);
    let session = hook_session(Some(memory), verb)?;
    let pre = match row_pre_resumable(
        memory,
        verb,
        args,
        resume,
        credential,
        validate_input,
        session.as_ref(),
    )? {
        Ok(pre) => pre,
        Err(stop) => return completed(verb, stop, session.as_ref()),
    };
    // A restrictive call (an erase, a revoke) lands over a damaged clock floor (FIX 10106).
    let restriction = pre
        .landing
        .is_some()
        .then(crate::authority::restriction_only_clock);
    let ran = run(pre.args.clone());
    drop(restriction);
    let result = match ran {
        Ok(result) => result,
        Err(error) => {
            abort(memory.vault(), pre);
            return Err(error);
        }
    };
    row_post(memory.vault(), pre, result)
}

/// [`row`] for a door that holds the row's typed input and returns its typed
/// output. The args and the result cross the chain as JSON; one no hook
/// changed keeps its own typed value.
///
/// # Errors
///
/// What `run` returns, and what [`row_pre`] and [`row_post`] return. A view
/// a redaction left without a field the typed output needs is refused, so
/// the field never leaks back.
pub fn typed_row<I, O>(
    memory: &Memory<'_>,
    verb: &str,
    input: I,
    run: impl FnOnce(I) -> MemoryResult<O>,
) -> MemoryResult<O>
where
    I: Serialize + DeserializeOwned,
    O: Serialize + DeserializeOwned,
{
    typed_row_validated(memory, verb, input, validate_input, run)
}

/// [`typed_row`] for a door whose typed input is its own rather than the
/// row's generated one (a binding's direct call, FIX 8114): the chain sees
/// that input, and a hook's rewrite must pass `validate`, the door's own
/// input check, before the admission its door bound on `memory`.
///
/// # Errors
///
/// As [`typed_row`].
pub fn typed_row_validated<I, O>(
    memory: &Memory<'_>,
    verb: &str,
    input: I,
    validate: fn(&str, &Value) -> MemoryResult<()>,
    run: impl FnOnce(I) -> MemoryResult<O>,
) -> MemoryResult<O>
where
    I: Serialize + DeserializeOwned,
    O: Serialize + DeserializeOwned,
{
    let args = encode(&input)?;
    // A typed door's own call may differ from the generated `invoke`'s, so
    // it saves no resume target: its caller's retry resumes it.
    let session = hook_session(Some(memory), verb)?;
    let mut pre = match row_pre_resumable(
        memory,
        verb,
        args.clone(),
        None,
        None,
        validate,
        session.as_ref(),
    )? {
        Ok(pre) => pre,
        Err(stop) => return completed(verb, stop, session.as_ref()),
    };
    revoke_lands::settle(&mut pre, &revoke_lands::decodes::<I>);
    let ran = (|| -> MemoryResult<(O, Value)> {
        let input = if pre.args == args {
            input
        } else {
            serde_json::from_value(pre.args.clone()).map_err(|error| {
                MemoryError::bad_request(format!("a verb hook rewrote {verb}'s input: {error}"))
            })?
        };
        // A restrictive call (an erase, a revoke) lands over a damaged clock floor (FIX 10106).
        let _restriction = pre
            .landing
            .is_some()
            .then(crate::authority::restriction_only_clock);
        let output = run(input)?;
        let result = encode(&output)?;
        Ok((output, result))
    })();
    let (output, result) = match ran {
        Ok(ran) => ran,
        Err(error) => {
            abort(memory.vault(), pre);
            return Err(error);
        }
    };
    let view = row_post(memory.vault(), pre, result.clone())?;
    if view == result {
        return Ok(output);
    }
    serde_json::from_value(view).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("a verb hook redacted a field {verb}'s typed answer needs"),
            &["Call the verb through a JSON door, which returns the redacted view as it is."],
        )
    })
}

/// The actor a host's own call runs as when its credential names none: the
/// vault's owner.
///
/// # Errors
///
/// When the owner's id cannot be derived.
pub fn host_actor() -> crate::Result<EntityId> {
    crate::vault::embedded_owner_actor_id()
}

fn encode(value: &impl Serialize) -> MemoryResult<Value> {
    serde_json::to_value(value).map_err(|error| {
        MemoryError::bad_request(format!("a verb's value cannot cross its hooks: {error}"))
    })
}

fn stopped(stop: VerbHookStop) -> MemoryError {
    MemoryError::from(crate::Error::from(stop))
}

/// A row's answer to a pre-chain stop: what a call settlement already ran
/// returned, as the row's output. Any other stop is the refusal the caller
/// reads; the error a settled call failed with, or was refused with, keeps
/// its code and rides in `hook` with its receipt. A call that completed with
/// a result too large to keep says so, and not to call again; a session-only
/// call's Pending says how long its pause lives ([`stop_refusal`]).
fn completed<O: DeserializeOwned>(
    verb: &str,
    stop: VerbHookStop,
    session: Option<&HookSession>,
) -> MemoryResult<O> {
    match stop {
        VerbHookStop::Completed { result, .. } => serde_json::from_value(result).map_err(|error| {
            MemoryError::bad_request(format!("{verb}'s saved result does not decode: {error}"))
        }),
        stop => {
            let not_retained = matches!(
                &stop,
                VerbHookStop::CompletedWithError { code, .. } if code == HOOK_RESULT_NOT_RETAINED
            );
            let mut error = stop_refusal(stop, session);
            if not_retained {
                error.suggestions = vec![format!(
                    "{verb} ran once its hook's ask was answered; only its result was not kept. Do not call it again: read what it changed instead."
                )];
            }
            Err(error)
        }
    }
}
