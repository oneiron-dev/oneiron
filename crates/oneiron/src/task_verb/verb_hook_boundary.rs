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

mod row_run;
mod session;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::runtime_hooks::verb::{SessionHookKey, SessionHooks, VerbArgsCheck, VerbHookStorage};
use crate::runtime_hooks::{
    InvocationId, VerbCall, VerbCallScope, VerbDomain, VerbHookPre, VerbHookStop,
};
use crate::task_verb::revoke_lands;
use crate::verb_names::{self, CUSTODY_VALUE_ROWS};
use crate::verb_table::VerbTable;
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
/// `no_record` row ([`VerbTable::no_record`] of `verbs`), or a call on `memory` in an anonymous
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
pub fn hook_session(
    memory: Option<&Memory<'_>>,
    verbs: &dyn VerbTable,
    verb: &str,
) -> MemoryResult<Option<HookSession>> {
    hook_session_kept(memory, verbs, verb, false)
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
    verbs: &dyn VerbTable,
    verb: &str,
    input: &Value,
    held: Option<&crate::off_record::RoomNoteHandle>,
) -> MemoryResult<Option<HookSession>> {
    let room_note = memory.is_some_and(|memory| memory.room_note_call(verb, input, held));
    hook_session_kept(memory, verbs, verb, room_note)
}

/// [`hook_session`], `room_note` the call serving a room NOTE.
fn hook_session_kept(
    memory: Option<&Memory<'_>>,
    verbs: &dyn VerbTable,
    verb: &str,
    room_note: bool,
) -> MemoryResult<Option<HookSession>> {
    let anonymous = room_note || memory.is_some_and(Memory::keeps_no_record);
    // A pause is resumed beside the invocation it paused; a call that names
    // none resumes nothing.
    let resume = memory.and_then(|memory| memory.invocation().and(memory.hook_ask()));
    if !anonymous && !verbs.no_record(verb) {
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
pub fn door_invocation_of(
    memory: &Memory<'_>,
    verbs: &dyn VerbTable,
    verb: &str,
) -> Option<InvocationId> {
    let invocation = memory.invocation()?;
    if !memory.keeps_no_record() && !verbs.no_record(verb) {
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
    mut args: Value,
    check: VerbArgsCheck<'_>,
    run: impl FnOnce(Value) -> Result<Value, E>,
    is_storage_error: &dyn Fn(&E) -> bool,
) -> Result<Result<Value, VerbHookStop>, E> {
    let secret = CustodySecret::lift(&call.verb, &mut args);
    let run = move |args| run(CustodySecret::restored(secret.as_ref(), args));
    let Some(session) = session else {
        return vault.verb_hooks(call, args, check, run, is_storage_error);
    };
    let pre = match session_pre(vault, call, args, check, session, None)? {
        Ok(pre) => pre,
        Err(VerbHookStop::Completed { result, .. }) => return Ok(Ok(result)),
        Err(stop) => return Ok(Err(stop)),
    };
    let result = match run(pre.args.clone()) {
        Ok(result) => result,
        Err(error) => {
            if is_storage_error(&error) {
                vault.reopen_resumed_ask(&pre);
            }
            abort(vault, pre);
            return Err(error);
        }
    };
    Ok(session_post(vault, pre, result, session)?)
}

/// The receipt a resumed call's stored `result` carries, when it decodes as
/// one: a turn that resumes a settled ask reads its sources from it (FIX 7042).
pub fn resumed_witness_receipt(result: &Value) -> Option<crate::memory::WitnessReceipt> {
    serde_json::from_value(result.clone()).ok()
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

pub(crate) use row_run::row_holding_member;
pub use row_run::{
    browser_row_pre, row, row_pre, row_retained, row_tapped, row_with_notice, typed_row,
    typed_row_validated,
};
pub(crate) use session::{session_row_call, session_row_post, session_row_pre};

/// A row's domain: a blocking hook that fails hides a read row's result and
/// sends any other row to an ask. Row `verb` writes when `verbs` says so.
#[must_use]
pub fn row_domain(verbs: &dyn VerbTable, verb: &str) -> VerbDomain {
    if verbs.writes(verb) {
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
pub fn row_call(memory: &Memory<'_>, verbs: &dyn VerbTable, verb: &str) -> MemoryResult<VerbCall> {
    let mut call = VerbCall::for_memory(memory, verb, row_domain(verbs, verb))?;
    call.scope = memory
        .room_turn()
        .map(|turn| VerbCallScope::Named(format!("room:{}", turn.room.to_hex())));
    Ok(call)
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

/// The actor a host's own call runs as when its credential names none: the
/// vault's owner.
///
/// # Errors
///
/// When the owner's id cannot be derived.
pub fn host_actor() -> crate::Result<EntityId> {
    crate::vault::embedded_owner_actor_id()
}

/// A custody row's secret member ([`CUSTODY_VALUE_ROWS`]: a secret's value,
/// or its sealed input), lifted out of the call's args before its pre chain
/// as the server's doors lift it (FIX 11665, 11724). Its hooks, their
/// records and an ask's saved args meet the member empty; only the args the
/// verb runs with carry it back. A retry that resumes a pause runs with the
/// value the retry itself carries.
struct CustodySecret {
    member: &'static str,
    value: Zeroizing<String>,
}

impl CustodySecret {
    /// Takes `verb`'s secret member out of `args`, leaving it empty; `None`
    /// for any other row, and for a member absent or empty already.
    fn lift(verb: &str, args: &mut Value) -> Option<Self> {
        if !CUSTODY_VALUE_ROWS.contains(&verb) {
            return None;
        }
        let member = verb_names::custody_member(verb)?;
        let Some(Value::String(held)) = args.get_mut(member) else {
            return None;
        };
        if held.is_empty() {
            return None;
        }
        Some(Self {
            member,
            value: Zeroizing::new(std::mem::take(held)),
        })
    }

    /// `args` the verb runs with, `secret`'s member put back.
    fn restored(secret: Option<&Self>, mut args: Value) -> Value {
        if let (Some(secret), Some(fields)) = (secret, args.as_object_mut()) {
            fields.insert(
                secret.member.to_owned(),
                Value::String((*secret.value).clone()),
            );
        }
        args
    }
}

fn stopped(stop: VerbHookStop) -> MemoryError {
    MemoryError::from(crate::Error::from(stop))
}

/// A reply to `verb` as a call receipt digests it and a verb hook reads it
/// (OF-560): a `reveal.wait` reply, in whatever envelope its door wraps it,
/// with each value replaced by its secret's handle, as a structured field
/// keeps a masked secret. `None` for any other verb's reply, which is read as
/// it is. A digest of the value itself would let a short secret be guessed
/// offline.
#[must_use]
pub fn masked_reveal_reply(verb: &str, reply: &serde_json::Value) -> Option<serde_json::Value> {
    if verb.rsplit('/').next() != Some(verb_names::REVEAL_WAIT) {
        return None;
    }
    let mut masked = reply.clone();
    mask_reveal_values(&mut masked);
    Some(masked)
}

/// The caller's view of a `reveal.wait` reply once its hooks read the masked
/// form: where the view still holds the handle the mask left, the value goes
/// back; a field a hook changed or dropped stays as the hook left it.
#[must_use]
pub fn revealed_hook_view(
    mut view: serde_json::Value,
    masked: &serde_json::Value,
    reply: &serde_json::Value,
) -> serde_json::Value {
    if let (Some(fields), Some(masked), Some(reply)) =
        (view.as_object_mut(), masked.as_object(), reply.as_object())
    {
        for key in REVEALED_FIELDS {
            if let (Some(slot), Some(stand_in), Some(value)) =
                (fields.get_mut(key), masked.get(key), reply.get(key))
                && slot == stand_in
            {
                *slot = value.clone();
            }
        }
    }
    view
}

/// The fields of a `reveal.wait` answer that carry the value.
const REVEALED_FIELDS: [&str; 2] = ["value", "value_base64"];

/// Each value field in `value`, at any depth, replaced by the handle its
/// answer's receipt names, or by null when none does. A JSON text an
/// envelope carries (an MCP text content) is read the same way.
fn mask_reveal_values(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            let handle = fields
                .get("receipt")
                .and_then(|receipt| receipt.get("handle"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            for key in REVEALED_FIELDS {
                if let Some(slot) = fields.get_mut(key) {
                    *slot = handle
                        .clone()
                        .map_or(serde_json::Value::Null, serde_json::Value::String);
                }
            }
            fields.values_mut().for_each(mask_reveal_values);
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(mask_reveal_values),
        serde_json::Value::String(text) if text.starts_with(['{', '[']) => {
            if let Ok(mut inner) = serde_json::from_str::<serde_json::Value>(text) {
                let before = inner.clone();
                mask_reveal_values(&mut inner);
                if inner != before {
                    *text = inner.to_string();
                }
            }
        }
        _ => {}
    }
}
