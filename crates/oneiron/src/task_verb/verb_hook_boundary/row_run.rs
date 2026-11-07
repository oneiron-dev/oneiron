//! The row boundary's run of one call (ARCH-0080 §3): its pre chain, the
//! row and its post chain. [`row`], [`row_tapped`] and [`typed_row`] run a
//! whole call; [`row_pre`] runs a door's pre chain alone. A retry of a call
//! settlement already ran answers what it returned (`completed`).

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{
    CustodySecret, HookSession, abort, hook_session_for_call, row_call, row_post, session_pre,
    stop_refusal,
};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::runtime_hooks::verb::{
    HOOK_RESULT_NOT_RETAINED, VerbAskCredential, VerbAskDrainPermit, VerbHookStorage,
};
use crate::runtime_hooks::{InvocationId, VerbHookPre, VerbHookStop, VerbResume};
use crate::task_verb::revoke_lands;
use crate::task_verb::sdk::{AgentVerb, validate_input};

/// Runs the pre chain of row `verb` over its JSON `args`: the args to run it
/// with. A rewrite must pass the row's own input check, then the admission
/// its door bound on `memory`.
///
/// # Errors
///
/// A hook's stop, as the refusal the caller reads; storage errors.
pub fn row_pre(memory: &Memory<'_>, verb: &str, args: Value) -> MemoryResult<VerbHookPre> {
    // A call serving a room NOTE keeps its hooks' records for its session
    // (FIX 4280, 10344), judged on the call's own input.
    let _restriction = restriction_clock_for_call(memory, verb, &args);
    let session = hook_session_for_call(Some(memory), verb, &args, None)?;
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
    let _restriction = restriction_clock_for_call(memory, verb, &args);
    let session = hook_session_for_call(Some(memory), verb, &args, None)?;
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

/// The restriction-only clock for a call that is wholly an owner's erase or
/// revoke on the caller's own `args` ([`revoke_lands::restriction_only_call`]),
/// held over its hooks' pre chain, so over a damaged clock floor they read
/// what its run reads (FIX 11522). A classification read that fails enters
/// none, as before.
fn restriction_clock_for_call(
    memory: &Memory<'_>,
    verb: &str,
    args: &Value,
) -> Option<crate::authority::RestrictionOnlyClock> {
    revoke_lands::restriction_only_call(memory.vault(), verb, args)
        .unwrap_or(false)
        .then(crate::authority::restriction_only_clock)
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
    row_pre_with_saved(
        memory, verb, args, resume, credential, validate, session, false,
    )
}

fn row_pre_with_saved(
    memory: &Memory<'_>,
    verb: &str,
    args: Value,
    resume: Option<VerbResume>,
    credential: Option<VerbAskCredential>,
    validate: fn(&str, &Value) -> MemoryResult<()>,
    session: Option<&HookSession>,
    require_saved: bool,
) -> MemoryResult<Result<VerbHookPre, VerbHookStop>> {
    // A call on the handle the plain drain rebuilt carries its permit
    // (FIX 2183): on whatever thread a nested call of its invocation
    // reaches this boundary, the thread stands as the drain's own, so
    // the call runs instead of meeting the drain's hold as a retry.
    let _drain = memory.drain_permit().map(VerbAskDrainPermit::enter);
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
    let mut ended = if require_saved {
        match session {
            Some(session) => session.with_storage(vault, |storage| {
                vault.pre_verb_hooks_retained_in(storage, call, args, &check, turn)
            })?,
            None => vault.pre_verb_hooks_retained_in(
                VerbHookStorage::Canonical,
                call,
                args,
                &check,
                turn,
            )?,
        }
    } else {
        match (session, credential) {
            (Some(session), _) => session_pre(vault, call, args, &check, session, turn)?,
            (None, Some(credential)) => {
                vault.pre_verb_hooks_for_credential(call, args, &check, Some(credential), turn)?
            }
            (None, None) => vault.pre_verb_hooks_resumable(call, args, &check, resume, turn)?,
        }
    };
    if let Ok(pre) = &mut ended {
        revoke_lands::settle(pre, &|args| validate(verb, args).is_ok());
        pre.with_read_capture(memory.read_capture());
    }
    // A retry the saved call's target check answered with what settlement's
    // drain ran lists the rows that answer was saved beside, before any door
    // turns it into the row's output (FIX 21054).
    if let Err(VerbHookStop::Completed { invocation, .. }) = &ended {
        memory.produced_by_drained(InvocationId::parse_hex(invocation));
    }
    Ok(ended)
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
    row_with_saved(memory, verb, args, run, false)
}

/// A workflow's caller-only retry from its retained tool checkpoint. The
/// caller rebuilds its current task host and authority as on a first call;
/// the native pre chain must also find the saved call before the body runs.
/// A missing or nested saved invocation never becomes a fresh call.
///
/// # Errors
///
/// As [`row`], including an unavailable saved hook call.
pub fn row_retained(
    memory: &Memory<'_>,
    verb: &str,
    args: Value,
    run: impl FnOnce(Value) -> MemoryResult<Value>,
) -> MemoryResult<Value> {
    row_with_saved(memory, verb, args, run, true)
}

fn row_with_saved(
    memory: &Memory<'_>,
    verb: &str,
    mut args: Value,
    run: impl FnOnce(Value) -> MemoryResult<Value>,
    require_saved: bool,
) -> MemoryResult<Value> {
    // A call a budget window paced answers from its held row until its turn
    // ran (FIX 8753), before any hook runs on it again.
    if !require_saved
        && let Some(reply) = crate::runtime_hooks::verb::paced_verb_reply(memory, verb)
    {
        return reply;
    }
    let secret = CustodySecret::lift(verb, &mut args);
    // Bound on every call: a retry of a call an ask parked meets its saved
    // reference whether or not a hook takes the verb now. A credential
    // caller's reference comes first; else a handle the drain can rebuild is
    // its plain target; else only the caller's retry resumes it.
    let (credential, resume) = if require_saved {
        // Workflow task-host calls are caller-only; never rebind a drain target.
        (None, None)
    } else {
        let credential = memory.verb_ask_credential();
        let resume = memory
            .plain_resume()
            .filter(|_| credential.is_none() && verb != AgentVerb::RevealWait.as_str())
            .map(VerbResume::Row);
        (credential, resume)
    };
    let pre_restriction = restriction_clock_for_call(memory, verb, &args);
    let session = hook_session_for_call(Some(memory), verb, &args, None)?;
    let pre = match row_pre_with_saved(
        memory,
        verb,
        args,
        resume,
        credential,
        validate_input,
        session.as_ref(),
        require_saved,
    )? {
        Ok(pre) => pre,
        Err(stop) => return completed(verb, stop, session.as_ref()),
    };
    drop(pre_restriction);
    // A restrictive call (an erase, a revoke) lands over a damaged clock floor (FIX 10106).
    let restriction = pre
        .landing
        .is_some()
        .then(crate::authority::restriction_only_clock);
    let ran = run(CustodySecret::restored(secret.as_ref(), pre.args.clone()));
    drop(restriction);
    let result = match ran {
        Ok(result) => result,
        Err(error) => {
            if crate::runtime_hooks::verb::run_failed_transient(&error) {
                memory.vault().reopen_resumed_ask(&pre);
            }
            abort(memory.vault(), pre);
            return Err(error);
        }
    };
    row_post(memory.vault(), pre, result)
}

/// [`row`] for a caller that must observe the committed engine result before
/// post-hook redaction (P1 REVIEW-4395): `tap` sees `result` exactly as `run`
/// committed it, after the call's records settle and BEFORE [`row_post`]
/// applies post-hook redactions, so a valid Redact of `/receipt` (or a
/// hook variant rewrite of the args) can neither suppress nor fabricate what
/// the tap observed. The tap runs only when `run` returned `Ok`; an `Err`
/// aborts exactly as in [`row`] and the tap never fires. No other behavior
/// differs from [`row`]: same secret lift, resume, pre chain, restriction
/// clock and abort path.
pub fn row_tapped(
    memory: &Memory<'_>,
    verb: &str,
    mut args: Value,
    run: impl FnOnce(Value) -> MemoryResult<Value>,
    tap: impl FnOnce(&Value),
) -> MemoryResult<Value> {
    let secret = CustodySecret::lift(verb, &mut args);
    // Bound on every call: a retry of a call an ask parked meets its saved
    // reference whether or not a hook takes the verb now. A credential
    // caller's reference comes first; else a handle the drain can rebuild is
    // its plain target; else only the caller's retry resumes it.
    let credential = memory.verb_ask_credential();
    let resume = memory
        .plain_resume()
        .filter(|_| credential.is_none() && verb != AgentVerb::RevealWait.as_str())
        .map(VerbResume::Row);
    let pre_restriction = restriction_clock_for_call(memory, verb, &args);
    let session = hook_session_for_call(Some(memory), verb, &args, None)?;
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
    drop(pre_restriction);
    // A restrictive call (an erase, a revoke) lands over a damaged clock floor (FIX 10106).
    let restriction = pre
        .landing
        .is_some()
        .then(crate::authority::restriction_only_clock);
    let ran = run(CustodySecret::restored(secret.as_ref(), pre.args.clone()));
    drop(restriction);
    let result = match ran {
        Ok(result) => result,
        Err(error) => {
            abort(memory.vault(), pre);
            return Err(error);
        }
    };
    tap(&result);
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
    let mut args = encode(&input)?;
    let secret = CustodySecret::lift(verb, &mut args);
    // A typed door's own call may differ from the generated `invoke`'s, so
    // it saves no resume target: its caller's retry resumes it.
    let pre_restriction = restriction_clock_for_call(memory, verb, &args);
    let session = hook_session_for_call(Some(memory), verb, &args, None)?;
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
    drop(pre_restriction);
    revoke_lands::settle(&mut pre, &revoke_lands::decodes::<I>);
    let ran = (|| -> MemoryResult<(O, Value)> {
        let input = if pre.args == args {
            input
        } else {
            serde_json::from_value(CustodySecret::restored(secret.as_ref(), pre.args.clone()))
                .map_err(|error| {
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
            if crate::runtime_hooks::verb::run_failed_transient(&error) {
                memory.vault().reopen_resumed_ask(&pre);
            }
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

fn encode(value: &impl Serialize) -> MemoryResult<Value> {
    serde_json::to_value(value).map_err(|error| {
        MemoryError::bad_request(format!("a verb's value cannot cross its hooks: {error}"))
    })
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
