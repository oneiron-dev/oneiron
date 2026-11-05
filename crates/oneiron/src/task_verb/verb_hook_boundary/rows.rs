//! One row's hook boundary and its caller-only success metadata.

use super::*;

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
    row_with_saved(memory, verb, args, run, false).map(|(value, _)| value)
}

/// [`row`] with the content-free notice bit from the actual pre chain,
/// captured before the post chain consumes it. `None` means this call read
/// a drained call's saved result, which does not retain that metadata.
/// The result itself and every hook, admission and abort stay the same.
///
/// # Errors
///
/// As [`row`].
pub fn row_with_notice(
    memory: &Memory<'_>,
    verb: &str,
    args: Value,
    run: impl FnOnce(Value) -> MemoryResult<Value>,
) -> MemoryResult<(Value, Option<bool>)> {
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
    row_with_saved(memory, verb, args, run, true).map(|(value, _)| value)
}

fn row_with_saved(
    memory: &Memory<'_>,
    verb: &str,
    mut args: Value,
    run: impl FnOnce(Value) -> MemoryResult<Value>,
    require_saved: bool,
) -> MemoryResult<(Value, Option<bool>)> {
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
        Err(stop) => {
            return completed(verb, stop, session.as_ref()).map(|value| (value, None));
        }
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
    let notice = revoke_lands::caller_notice(&pre).is_some();
    row_post(memory.vault(), pre, result).map(|value| (value, Some(notice)))
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
