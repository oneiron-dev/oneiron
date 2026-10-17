//! The verb-hook boundary of one SDK row (ARCH-0080 §3, attach point 1).
//!
//! Every door that runs a row crosses it once: the generated `invoke`, the
//! MCP and code-mode dispatch, the HTTP routes that run a row themselves,
//! code mode's browser rows and the native handles that call the engine
//! directly. Each door wraps the row's own call, never a wrapper around it,
//! so a hook fires once per logical verb. A hook's stop reaches the caller as
//! a refusal whose `hook` carries the typed stop. A call the generated
//! `invoke` runs for an on-device caller with no credential saves how to run
//! it again with its ask, so settlement resumes it (`Vault::drain_verb_asks`);
//! a retry then answers what it returned. So does a credential caller's call
//! whose host bound its instrument and door: settlement runs it through that
//! door, once the host verified the credential again.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::runtime_hooks::verb::VerbAskCredential;
use crate::runtime_hooks::{VerbCall, VerbDomain, VerbHookPre, VerbHookStop, VerbResume};
use crate::task_verb::sdk::{AgentVerb, validate_input};
use crate::{EntityId, Vault};

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
    row_pre_resumable(memory, verb, args, None, None)?.map_err(stopped)
}

/// [`row_pre`] with the stop as it is. `resume` is how settlement runs the
/// call again without its caller, and `credential` how it runs a credential
/// caller's through its door; a door that runs the row itself, not through
/// the generated `invoke`, passes `None` for both, since the drain could not
/// run it the way that door does.
fn row_pre_resumable(
    memory: &Memory<'_>,
    verb: &str,
    args: Value,
    resume: Option<VerbResume>,
    credential: Option<VerbAskCredential>,
) -> MemoryResult<Result<VerbHookPre, VerbHookStop>> {
    let check = |args: &Value| {
        validate_input(verb, args).map_err(|error| error.to_string())?;
        memory
            .rewrite_admit()
            .map_or(Ok(()), |admit| admit(verb, args))
    };
    let vault = memory.vault();
    let call = row_call(memory, verb)?;
    Ok(match credential {
        Some(credential) => {
            vault.pre_verb_hooks_for_credential(call, args, &check, Some(credential))?
        }
        None => vault.pre_verb_hooks_resumable(call, args, &check, resume)?,
    })
}

/// Runs the post chain over the row's JSON `result`: the caller's view of it.
/// A write the row committed stays reported as committed: a storage failure
/// in its post chain is logged, not returned.
///
/// # Errors
///
/// A hook's stop, as the refusal the caller reads; a read row's storage
/// errors.
pub fn row_post(vault: &Vault, pre: VerbHookPre, result: Value) -> MemoryResult<Value> {
    if pre.call().domain == VerbDomain::Read {
        return vault.post_verb_hooks(pre, result)?.map_err(stopped);
    }
    let verb = pre.call().verb.clone();
    let committed = result.clone();
    match vault.post_verb_hooks(pre, result) {
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
/// returned.
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
    let resume = memory
        .resume_bounds()
        .map(|(session, room)| VerbResume::Row { session, room });
    let credential = memory.verb_ask_credential();
    let pre = match row_pre_resumable(memory, verb, args, resume, credential)? {
        Ok(pre) => pre,
        Err(stop) => return completed(verb, stop),
    };
    let result = run(pre.args.clone())?;
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
    let args = encode(&input)?;
    // A typed door's own call may differ from the generated `invoke`'s, so
    // it saves no resume target: its caller's retry resumes it.
    let pre = match row_pre_resumable(memory, verb, args.clone(), None, None)? {
        Ok(pre) => pre,
        Err(stop) => return completed(verb, stop),
    };
    let input = if pre.args == args {
        input
    } else {
        serde_json::from_value(pre.args.clone()).map_err(|error| {
            MemoryError::bad_request(format!("a verb hook rewrote {verb}'s input: {error}"))
        })?
    };
    let output = run(input)?;
    let result = encode(&output)?;
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
/// its code and rides in `hook` with its receipt.
fn completed<O: DeserializeOwned>(verb: &str, stop: VerbHookStop) -> MemoryResult<O> {
    match stop {
        VerbHookStop::Completed { result, .. } => serde_json::from_value(result).map_err(|error| {
            MemoryError::bad_request(format!("{verb}'s saved result does not decode: {error}"))
        }),
        stop => Err(stopped(stop)),
    }
}
