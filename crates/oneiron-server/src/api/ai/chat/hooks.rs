//! Chat generation and witness hook boundaries.
//! Entry: turn_generate_pre.
//! Chat types stay in the parent; moved functions keep equal-scope old-path exports.

use super::{
    Answering, Arc, EntityId, HOST_TURN_GENERATE, HookActorClass, IntoResponse, InvocationId, Json,
    Memory, MemoryError, MessageStreamReceipt, Refused, ScopedReadActorKey, StatusCode, Value,
    Vault, VerbCall, VerbDomain, VerbHookPre, VerbHookStop, WITNESS_ROW, WitnessTurn, json,
    sources, verb_hook_boundary,
};

/// The call of a turn's `host.turn.generate`. A write a host verb causes
/// stamps the System class. Its invocation derives from the turn's own, so a
/// retry of the turn carries it too. Its hooks read under `reader`, the
/// caller's key, and as `actor` when there is none. `room` is the room the
/// host resolved the turn into, if it did: the call's scope.
pub(in crate::api::ai::chat) fn turn_generate_call(
    actor: EntityId,
    invocation: Option<InvocationId>,
    reader: Option<ScopedReadActorKey>,
    room: Option<EntityId>,
) -> VerbCall {
    VerbCall {
        verb: HOST_TURN_GENERATE.to_owned(),
        invocation: invocation.map_or_else(InvocationId::mint, |id| {
            InvocationId::of_run_step(
                &[id.0.as_slice(), HOST_TURN_GENERATE.as_bytes()].concat(),
                0,
            )
        }),
        actor,
        class: HookActorClass::System,
        scope: room.map(|room| format!("room:{}", room.to_hex())),
        board_epoch: None,
        domain: VerbDomain::Write,
        reader,
    }
}

/// Runs `host.turn.generate`'s pre chain for `actor`'s reply in `room`,
/// its hooks reading under `reader`, the caller's key, when there is one.
/// `resolved` is the room entity the host already read `room` as, if any:
/// a hook scoped to it, or to its world, facet or project, fires. A turn
/// that keeps no record runs them on `session`, its records and pauses kept
/// there only (FIX 5380). `Err(stop)` when a hook skipped the turn or asked
/// first: the turn ends there, with the stop's reason. Hooks write and run
/// their sandbox, so they run off the runtime's workers.
pub(crate) fn turn_generate_pre(
    vault: &Vault,
    actor: EntityId,
    invocation: Option<InvocationId>,
    reader: Option<ScopedReadActorKey>,
    room: &str,
    resolved: Option<EntityId>,
    session: Option<&verb_hook_boundary::HookSession>,
) -> oneiron::Result<Result<VerbHookPre, VerbHookStop>> {
    let args = json!({
        "room": room,
        "scope": Value::Null,
        "board_epoch": Value::Null,
    });
    crate::server::blocking(|| {
        verb_hook_boundary::hooks_pre(
            vault,
            turn_generate_call(actor, invocation, reader, resolved),
            args.clone(),
            &|rewritten: &Value| host_args_kept(&args, rewritten),
            session,
            None,
        )
    })
}

/// A host verb's args are the host's: a hook's rewrite of them is refused.
pub(in crate::api::ai::chat) fn host_args_kept(
    args: &Value,
    rewritten: &Value,
) -> Result<(), String> {
    if rewritten == args {
        Ok(())
    } else {
        Err("a host verb's args are the host's".to_owned())
    }
}

/// Lands the user's turn through the `vault.witness` row's boundary, so the
/// row's verb hooks fire on it (ARCH-0080 §3), reading under `hooked`'s key.
/// A turn that keeps no record runs them on `session` (FIX 5380). The answer
/// is the caller's view of the row's receipt; `written` takes the MESSAGE
/// rows from the receipt itself, and stays `None` when no witness ran here.
pub(in crate::api::ai::chat) fn witness_through_row(
    vault: &Vault,
    memory: &Memory<'_>,
    hooked: &Memory<'_>,
    turn: &WitnessTurn,
    session: Option<&verb_hook_boundary::HookSession>,
    written: &mut Option<Vec<EntityId>>,
) -> Result<Result<Value, VerbHookStop>, MemoryError> {
    let args = serde_json::to_value(turn)
        .map_err(|_| MemoryError::bad_request("witness turn does not encode"))?;
    verb_hook_boundary::verb_hooks_in(
        vault,
        session,
        VerbCall::for_memory(hooked, WITNESS_ROW, VerbDomain::Write)?,
        args,
        &|args: &Value| {
            oneiron::task_verb::sdk::validate_input(WITNESS_ROW, args)
                .map_err(|error| error.to_string())
        },
        |args| {
            let turn: WitnessTurn = serde_json::from_value(args)
                .map_err(|_| MemoryError::bad_request("witness turn does not decode"))?;
            let receipt = memory.witness(&turn)?;
            *written = sources::witnessed(&receipt);
            serde_json::to_value(receipt)
                .map_err(|_| MemoryError::bad_request("witness receipt does not encode"))
        },
    )
}

/// A turn a verb hook stopped (ARCH-0080 §3): a skip is a conflict, an ask
/// is accepted and pending on its handle, a hidden answer is denied. The body
/// carries the stop, with the invocation a retry carries.
pub(in crate::api::ai::chat) fn hook_stopped(stop: &VerbHookStop) -> Refused {
    let (status, code) = match stop {
        VerbHookStop::Skipped { .. } => (StatusCode::CONFLICT, "verb_hook_skipped"),
        VerbHookStop::Pending { .. } => (StatusCode::ACCEPTED, "verb_hook_pending"),
        VerbHookStop::Hidden { .. } => (StatusCode::FORBIDDEN, "verb_hook_hidden"),
        // The call ran once its ask settled: the stop carries what it
        // returned, and nothing runs it again.
        VerbHookStop::Completed { .. } => (StatusCode::OK, "verb_hook_completed"),
        VerbHookStop::CompletedWithError { .. } => {
            (StatusCode::CONFLICT, "verb_hook_completed_with_error")
        }
    };
    Box::new(
        (
            status,
            Json(json!({"error": {"code": code, "message": stop.to_string(), "hook": stop}})),
        )
            .into_response(),
    )
}

/// Runs `host.turn.generate`'s post chain once the reply's producer ends,
/// whether or not a caller still listens. A block a post-hook adds lands the
/// next turn; the reply stands whatever a post-hook says.
pub(crate) fn after_turn(
    vault: Arc<Vault>,
    generating: VerbHookPre,
    answering: Answering,
) -> Answering {
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    let (finished, forwarded) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok(ended) = outcome.await else {
            return;
        };
        let result = json!({
            "message_id": handle.message_id().to_hex(),
            "text": ended.text,
            "saved": ended.saved.is_some(),
            "complete": ended.saved.as_ref().is_some_and(MessageStreamReceipt::complete),
            "finish_reason": ended.saved.as_ref().and_then(|receipt| receipt.finish_reason.clone()),
        });
        // Where its pre chain ran: a turn that keeps no record keeps its
        // post hooks' records in its session only (FIX 5380).
        let posted =
            crate::server::blocking(|| verb_hook_boundary::hooks_post(&vault, generating, result));
        if let Err(error) = posted {
            tracing::warn!(
                ?error,
                "host.turn.generate post-hooks failed on a finished turn"
            );
        }
        let _ = finished.send(ended);
    });
    Answering {
        handle,
        subscription,
        outcome: forwarded,
    }
}
