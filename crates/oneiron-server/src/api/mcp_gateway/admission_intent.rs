//! The durable admission receipt (ARCH-0044 C5) of a generated verb an MCP
//! `tools/call` runs under the invocation its `_meta` names, kept as the
//! HTTP facade keeps one for the same row (FIX 4735): the intent is kept
//! before the verb runs, each wait the call takes in a line is observed on
//! it, and its answer settles it. A call inside an anonymous off-record
//! session, or one serving a room NOTE, keeps none, as its call receipt
//! keeps none; a page continuation restates a retained answer and keeps
//! none either.

use std::future::Future;
use std::sync::Arc;

use oneiron::receipt::admission::AdmissionTracker;
use oneiron::runtime_hooks::VerbHookStop;
use serde_json::Value;

use super::envelope::{McpCallContext, McpGatewayError};
use crate::mcp::McpValidatedToolArgs;
use crate::server::SyncServer;

/// The intent a tracked call keeps: its row, the digest of its arguments
/// and the fingerprint a retry of the same invocation must match.
pub(super) struct McpIntent {
    verb: String,
    request_digest: String,
    fingerprint: String,
}

impl McpIntent {
    /// The intent `args` keeps for `actor`, when it keeps one: a fresh call
    /// of a generated verb the facade tracks ([`crate::api::facade::tracks_admission`]),
    /// under a named invocation, by an actor that binds. `off_record` is the
    /// call's no-record judgement on arrival.
    pub(super) fn of(
        server: &SyncServer,
        args: &McpValidatedToolArgs,
        actor: &McpCallContext,
        off_record: bool,
    ) -> Option<Self> {
        let McpValidatedToolArgs::Verb(call) = args else {
            return None;
        };
        // A page budget alone is a fresh call; a cursor restates a retained
        // answer.
        let continuation = call
            .payload
            .page
            .as_ref()
            .is_some_and(|page| page.cursor.is_some());
        if off_record || continuation {
            return None;
        }
        // Held content counts as it arrived (FIX 22074).
        let digest = call.page_argument_digest();
        Self::named(
            server,
            actor,
            call.tool.name,
            blake3::Hash::from_bytes(digest).to_hex().to_string(),
        )
    }

    /// The intent the drain's run of a saved `verb` call with `args` reopens
    /// for `actor` (FIX 8753), when the row keeps one.
    #[cfg(feature = "code-sandbox-wasmtime")]
    pub(super) fn resumed(
        server: &SyncServer,
        actor: &McpCallContext,
        verb: &str,
        args: &Value,
    ) -> Option<Self> {
        Self::named(
            server,
            actor,
            verb,
            oneiron::receipt::call_json_digest(args),
        )
    }

    fn named(
        server: &SyncServer,
        actor: &McpCallContext,
        verb: &str,
        request_digest: String,
    ) -> Option<Self> {
        actor.invocation?;
        if !crate::api::facade::tracks_admission(verb)
            || !AdmissionTracker::binds(server.vault(), actor.actor_ref, actor.actor_class)
        {
            return None;
        }
        let room = actor.room_turn.map(|id| id.to_hex()).unwrap_or_default();
        let fingerprint = crate::api::facade::invocation_body(
            actor.auth.as_ref(),
            actor.locality(),
            &[verb.as_bytes(), room.as_bytes(), request_digest.as_bytes()],
        );
        Some(Self {
            verb: verb.to_owned(),
            request_digest,
            fingerprint: blake3::Hash::from_bytes(fingerprint).to_hex().to_string(),
        })
    }
}

/// The intent's settlement, owed until its answer is observed: a call that
/// stops first leaves it interrupted, never running.
struct Flight {
    tracker: AdmissionTracker,
    settled: bool,
}

impl Drop for Flight {
    fn drop(&mut self) {
        if !self.settled
            && let Err(error) = self.tracker.interrupt()
        {
            tracing::error!(%error, "MCP admission interruption receipt failed");
        }
    }
}

/// Runs `call` under the intent `intent` keeps for `actor`: kept before the
/// call starts (reopened, on the drain's run of a held call), observed while
/// it waits in a line, and settled by its answer. With no intent, or on a
/// drain's run of a call that kept none, `call` runs as it is. `answer`
/// reads a successful output's tool result, where a verb hook's stop rides
/// as `structuredContent.hook`.
pub(super) async fn observed<T>(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    intent: Option<McpIntent>,
    call: impl Future<Output = Result<T, McpGatewayError>>,
    answer: impl FnOnce(&T) -> &Value,
) -> Result<T, McpGatewayError> {
    let (Some(intent), Some(invocation)) = (intent, actor.invocation) else {
        return call.await;
    };
    let vault = Arc::clone(server.vault());
    let (who, class) = (actor.actor_ref, actor.actor_class);
    let resumed = actor.drain.is_some();
    // A paced call the drain already ran answers its saved outcome to the
    // same caller's retry from its row, before an admission intent starts
    // again: that intent is settled, and the effect never runs twice (FIX
    // 19034, as the facade's FIX 8753 guard).
    if !resumed && oneiron::runtime_hooks::verb::is_paced_verb(&intent.verb) {
        let (lookup, caller, verb) = (Arc::clone(server), actor.clone(), intent.verb.clone());
        let ended = crate::api::clock_ingress::run_blocking(move || {
            super::tasks_response::mcp_paced_lookup_memory(&lookup, &caller, invocation)
                .ended_paced_verb_reply_listed(&verb)
        })
        .await
        .ok()
        .flatten();
        // The row answers the reply read here, so a line expiry between the
        // two reads can never run the effect again.
        if let Some(reply) = ended {
            return super::verb_hooks::ENDED_PACED_REPLY
                .scope(std::cell::RefCell::new(Some(reply)), call)
                .await;
        }
    }
    let started = crate::api::clock_ingress::run_blocking(move || {
        let McpIntent {
            verb,
            request_digest,
            fingerprint,
        } = intent;
        if resumed {
            AdmissionTracker::reopen(
                vault,
                who,
                class,
                invocation,
                &verb,
                request_digest,
                fingerprint,
            )
        } else {
            AdmissionTracker::start(
                vault,
                who,
                class,
                invocation,
                &verb,
                request_digest,
                fingerprint,
                false,
            )
            .map(Some)
        }
    })
    .await
    .map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "the admission intent could not be kept",
        )
    })?
    .map_err(super::facade_refusals::mcp_facade_error)?;
    let Some(tracker) = started else {
        return call.await;
    };
    let mut flight = Flight {
        tracker,
        settled: false,
    };
    let observer =
        crate::api::facade::tracker_observer(&flight.tracker, crate::api::admission_observer());
    let result = crate::api::facade::with_admission_observer(Some(observer), call).await;
    let settle = match &result {
        Ok(output) => {
            let value = answer(output);
            match tool_result_stop(value) {
                Some(stop) => settle_stop(&flight.tracker, &stop),
                None => flight.tracker.finish(Ok(value)),
            }
        }
        Err(error) => match error.hook.as_deref() {
            Some(stop) => settle_stop(&flight.tracker, stop),
            None if error.kind == "paced_hold" => flight.tracker.finish(Err((
                oneiron::memory::MEMORY_CODE_PACED_HOLD,
                &error.message,
            ))),
            None => flight.tracker.finish(Err((error.kind, &error.message))),
        },
    };
    settle.map_err(super::facade_refusals::mcp_facade_error)?;
    flight.settled = true;
    result
}

/// The verb hook's stop a tool result carries, when the verb did not run.
fn tool_result_stop(result: &Value) -> Option<VerbHookStop> {
    let stop = result.get("structuredContent")?.get("hook")?;
    serde_json::from_value(stop.clone()).ok()
}

/// Settles on a verb hook's stop as the facade settles on the refusal it
/// becomes: an open ask stays held and resumes under its invocation; a
/// skip, a hidden result or a call settlement already ran is refused.
fn settle_stop(
    tracker: &AdmissionTracker,
    stop: &VerbHookStop,
) -> oneiron::memory::MemoryResult<()> {
    let reason = stop.to_string();
    let code = match stop {
        VerbHookStop::Pending { .. } => oneiron::memory::MEMORY_CODE_PENDING_ASK,
        VerbHookStop::Hidden { .. } => oneiron::memory::MEMORY_CODE_FORBIDDEN,
        VerbHookStop::CompletedWithError { code, .. } => code.as_str(),
        VerbHookStop::Skipped { .. } | VerbHookStop::Completed { .. } => {
            oneiron::memory::MEMORY_CODE_INVALID_STATE
        }
    };
    tracker.finish(Err((code, &reason)))
}
