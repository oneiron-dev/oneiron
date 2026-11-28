//! Admitted entries to a durable MCP code run.

mod result;
mod resume;

use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::engine_executor::{CallerRunInput, caller_run_input};
use rand_core::{OsRng, RngCore as _};

use super::super::code_run_resume::McpCodeRunEntry;
use super::*;
use crate::mcp::McpCodeRunEnd;
use crate::mcp::{
    McpCodeExecutionError, McpCodeRunInput, McpCodeRunResumeCondition, McpCodeRunResumed,
    McpExecuteToolArgs,
};

pub(crate) use self::resume::execute_mcp_resume;

pub(crate) async fn execute_mcp_execute(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    args: &McpExecuteToolArgs,
) -> Result<Value, McpGatewayError> {
    refuse_off_record_source(server, actor)?;
    let minted;
    let run_ref = match args.run_ref.as_deref() {
        Some(run_ref) => run_ref,
        None => {
            minted = format!("run:{:016x}", OsRng.next_u64());
            &minted
        }
    };
    run_and_render(
        server,
        actor,
        run_ref,
        McpCodeRunInput::CallerSource(&args.code),
        false,
    )
    .await
}

/// Re-enters a task run under the engine-model door. Only the test seam may
/// start a new task run; MCP `resume` checks that the record already exists.
pub(crate) async fn execute_mcp_task_run(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    task: &str,
) -> Result<Value, McpGatewayError> {
    run_and_render(server, actor, run_ref, McpCodeRunInput::Task(task), true).await
}

#[cfg(test)]
pub(crate) async fn execute_mcp_task_run_for_test(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    task: &str,
) -> Result<Value, McpGatewayError> {
    super::actor_dispatch::mcp_execute_code_gate(server, actor)?;
    let entry = McpCodeRunEntry::begin(server, crate::mcp::mcp_code_run_id(run_ref, actor));
    let entered = enter_mcp_code_run(
        server,
        actor,
        run_ref,
        McpCodeRunInput::Task(task),
        entry,
        None,
    )
    .await?
    .expect("a new entry has no resume condition");
    result::render_task_for_test(server, actor, run_ref, entered).await
}

async fn run_and_render(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    input: McpCodeRunInput<'_>,
    existing_only: bool,
) -> Result<Value, McpGatewayError> {
    let run_id = crate::mcp::mcp_code_run_id(run_ref, actor);
    let entry = McpCodeRunEntry::begin(server, run_id);
    let condition = existing_only.then(|| McpCodeRunResumeCondition::existing(run_id));
    let Some(entered) = enter_mcp_code_run(server, actor, run_ref, input, entry, condition).await?
    else {
        return result::refusal(server, actor, run_ref, resume::unknown_ref()).await;
    };
    result::render(server, actor, run_ref, entered).await
}

/// A source body is durable. Do not fall back to canonical storage when the
/// caller names a live off-record session or an off-record-only handle.
fn refuse_off_record_source(
    server: &SyncServer,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    if let Some(session) = actor.off_record_session.as_deref()
        && (oneiron::EntityId::from_hex(session).is_err()
            || server
                .vault
                .off_record_session(session)
                .map_err(|error| mcp_engine_error("execute could not read the session", error))?
                .is_some())
    {
        return Err(McpGatewayError::new(
            -32020,
            "code_run_refused",
            "execute and resume do not run caller code in an off-record session",
        ));
    }
    Ok(())
}

fn stored_input(input: &CallerRunInput) -> McpCodeRunInput<'_> {
    match input {
        CallerRunInput::Source(code) => McpCodeRunInput::CallerSource(code),
        CallerRunInput::Task(task) => McpCodeRunInput::Task(task),
    }
}

fn mcp_code_run_verbs(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_id: oneiron::EntityId,
    input: McpCodeRunInput<'_>,
) -> Arc<super::code_mode_verbs::McpCodeModeVerbs> {
    let verbs = super::code_mode_verbs::McpCodeModeVerbs::new(server, actor, run_id);
    Arc::new(match input {
        McpCodeRunInput::CallerSource(_) => verbs.authored_by_caller(),
        McpCodeRunInput::Task(_) => verbs.authored_by_engine_model(),
    })
}

/// One entry of a durable run: its id, the verb door it ran behind and
/// what the host answered.
pub(in crate::api::mcp_gateway) struct McpCodeRunEntered {
    pub(in crate::api::mcp_gateway) run_id: oneiron::EntityId,
    pub(in crate::api::mcp_gateway) verbs: Arc<super::code_mode_verbs::McpCodeModeVerbs>,
    pub(in crate::api::mcp_gateway) outcome:
        Result<oneiron::engine_executor::EngineExecutorOutcome, crate::mcp::McpCodeExecutionError>,
}

/// The admitted entry of the durable run `entry` holds, which `run_ref`
/// names under `actor`: the host's single flight, run admission, model seat
/// and spend line, as every entry of the run takes them. This is the
/// caller's own call, which renders its answer. The outcome settles
/// `entry`: a run parked on a wait registers it, and any other end removes
/// the registration.
async fn enter_mcp_code_run(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    input: McpCodeRunInput<'_>,
    entry: McpCodeRunEntry,
    condition: Option<McpCodeRunResumeCondition>,
) -> Result<Option<McpCodeRunEntered>, McpGatewayError> {
    let host = server
        .code_execution_host()
        .ok_or_else(|| mcp_code_execution_error(&crate::mcp::McpCodeExecutionError::HostUnbound))?;
    let run_id = entry.run_id();
    let verbs = mcp_code_run_verbs(server, actor, run_id, input);
    let cleanup = Arc::new(McpCodeRunTerminalCleanup {
        desktop_seats: Arc::clone(&server.desktop_seats),
        browser_seats: Arc::clone(&server.browser_seats),
        lens_frames: Arc::clone(&server.lens_frames),
        vault: Arc::clone(&server.vault),
        run_id,
        ended: AtomicBool::new(false),
    });
    let request = mcp_code_run_request(
        server,
        actor,
        run_ref,
        input,
        run_id,
        &verbs,
        Arc::clone(&cleanup) as Arc<dyn McpCodeRunEnd>,
    );
    let outcome = if let Some(condition) = condition {
        match host.execute_resumed(request, condition).await {
            Ok(McpCodeRunResumed::Superseded) => {
                entry.supersede();
                return Ok(None);
            }
            Ok(McpCodeRunResumed::Entered(outcome)) => Ok(*outcome),
            Err(error) => Err(error),
        }
    } else {
        host.execute(request).await
    };
    Ok(Some(mcp_code_run_ended(
        cleanup.as_ref(),
        actor,
        run_ref,
        entry,
        verbs,
        outcome,
    )))
}

/// The automatic re-entry of a parked run whose reply was delivered (FIX
/// 4606), through the same admitted entry as the caller's own call. It
/// renders no answer. `condition` is the wait and the generation the
/// re-entry was readied for, and the host checks it under the run's single
/// flight. `None`: the run had left them, as when a caller's own call took
/// it first, so no batch ran and the entry ends as one that started
/// nothing. Any other outcome settles `entry` as a caller's call does.
pub(in crate::api::mcp_gateway) async fn resume_mcp_code_run(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    entry: McpCodeRunEntry,
    condition: McpCodeRunResumeCondition,
) -> Result<Option<McpCodeRunEntered>, McpGatewayError> {
    let run_id = entry.run_id();
    let Some(stored) = caller_run_input(&server.vault, run_id)
        .map_err(|error| mcp_engine_error("resume could not read run input", error))?
    else {
        entry.supersede();
        return Ok(None);
    };
    let input = stored_input(&stored);
    if matches!(input, McpCodeRunInput::CallerSource(_)) {
        refuse_off_record_source(server, actor)?;
    }
    enter_mcp_code_run(server, actor, run_ref, input, entry, Some(condition)).await
}

/// The host request for one entry of `run_id`, the run `run_ref` names
/// under `actor`, behind the verb door `verbs`, bound for `actor` as the
/// admitted caller a code consent wait of the run keeps (FIX 4606), with a task run's
/// self brief when `actor`'s connection has one (caller-source runs build none, P2-2).
fn mcp_code_run_request<'a>(
    server: &Arc<SyncServer>,
    actor: &'a McpCallContext,
    run_ref: &'a str,
    input: McpCodeRunInput<'a>,
    run_id: oneiron::EntityId,
    verbs: &Arc<super::code_mode_verbs::McpCodeModeVerbs>,
    run_end: Arc<dyn McpCodeRunEnd>,
) -> crate::mcp::McpCodeExecutionRequest<'a> {
    // FIX 17594 D5: a task run's self brief, keyed by its trusted run
    // id, for a connection that has one; the host installs it under the
    // run's single flight and closes it when the run completes. A parked
    // run's automatic re-entry (FIX 4606) takes it the same way. A caller-source run
    // makes no model calls, so it builds none (P2-2).
    let brief = (matches!(input, McpCodeRunInput::Task(_))
        && crate::api::connection_has_brief(actor))
    .then(|| {
        Arc::new(super::code_mode_self_brief::CodeModeSelfBrief::new(
            server, actor, run_id,
        )) as Arc<dyn crate::mcp::McpCodeRunSelfBrief>
    });
    crate::mcp::McpCodeExecutionRequest {
        vault: Arc::clone(&server.vault),
        actor,
        off_record_session: actor.off_record_session.clone(),
        run_ref,
        input,
        run_id,
        verbs: Arc::clone(verbs) as Arc<dyn oneiron::code_run::AgentVerbDoor>,
        consent_origin: super::super::code_run_resume::mcp_code_consent_origin(
            server, actor, run_ref,
        ),
        brief,
        run_end: Some(run_end),
    }
}

struct McpCodeRunTerminalCleanup {
    desktop_seats: Arc<crate::server::DesktopSeats>,
    browser_seats: Arc<crate::server::BrowserSeats>,
    lens_frames: Arc<crate::lens_frames::LensFrameStore>,
    vault: Arc<oneiron::Vault>,
    run_id: oneiron::EntityId,
    ended: AtomicBool,
}

impl McpCodeRunEnd for McpCodeRunTerminalCleanup {
    fn end(&self) {
        if self.ended.swap(true, Ordering::AcqRel) {
            return;
        }
        let run_id = self.run_id;
        self.desktop_seats.end_run(run_id);
        self.browser_seats.end_run(run_id);
        self.lens_frames.close_run(&run_id.to_hex());
        if let Err(error) = self.vault.seal_code_run_scratchpads(run_id) {
            tracing::warn!(%error, run_id = %run_id.to_hex(), "code-run scratchpad seal failed");
        }
    }
}

/// Settles `entry` with what its host answered. Completion and an outgrown
/// window end the run (FIX CODE-MODE-LENDING-W6). The native worker cleans up
/// its resources under single flight even if the caller disconnects; this
/// calls the same cleanup for hosts that did not. Other outcomes keep the
/// run's resources parked for its next entry (OF-181, FIX 2612, CUA-001).
fn mcp_code_run_ended(
    cleanup: &dyn McpCodeRunEnd,
    actor: &McpCallContext,
    run_ref: &str,
    entry: McpCodeRunEntry,
    verbs: Arc<super::code_mode_verbs::McpCodeModeVerbs>,
    outcome: Result<
        oneiron::engine_executor::EngineExecutorOutcome,
        crate::mcp::McpCodeExecutionError,
    >,
) -> McpCodeRunEntered {
    let run_id = entry.run_id();
    let ended = match &outcome {
        Ok(outcome) => matches!(
            outcome.status,
            oneiron::engine_executor::EngineExecutorStatus::Complete
        ),
        Err(error) => error.ends_run(),
    };
    if ended {
        cleanup.end();
    }
    entry.settle(actor, run_ref, &outcome);
    McpCodeRunEntered {
        run_id,
        verbs,
        outcome,
    }
}

fn mcp_code_execution_error(error: &crate::mcp::McpCodeExecutionError) -> McpGatewayError {
    if matches!(error, McpCodeExecutionError::RunRefReused) {
        return McpGatewayError::new(
            -32020,
            "RUN_REF_REUSED",
            "use a new run_ref for new code; resume continues a paused run",
        );
    }
    let code = match error {
        crate::mcp::McpCodeExecutionError::HostUnbound
        | crate::mcp::McpCodeExecutionError::RunWaitedOut
        | crate::mcp::McpCodeExecutionError::Refused(_)
        | crate::mcp::McpCodeExecutionError::WindowOutgrown => -32020,
        crate::mcp::McpCodeExecutionError::RunBinding(_)
        | crate::mcp::McpCodeExecutionError::Run(_)
        | crate::mcp::McpCodeExecutionError::ResumeDivergence(_)
        | crate::mcp::McpCodeExecutionError::ProviderUnavailable { .. }
        | McpCodeExecutionError::RunRefReused => -32603,
    };
    let retry_after = match error {
        crate::mcp::McpCodeExecutionError::ProviderUnavailable { retry_after } => {
            Some(*retry_after)
        }
        _ => None,
    };
    McpGatewayError {
        retry_after,
        ..McpGatewayError::new(code, error.error_code(), error.to_string())
    }
}
