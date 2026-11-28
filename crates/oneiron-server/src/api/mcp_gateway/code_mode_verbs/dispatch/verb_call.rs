//! One code-mode verb call on the tool-first surface: admitted, gated, run on
//! the verb table's fan-out and answered, with the line a media call spends on.

use super::*;
use oneiron::runtime_hooks::VerbHookStop;

pub(in super::super) async fn execute_code_mode_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    verb: &str,
    input: Value,
    run: McpCodeRun,
) -> Result<AgentVerbAnswer, McpGatewayError> {
    run_code_mode_verb(server, actor, verb, input, run, mcp_admit_scoped_verb).await
}

/// A browser batch's routine decision: the connector's `ai.verdict`, admitted
/// as a direct `tools/call` of it is, needing the connector's own binding of
/// `ai.verdict` plus its scope (FIX CODE-MODE-LENDING-W3). Its credential
/// gate and hooks run as on any verb call.
pub(in super::super) async fn execute_step_verdict(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    input: Value,
    run: McpCodeRun,
) -> Result<(Value, Vec<oneiron::EntityId>), McpGatewayError> {
    // Only the verdict is read; its rows are not.
    run_code_mode_verb(
        server,
        actor,
        "ai.verdict",
        input,
        run,
        mcp_admit_scoped_verb,
    )
    .await
    .map(|answer| (answer.output, answer.rows.unwrap_or_default()))
}

/// How one verb call's tool binding and scope are admitted.
type VerbAdmission = fn(
    &Arc<SyncServer>,
    crate::mcp::McpGeneratedVerbTool,
    &crate::mcp::McpVerbArguments,
    &McpCallContext,
) -> Result<(), McpGatewayError>;

async fn run_code_mode_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    verb: &str,
    input: Value,
    run: McpCodeRun,
    admit: VerbAdmission,
) -> Result<AgentVerbAnswer, McpGatewayError> {
    let surface = try_registered_surface(McpSurfaceMode::ToolFirst)
        .map_err(super::super::admission::mcp_surface_unavailable)?;
    let Some(McpEndpointTool::Verb(tool)) = surface.resolve(verb) else {
        if let Some(refusal) = oneiron::task_verb::sdk::wrong_root(verb) {
            return Err(super::super::mcp_facade_error(refusal));
        }
        return Err(McpGatewayError::new(
            -32601,
            "unknown_tool",
            format!("{verb} is not a verb in the SDK verb table"),
        ));
    };
    let arguments = mcp_agent_verb_arguments(tool.name, &input)?;
    arguments
        .validate(tool.name, tool)
        .map_err(mcp_tool_validation_error)?;
    admit(server, tool, &arguments, actor)?;
    mcp_verb_gate(server, tool, &arguments, actor)?;
    // A run's call is answered once and never continued; it tracks whether
    // a producer's path listed none (FIX 5988).
    let mut served = super::super::McpServed::default();
    let mut board_hooks = None;
    let origin = run.origin.clone();
    // A media call spends on the run's own line, as its steps do (FIX 780).
    // A caller's own code spends as its direct call does: through the
    // owner's door, under the grant that door asks (FIX EXECUTE-CALLER-CODE).
    let line = match run.author {
        RunAuthor::EngineModel => media_line(server, tool.name, run.run_id),
        RunAuthor::Caller => None,
    };
    // The verb table's fan-out, on the heap (FIX 12072).
    let executed = crate::api::facade::host_doors::support::with_calling_origin(
        origin,
        crate::api::facade::host_doors::with_calling_line(
            line,
            Box::pin(execute_agent_verb_input(
                server,
                tool.name,
                input,
                actor,
                Some(run),
                &mut served,
                &mut board_hooks,
            )),
        ),
    )
    .await;
    let (output, _, _, _, hook_notice) = match executed {
        // A retry of a call its drain already ran gets what that call
        // returned, never a stop (FIX 21054). Nothing runs again. Its saved
        // chain's actual notice rides beside it as the content-free summary
        // (FIX 12517).
        Err(McpGatewayError {
            hook: Some(stop), ..
        }) if matches!(*stop, VerbHookStop::Completed { .. }) => {
            let notice = matches!(
                *stop,
                VerbHookStop::Completed {
                    hook_notice: Some(true),
                    ..
                }
            );
            let (output, rows) = completed_answer(server, actor, *stop, &mut served)?;
            let mut answer = AgentVerbAnswer::new(output, rows);
            if notice {
                answer.hook_notice = Some(serde_json::json!(
                    oneiron::task_verb::revoke_lands::CALLER_NOTICE_SUMMARY
                ));
            }
            return Ok(answer);
        }
        executed => executed?,
    };
    // A board read answers the run here: the receipt its hook rows owe is
    // recorded and their blocks spent as the answer returns (OF-579).
    if let Some(mut hooks) = board_hooks {
        hooks.record_receipt(server).await?;
        hooks.spend(server);
    }
    // An act whose rows are unknown answers off this device only that it
    // ran (FIX 5988); a read releases as before.
    let (output, rows) =
        super::super::served_rows::unknown_act_answer(tool.name, actor, output, served)?;
    let mut answer = AgentVerbAnswer::new(output, rows);
    answer.hook_notice = super::super::super::tasks_response::mcp_hook_notice(
        server,
        actor,
        hook_notice,
        &mut answer.rows,
    );
    Ok(answer)
}

/// The answer a guest call gets when its verb hook `stop` is Completed
/// (FIX 21054): the result the call's drain saved, not a stop. The release
/// check runs before the guest reads it, by the rows the saved answer was
/// derived from. A held result keeps the release's withheld error. A result
/// saved with no row set is released on this device only. Any other stop is
/// the refusal it was.
fn completed_answer(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    stop: VerbHookStop,
    served: &mut McpServed,
) -> Result<(Value, Option<Vec<oneiron::EntityId>>), McpGatewayError> {
    let rows = super::super::served_rows::stop_release_rows(server, actor, &stop, served)
        .map(<[oneiron::EntityId]>::to_vec);
    // The drain read that answer, not this guest call (FIX 21614).
    if super::super::served_rows::drained_rows_lapsed(server, actor, &stop, rows.as_deref(), false)
    {
        let ran = oneiron::task_verb::sdk::ActAnswer::<()>::details_on_device();
        return Ok((serde_json::json!(ran), Some(Vec::new())));
    }
    match stop {
        VerbHookStop::Completed { result, .. } => {
            let released = super::super::super::mcp_release_listed(
                server,
                actor,
                rows.as_deref(),
                false,
                result,
                false,
            )?;
            Ok((released, rows))
        }
        stop => Err(super::super::tasks_response::mcp_hook_stop(stop)),
    }
}

/// The `ai.*` media verbs a code-mode run's line pays for (FIX 780), and
/// `connector.call`, whose web calls on the deploy's key it pays for (FIX 11604).
const LINE_VERBS: [&str; 9] = [
    "ai.options",
    "ai.image",
    "ai.speech",
    "ai.transcribe",
    "ai.embed",
    "ai.video",
    "ai.video.poll",
    "ai.video.cancel",
    "connector.call",
];

/// The line a code-mode run's `ai.*` media call spends on (FIX 780): the
/// run's code-mode line ([`code_mode_line`]). `None` for any other verb, or
/// where code mode lends no meter: that call takes the owner's door, as a
/// direct tool call does.
fn media_line(
    server: &SyncServer,
    verb: &str,
    run_id: oneiron::EntityId,
) -> Option<oneiron::llm::run_admission::RunAdmission> {
    if !LINE_VERBS.contains(&verb) {
        return None;
    }
    code_mode_line(server, run_id)
}

/// Code-mode durable run `run_id`'s line: code mode's own meter, the one the
/// run's steps spend on, under the run's own name. Its media calls spend on
/// it, and its self brief states its budget from it (FIX 17594 D5). `None`
/// where code mode lends no meter.
pub(crate) fn code_mode_line(
    server: &SyncServer,
    run_id: oneiron::EntityId,
) -> Option<oneiron::llm::run_admission::RunAdmission> {
    let meter = server
        .code_execution_host()?
        .engine_native()?
        .provider()
        .host_meter()?;
    let run = format!("code-mode:{}", run_id.to_hex());
    Some(server.ai.model_runtime().funded_run(run, meter, None))
}
