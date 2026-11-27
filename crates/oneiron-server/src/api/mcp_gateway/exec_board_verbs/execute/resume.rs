//! The caller's explicit re-entry and, when offered, its word on a pending ask.

use oneiron::code_run::{SelfDurableWait, SelfEffect, WaitDeliveries};
use oneiron::engine_executor::code_run_parked_wait;

use super::super::super::{admission, tasks_response};
use super::*;
use crate::mcp::McpResumeToolArgs;

pub(crate) async fn execute_mcp_resume(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    args: &McpResumeToolArgs,
) -> Result<Value, McpGatewayError> {
    let run_ref = &args.run_ref;
    let run_id = crate::mcp::mcp_code_run_id(run_ref, actor);
    let record = server
        .vault
        .get_code_run_replay_record(&run_id)
        .map_err(|error| mcp_engine_error("resume could not read run", error))?;
    let Some(record) = record else {
        return result::refusal(server, actor, run_ref, unknown_ref()).await;
    };
    let Some(input) = caller_run_input(&server.vault, run_id)
        .map_err(|error| mcp_engine_error("resume could not read run input", error))?
    else {
        return result::refusal(
            server,
            actor,
            run_ref,
            McpGatewayError::new(-32020, "WRONG_INPUT", "the stored run input is unavailable"),
        )
        .await;
    };
    if matches!(&input, CallerRunInput::Source(_)) {
        refuse_off_record_source(server, actor)?;
    }
    if matches!(&input, CallerRunInput::Task(_))
        && !server
            .code_execution_host()
            .is_some_and(|host| host.task_runtime_available())
    {
        return result::refusal(
            server,
            actor,
            run_ref,
            McpGatewayError::new(
                -32020,
                "model_unavailable",
                "this server has no task model bound",
            ),
        )
        .await;
    }
    let parked = code_run_parked_wait(&server.vault, &record)
        .map_err(|error| McpGatewayError::new(-32603, "engine_error", error.to_string()))?;
    let ask = match parked {
        Some((key, wait)) => {
            let delivered = WaitDeliveries::canonical(&server.vault)
                .delivery(&key)
                .map_err(|error| mcp_engine_error("resume could not read wait delivery", error))?
                .is_some();
            if delivered {
                None
            } else {
                pending_ask(server, &wait)?
            }
        }
        None => None,
    };
    if let Some((_, Some(cutoff))) = ask
        && server.vault.now_recorded_at() >= cutoff
    {
        return result::refusal(server, actor, run_ref, McpGatewayError::new(
            -32020, "EXPIRED",
            "this pause expired; execute the same code again with the same run_ref: writes that landed are not repeated",
        )).await;
    }
    if let Some(word) = &args.answer {
        let Some((group, _)) = ask else {
            return result::refusal(
                server,
                actor,
                run_ref,
                McpGatewayError::new(-32602, "WRONG_INPUT", "this run is not waiting on an ask"),
            )
            .await;
        };
        if let Err(error) = answer_wait(server, actor, group, word).await {
            return result::refusal_for_verb(
                server,
                actor,
                run_ref,
                error,
                Some(oneiron::task_verb::sdk::AgentVerb::TasksAnswer.as_str()),
            )
            .await;
        }
    }
    match input {
        CallerRunInput::Source(code) => {
            run_and_render(
                server,
                actor,
                run_ref,
                McpCodeRunInput::CallerSource(&code),
                true,
            )
            .await
        }
        CallerRunInput::Task(task) => execute_mcp_task_run(server, actor, run_ref, &task).await,
    }
}

pub(super) fn unknown_ref() -> McpGatewayError {
    McpGatewayError::new(
        -32020,
        "UNKNOWN_REF",
        "no run under this run_ref for this credential",
    )
}

pub(super) fn pending_ask(
    server: &SyncServer,
    wait: &SelfDurableWait,
) -> Result<Option<(oneiron::EntityId, Option<u64>)>, McpGatewayError> {
    if !matches!(wait.effect, SelfEffect::TasksWait) {
        return Ok(None);
    }
    server
        .vault
        .code_run_ask_cutoff(wait.wait_id)
        .map(|ask| ask.map(|cutoff| (wait.wait_id, cutoff)))
        .map_err(|error| mcp_engine_error("resume could not read ask", error))
}

// The word and its provenance are validated by the direct verb's door. A
// run's author, model line or receipt can lend this call no authority.
async fn answer_wait(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    group: oneiron::EntityId,
    word: &Value,
) -> Result<(), McpGatewayError> {
    let verb = oneiron::task_verb::sdk::AgentVerb::TasksAnswer.as_str();
    let surface = crate::mcp::try_registered_surface(crate::mcp::McpSurfaceMode::ToolFirst)
        .map_err(admission::mcp_surface_unavailable)?;
    let Some(crate::mcp::McpEndpointTool::Verb(tool)) = surface.resolve(verb) else {
        return Err(McpGatewayError::new(
            -32603,
            "engine_error",
            "tasks.answer is not bound on this server",
        ));
    };
    let input = json!({"handle": {"group_ref": group}, "word": word});
    // This is a fresh call, not the outer resume's hook invocation or retry.
    let actor = McpCallContext {
        invocation: None,
        hook_ask: None,
        ..actor.clone()
    }
    .for_verb_row(tool.writes(), &input);
    let arguments = tasks_response::mcp_agent_verb_arguments(verb, &input)?;
    arguments
        .validate(verb, tool)
        .map_err(super::actor_dispatch::mcp_tool_validation_error)?;
    admission::mcp_admit_scoped_verb(server, tool, &arguments, &actor)?;
    super::actor_dispatch::mcp_verb_gate(server, tool, &arguments, &actor)?;
    let mut served = Default::default();
    let mut board_hooks = None;
    Box::pin(tasks_response::execute_agent_verb_input(
        server,
        verb,
        input,
        &actor,
        None,
        &mut served,
        &mut board_hooks,
    ))
    .await?;
    Ok(())
}
