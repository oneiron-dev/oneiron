//! The rows a pumped run's door answers from the run's own seats (FIX
//! 2086): `describe(self)`, the run's own self brief, and
//! `vault.weave.lens`, its agent's own live lens. Each runs for the run's
//! agent, which holds no credential, with the row's verb hooks once around
//! it, and answers the same wire value a credential's call of the row does.

use oneiron::claim::WeaveReportRequest;

use super::{
    AgentVerb, Arc, DescribeRequest, EntityId, HostWriteOrigin, InvocationId, MemoryResult,
    RunAdmission, StreamConnectionId, SyncServer, Value, WriteActor, agent_memory, decode, encode,
    sdk, verb_hook_boundary,
};
use crate::ai_host::{WeaveLensCaller, render_live_weave_lens_for_run};
use crate::lens_frames::CardOwner;

/// Answers the run's `describe(self)`: the self brief of the snapshot
/// installed for the run's own board connection, read for its agent, and
/// the rows the brief is derived from. Blocking: call it on a blocking
/// thread of the server's runtime.
pub(super) fn self_brief_as_agent(
    server: &Arc<SyncServer>,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
    board: &StreamConnectionId,
    input: Value,
) -> MemoryResult<(Value, Vec<EntityId>)> {
    let memory = agent_memory(server, actor, origin, invocation);
    let name = AgentVerb::Describe.as_str();
    let mut rows = Vec::new();
    let output = verb_hook_boundary::row(&memory, name, input, |input| {
        sdk::validate_input(name, &input)?;
        let request: DescribeRequest = decode(input)?;
        let handle = tokio::runtime::Handle::current();
        let (output, sources) =
            handle.block_on(crate::api::describe_self_for_run(server, actor, board, &request))?;
        rows = sources;
        Ok(output)
    })?;
    Ok((output, rows))
}

/// Answers the run's `vault.weave.lens`: its agent's own live lens, its
/// step on the run's own `line`, its card held for run `run`, replacing the
/// card the run rendered for the same request, and closed as the run ends.
/// The rows are every read the lens rendered from. Blocking: call it on a
/// blocking thread of the server's runtime.
pub(super) fn weave_lens_as_agent(
    server: &Arc<SyncServer>,
    actor: WriteActor,
    run: EntityId,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
    line: Option<&RunAdmission>,
    input: Value,
) -> MemoryResult<(Value, Vec<EntityId>)> {
    let memory = agent_memory(server, actor, origin, invocation);
    let name = AgentVerb::VaultWeaveLens.as_str();
    let mut rows = Vec::new();
    let output = verb_hook_boundary::row(&memory, name, input, |input| {
        sdk::validate_input(name, &input)?;
        let owner = CardOwner::run_request(run, name, &input);
        let request: WeaveReportRequest = decode(input)?;
        let caller = WeaveLensCaller::Run {
            actor: actor.entity_ref(),
            class: actor.actor_class(),
            run,
            line: line.cloned(),
        };
        let handle = tokio::runtime::Handle::current();
        let (card, listed) =
            handle.block_on(render_live_weave_lens_for_run(server, caller, request, owner));
        rows = listed;
        encode(card?)
    })?;
    Ok((output, rows))
}
