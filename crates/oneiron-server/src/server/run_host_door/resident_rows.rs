//! The rows a pumped run's door answers from the run's own seats (FIX
//! 2086): `describe(self)`, the run's own self brief, and
//! `vault.weave.lens`, its agent's own live lens. Each runs for the run's
//! agent, which holds no credential, with the row's verb hooks once around
//! it, and answers the same wire value a credential's call of the row does.

use oneiron::claim::WeaveReportRequest;
use oneiron::lens::WeaveLensRequest;

use super::{
    AgentVerb, Arc, BriefHostFacts, DescribeRequest, EntityId, HostWriteOrigin, InvocationId,
    MemoryResult, PoisonError, RunAdmission, RunHostDoor, StreamConnectionId, SyncServer, Value,
    VerifiedSlip, WriteActor, agent_memory, decode, encode, sdk, verb_hook_boundary,
};
use crate::ai_host::{WeaveLensCaller, render_live_weave_lens_for_run};
use crate::lens_frames::CardOwner;

impl RunHostDoor {
    /// What this door holds for its run's `describe(self)` (FIX 17594): the
    /// run ceiling its host bound for the entry in flight, and, for a turn
    /// program a verified slip woke, that slip's credential ceiling beside
    /// the read key it admits on this door, and its comm reach. An ordinary
    /// pumped run holds no slip, so neither credential value; a read key
    /// that does not resolve leaves the credential ceiling unavailable,
    /// logged. The door binds no scratchpad session, so it holds no
    /// scratchpad. Its pins are the ones the run's own board admits now, on
    /// the agent's own lane, as that board reads them
    /// ([`crate::api::run_brief_pins`]); nothing is recorded.
    pub(super) fn brief_host_facts(&self) -> BriefHostFacts {
        let run_ceiling = self
            .run_ceiling
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let credential_ceiling = self.proof.as_ref().and_then(|proof| {
            self.admitting_memory()
                .read_key()
                .inspect_err(|error| {
                    tracing::warn!(
                        code = %error.code,
                        "a turn program's read key did not resolve for its self brief"
                    );
                })
                .ok()
                // A door's call arrives on no registered MCP connector.
                .map(|read_key| {
                    oneiron::context_board::brief_credential_ceiling(proof, &read_key, None)
                })
        });
        BriefHostFacts {
            run_ceiling,
            credential_ceiling,
            communication_credential_ceiling: self.proof.as_ref().map(VerifiedSlip::comm),
            // The door binds no scratchpad session (FIX 2340), so its board
            // renders no SCRATCHPAD and its brief has no session to look in.
            scratchpad: None,
            pins: crate::api::run_brief_pins(&self.server, self.actor),
        }
    }
}

/// Answers the run's `describe(self)`: its self brief as the run stands
/// now, read for its agent over the run's own board connection, its budget
/// the run's own `line`, its ceilings from what its door holds (`host`),
/// and the rows the brief is derived from. Blocking: call it on a blocking
/// thread of the server's runtime.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the run's host binding"
)]
pub(super) fn self_brief_as_agent(
    server: &Arc<SyncServer>,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
    board: &StreamConnectionId,
    line: Option<&RunAdmission>,
    host: &BriefHostFacts,
    input: Value,
) -> MemoryResult<(Value, Vec<EntityId>)> {
    let memory = agent_memory(server, actor, origin, invocation);
    let name = AgentVerb::Describe.as_str();
    let mut rows = Vec::new();
    let output = verb_hook_boundary::row(&memory, name, input, |input| {
        sdk::validate_input(name, &input)?;
        let request: DescribeRequest = decode(input)?;
        let handle = tokio::runtime::Handle::current();
        let (output, sources) = handle.block_on(crate::api::describe_self_for_run(
            server, actor, board, line, host, &request,
        ))?;
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
        let request: WeaveLensRequest = decode(input)?;
        let surface = request.surface;
        let request = WeaveReportRequest {
            sections: request.sections,
        };
        let caller = WeaveLensCaller::Run {
            actor,
            run,
            line: line.cloned(),
        };
        let handle = tokio::runtime::Handle::current();
        let (card, listed) = handle.block_on(render_live_weave_lens_for_run(
            server, caller, request, owner, surface,
        ));
        rows = listed;
        encode(card?)
    })?;
    Ok((output, rows))
}
