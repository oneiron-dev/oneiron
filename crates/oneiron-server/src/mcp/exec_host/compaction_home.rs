//! The compaction host binding of a run its caller's credential entered:
//! the host assembles it from what the credential authenticated, never
//! from a tool argument.

use oneiron::authority::VerifiedSlip;
use oneiron::code_run::bind_compaction_caller;
use oneiron::engine_executor::RunCompaction;
use oneiron::{Vault, WriteActor};

use super::McpCodeModeProvider;
use crate::mcp::actors::McpResolvedActor;

/// A compaction seat for a run `actor`'s credential entered and the host
/// holds none for: its summaries bylined by `write_actor`, the actor the
/// credential writes as, its home read where the connection sits under the
/// slip it proved (`opener`), its passes queued in the credential's turn.
/// `None` keeps the run's window raw.
///
/// FIX 4571: the home's voice wears the credential's placement facet when
/// that facet is an explicit persona scenario of the run's own PERSON, as
/// the persona compile recognizes one; any other facet, or none, wears the
/// PERSON baseline. The placement is what the credential registered, never
/// a tool argument, a label or a searched scenario.
pub(super) fn caller_compaction_seat(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    actor: &McpResolvedActor,
    write_actor: WriteActor,
    opener: Option<VerifiedSlip>,
) -> Option<RunCompaction> {
    // The host's own binding of the caller: the actor its
    // credential writes as, where its connection sits and
    // the slip it proved. Never a tool argument.
    let host = bind_compaction_caller(write_actor, actor.locality(), opener)
        .with_placement_scenario(vault, actor.scope.facet_ref);
    provider.compaction(host, &actor.stream_connection.0, None)
}
