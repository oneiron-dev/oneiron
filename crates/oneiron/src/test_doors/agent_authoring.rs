//! Doors for `tests/executor_agent_runtime_tier.rs` (FIX LIBTEST-AGENT-RUNTIME-TIER):
//! authoring an agent definition under a leased attempt's generation fence.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::agent_def::{AgentDefinition, AgentDefinitionPutDisposition};
use crate::attempt_queue::AttemptRecord;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Authors `requested` for `author` at `id`, fenced by `leased`'s generation:
/// the write lands only while the attempt is still leased to the same worker
/// at the same generation. `None` carries no fence, as the unleased door does.
///
/// # Errors
///
/// A `leased` try that is not leased, a fence the attempt no longer holds, an
/// author that is not active and approved, or the store's.
#[allow(clippy::too_many_arguments)]
pub fn put_for_author_with_scope_from_leased(
    vault: &Vault,
    author: &EntityId,
    id: &EntityId,
    requested: &AgentDefinition,
    scope_widens: bool,
    leased: Option<&AttemptRecord>,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<AgentDefinitionPutDisposition> {
    let lease = leased
        .map(crate::agent_def::AgentAuthorLease::from_leased)
        .transpose()?;
    vault.put_agent_definition_for_author_with_scope(
        author,
        id,
        requested,
        scope_widens,
        lease.as_ref(),
        occurred,
        learned_at,
    )
}
