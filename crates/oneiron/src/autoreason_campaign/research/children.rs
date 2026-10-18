//! Owner-requested experiment work, through the ordinary attenuating dispatcher.
use super::{binding, bounded, hex, invalid, nodes_in_txn, pruned_lineage};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use crate::context_projection::ContextSpec;
use crate::{AttemptId, EntityId, Result, Vault};

/// Enqueue an experiment under an existing campaign parent. The workflow records
/// its candidate afterward through `record_fork` or `record_weave`; this door
/// never invents a candidate, measurement, claim or completed result.
/// # Errors
/// An unbound campaign, an unknown or pruned parent, an invalid intent key,
/// or the dispatcher's ordinary depth, scope, budget and agent refusals.
pub fn create_research_child(
    vault: &Vault,
    root: AttemptId,
    parent: AttemptId,
    agent: EntityId,
    intent_key: &str,
    briefing: String,
    at: u64,
) -> Result<AttemptId> {
    bounded(intent_key, "an experiment child names a bounded intent key")?;
    let binding = binding(vault, root)?;
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    if !nodes.contains_key(parent.as_bytes()) || pruned_lineage(&nodes, &parent) {
        return Err(invalid("an experiment child needs an unpruned campaign parent"));
    }
    drop(txn);
    let outcome = AgentDispatcher::new(vault).dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: Some(parent),
            dedupe_key: Some(format!(
                "research-child:{}:{}:{intent_key}",
                hex(&root),
                hex(&parent),
            )),
            run_id: Some(binding.run_id),
            now: at,
        },
        AgentSpawnContext::default()
            .with_context_spec(ContextSpec::excluded().with_briefing(briefing)),
    )?;
    match outcome {
        AgentDispatchOutcome::Dispatched(status) | AgentDispatchOutcome::Existing(status) => {
            Ok(status.attempt.id)
        }
        _ => Err(invalid("the experiment dispatcher did not enqueue a child")),
    }
}
