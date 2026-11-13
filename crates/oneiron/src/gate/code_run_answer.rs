//! The optional companion MESSAGE of a canonical code run's final answer.

use super::definition_ceiling::agent_definition_ceiling_for_actor;
use super::witness_message::witness_message_gate_input;
use super::{GateOutcome, resolve_policy_manifest};
use crate::store::Store;
use crate::{Result, WriteActor};

/// Whether the witness policy allows the host to record a final answer as a
/// companion MESSAGE. This is a routing preflight, not write authorization:
/// an allowed answer still goes through the ordinary witness door, whose
/// floor and verdict run again on the write transaction.
///
/// It asks the witness's own question: the same gate input
/// (`witness_message_gate_input`), the same live ceiling resolvers and the
/// same evaluator as `check_witness_message_ceiling_with_permit`. No ceiling
/// policy is decided here.
pub(crate) fn code_run_answer_may_witness(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Result<bool> {
    let policy = resolve_policy_manifest(store, txn)?;
    if !policy.enforces_write_gate() {
        return Ok(true);
    }
    let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, txn, actor);
    let mut input = witness_message_gate_input(actor, agent_definition_ceiling);
    input.foreign_agent_ceiling = super::foreign_agent::resolve(store, txn, actor)?;
    Ok(policy.evaluate_gate(&input).outcome() == GateOutcome::Allow)
}
