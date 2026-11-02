//! Base-apply misc arms: edge dispatch and commitment gap-decay.

use super::edge::{apply_edge_op, edge_op_endpoints};
use super::validation::take_lapse_decisions;
use super::*;
use crate::write_envelope::WriteEnvelope;

pub(super) fn apply_edge_arm(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    state: &mut BatchApplyState,
    op: BatchOp,
) -> Result<()> {
    state.project_edge_endpoints.extend(edge_op_endpoints(&op));
    state.had_graph_mutation |= apply_edge_op(store, wtxn, op)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_commitment_gap_decay_arm(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    state: &mut BatchApplyState,
    ids: Vec<EntityId>,
    envelope: WriteEnvelope,
    learned_at: u64,
    text_index_trusted: bool,
) -> Result<()> {
    // CMT-4 (ONE-1541). All-or-nothing by construction: the helper
    // grounds every selected instance before staging a single op and
    // never commits, so one stale, closed or gate-refused member takes
    // the whole selection down with the caller's transaction.
    // Hand each claim the lapse writes its preflight identity in recorded
    // order. The nested ClaimCandidate applies consume its marker, not this
    // outer arm; consuming here again aborts it.
    let lapse_claim_ids = crate::commitment::lapse_claim_ids(&ids)?;
    let lapse_decision_ids =
        take_lapse_decisions(&mut state.preflight_gate_decision_ids, &lapse_claim_ids);
    crate::commitment::lapse_commitments_in_txn(
        store,
        config,
        analyzer,
        wtxn,
        &ids,
        &envelope,
        learned_at,
        text_index_trusted,
        state.write_policy.as_ref(),
        lapse_decision_ids,
    )?;
    Ok(())
}
