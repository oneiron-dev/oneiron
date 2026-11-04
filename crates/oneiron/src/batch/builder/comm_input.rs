//! Original caller policy admission before a bound communication input projects.

use super::super::ApplyOpsGateMode;
use crate::Vault;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::ClaimGateWrite;
use crate::store::GateWriteMode;
use std::collections::BTreeSet;

pub(super) fn admit_routed_inputs(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    inputs: &[(EntityId, ClaimBody)],
    gate_mode: &mut ApplyOpsGateMode,
) -> Result<()> {
    if inputs.is_empty() {
        return Ok(());
    }
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let mut pending_at_start = BTreeSet::new();
    if gate_mode.persist_pending_consent {
        for (id, _) in inputs {
            if vault.store.pending_gate_consent_in_txn(txn, id)?.is_some() {
                pending_at_start.insert(*id);
            }
        }
    }
    for (id, body) in inputs {
        // The original candidate is admitted, not materialized at its input
        // id. Its FIFO slot must not reach the ordinary Put-apply tail.
        let preflight = gate_mode
            .preflight_gate_decision_ids
            .remove(id)
            .and_then(|mut ids| ids.pop_front())
            .flatten();
        let pending_prompt = super::super::base_apply::pending_prompt_for(&gate_mode.births, id);
        crate::gate::check_claim_policy_for_write_with_preflight_decision(
            &vault.store,
            txn,
            id,
            ClaimGateWrite::plain(body, gate_mode.caller_envelopes.get(id))
                .with_pending_prompt(pending_prompt.as_deref()),
            &policy,
            GateWriteMode {
                record_decision: gate_mode.record_decisions,
                persist_pending_consent: gate_mode.persist_pending_consent,
                resolve_pending: true,
                can_resolve_pending_consent: pending_at_start.contains(id),
                include_source_in_gate_input: gate_mode.include_source_in_gate_input,
            },
            preflight,
        )?;
    }
    Ok(())
}
