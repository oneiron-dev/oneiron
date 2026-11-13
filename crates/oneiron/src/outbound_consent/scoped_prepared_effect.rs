use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::IntentLedgerError;

use super::tool_call::PreparedToolCall;

/// The chokepoint effect of one scoped call `prepared_call` by
/// `principal_ref` under `grant_id`, as attempt `attempt_id` call `call_seq`:
/// its pinned Gate input, its budget class and its frozen bytes, the one
/// place both the call's execution and its `can` preflight (FIX 22102) build
/// it. Reads only.
pub(super) fn scoped_prepared_effect(
    vault: &Vault,
    grant_id: EntityId,
    principal_ref: &str,
    attempt_id: AttemptId,
    call_seq: u64,
    prepared_call: &PreparedToolCall,
) -> std::result::Result<crate::outbound_chokepoint::PreparedEffect, IntentLedgerError> {
    let call = prepared_call.call().clone();
    // FIX 6424 part 3: the gate input pins this prepared call.
    let gate = super::approval::scoped_mcp_pinned_gate_input(
        principal_ref,
        grant_id,
        prepared_call,
        attempt_id,
        call_seq,
    );
    let idempotency_supported = prepared_call.idempotency_supported();
    // The Send class follows the dispatched tool's own effect (FIX 8688): a
    // tool its approved slate row declares read-only never debits `Sends`;
    // any other tool on a counterparty-communication catalog does.
    let budget_class = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::connector_key::scoped_tool_effect_in_txn(
            &vault.store,
            &txn,
            &call.server,
            prepared_call.is_read_only(),
        )?
        .budget_class()
    };
    Ok(crate::outbound_chokepoint::PreparedEffect {
        attempt_id,
        call_seq,
        server: call.server,
        tool: call.tool,
        payload: prepared_call.frozen_bytes().to_vec(),
        idempotency_supported,
        resolved_endpoint: Some(call.resolved_endpoint),
        gate,
        budget_class,
        authorization: crate::outbound_chokepoint::PreparedAuthorization::ScopedMcp {
            grant_id,
            principal_ref: principal_ref.to_owned(),
            prepared: Box::new(prepared_call.clone()),
        },
        verified_actor: None,
        owner_proof: None,
        dedupe_key: None,
        suppression_receipt: None,
        admission_ceiling: None,
        co_actor: None,
        exclusive_route: None,
        // The code run that makes the call, from its pending call's caller
        // binding (ARCH-0040 #revert-run).
        run_ref: prepared_call.run_ref().map(str::to_owned),
    })
}
