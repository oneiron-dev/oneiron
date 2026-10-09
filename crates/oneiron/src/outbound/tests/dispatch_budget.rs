//! Dispatch budget debit, exhaustion/suspend/resume, ladders, wrap window and charter drift.

use super::*;

#[test]
fn dispatch_holds_on_charter_drift_until_restamped()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = budget_vault_with_key(5)?;
    let key_id = entity(0xB7);
    let pending = vault.propose_connector_charter(&key_id, "never delete on email", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;

    // Hand-corrupt the stored charter text under the stale stamp.
    let mut record = vault.get_connector_key(&key_id)?.expect("record");
    record.charter.as_mut().expect("charter").text = "never delete on email (edited)".to_owned();
    vault.with_write_txn(|wtxn| {
        crate::connector_key::rewrite_connector_key_in_txn(&vault.store, wtxn, &key_id, &record)
    })?;

    // Drift degrades the send to proposed-only: Held, receipted, no debit.
    let mut executor = RecordingExecutor::default();
    let result = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor.clone(), 1), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(result.gate_reason_codes, vec!["gate.pending.charter_drift"]);
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_receipt_reasons")
            .map(String::as_str),
        Some("charter_drift")
    );
    assert!(result.effector_budget.is_none(), "drift skips all debits");
    assert!(executor.calls.is_empty());
    let read = vault
        .effector_budget_read("email", None)?
        .expect("governing key");
    assert_eq!(read.rows[0].used, 0);

    // A fresh propose/approve re-stamps and restores enforcement.
    let restamp = vault.propose_connector_charter(&key_id, "never delete on email", 1_010)?;
    vault.approve_connector_charter(&key_id, restamp.compiled_hash, "owner", 1_011)?;
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 2), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    Ok(())
}
