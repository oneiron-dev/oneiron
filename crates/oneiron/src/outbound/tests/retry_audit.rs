//! Retry audit history and receipt/queue transaction regressions.

use super::*;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, EnqueueAttempt,
    EnqueueOutcome, RetryAttempt,
};
use crate::outbound::retry_audit::persist_failed_send_receipt_and_retry;
use crate::receipt::{
    FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED, ReceiptKind, ReceiptQuery, ReceiptRecord,
    delivered_send_receipt_for_task, outbound_intent_receipt, persist_send_receipt,
    persist_send_receipt_in_txn,
};

fn audit_receipts(vault: &Vault) -> crate::Result<Vec<ReceiptRecord>> {
    vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Outbound))
}

#[test]
fn two_retryable_transport_failures_retain_both_audit_rows() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0xE0);
    put_connector_task_actor(&vault, actor, ONE_1768_SCHEDULED_AT)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xEC),
        &policy_manifest(&actor.to_hex(), "slack", &["react"]),
    )?;
    let draft = one_1768_draft("slack", "react", "retry-audit-history");
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;
    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_rate_limited")
            .with_receipt_field("retry_after", "900"),
        ..RecordingExecutor::default()
    };
    let first_at = ONE_1768_EXECUTE_AT;
    run_parked_round(&vault, &mut executor, first_at, 0);
    let first = audit_receipts(&vault)?.remove(0);

    let second_at = first_at + 900;
    executor.outcome =
        OutboundExecutionOutcome::failed("provider_busy").with_receipt_field("retry_after", "60");
    run_parked_round(&vault, &mut executor, second_at, 1);
    assert_eq!(
        executor.calls.len(),
        2,
        "a failed audit is not a send token"
    );
    let receipts = audit_receipts(&vault)?;
    assert_eq!(receipts.len(), 2);
    assert_eq!(
        receipts[1], first,
        "the first provider evidence is unchanged"
    );
    assert_ne!(receipts[0].receipt_id, receipts[1].receipt_id);
    for (receipt, occurred_at, delay, state) in [
        (&receipts[1], first_at, 900, "provider_rate_limited"),
        (&receipts[0], second_at, 60, "provider_busy"),
    ] {
        assert_eq!(receipt.outcome, "failed");
        assert_eq!(receipt.occurred_at, occurred_at);
        assert_eq!(receipt_field(receipt, "dispatch_outcome"), Some("failed"));
        assert_eq!(receipt_field(receipt, "retry_state"), Some(state));
        assert_eq!(receipt.fields["retry_after"], delay.to_string());
        assert_eq!(receipt.fields["provider_retry_after"], delay.to_string());
        assert_eq!(
            receipt.fields["retry_at"],
            (occurred_at + delay).to_string()
        );
        assert_eq!(receipt.fields[FIELD_TASK_REF], task_ref.to_hex());
        assert_eq!(
            receipt_field(receipt, FIELD_TRANSPORT_DISPATCHED),
            Some("false")
        );
    }
    assert_eq!(vault.store.send_receipt_rows()?.len(), 2);
    assert!(!send_receipt_exists_for_task(&vault, task_ref)?);
    assert_eq!(delivered_send_receipt_for_task(&vault, task_ref)?, None);
    assert_eq!(
        vault.store.get_delivered_send_task_by_idempotency(
            &actor,
            draft.idempotency_key.as_deref().expect("client key"),
        )?,
        None
    );
    let attempts = one_1768_bridge_attempts(&vault)?;
    assert_eq!(attempts.len(), 3);
    for (source, receipt) in attempts[..2].iter().zip(receipts.iter().rev()) {
        assert_eq!(source.state, AttemptState::Failed);
        assert!(
            receipt
                .receipt_id
                .contains(&crate::receipt::hex_lower(source.id.as_bytes()))
        );
    }
    assert_eq!(attempts[1].retry_of, Some(attempts[0].id));
    assert_eq!(attempts[2].retry_of, Some(attempts[1].id));
    assert_eq!(attempts[2].state, AttemptState::Scheduled);
    assert_eq!(attempts[2].scheduled_at, Some(second_at + 60));
    assert_eq!(attempts[2].attempt_count, 0);
    assert_eq!(vault.connector_send_task(&task_ref)?.unwrap().outcome, None);
    Ok(())
}

#[test]
fn two_holds_retain_both_audit_rows() -> crate::Result<()> {
    let (_tmp, vault, actor) = gate_pending_fixture(0xE2)?;
    let task_ref = schedule_gate_pending_send(&vault, actor, "hold-audit-history")?;
    let mut executor = RecordingExecutor::default();
    run_parked_round(&vault, &mut executor, ONE_1768_EXECUTE_AT, 0);
    let first = audit_receipts(&vault)?.remove(0);
    run_parked_round(&vault, &mut executor, ONE_1768_EXECUTE_AT + 1, 1);
    assert!(executor.calls.is_empty());

    let receipts = audit_receipts(&vault)?;
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[1], first);
    assert_ne!(receipts[0].receipt_id, receipts[1].receipt_id);
    for receipt in &receipts {
        assert_eq!(receipt.outcome, "failed");
        assert_eq!(receipt_field(receipt, "dispatch_outcome"), Some("held"));
        assert_eq!(receipt_field(receipt, "gate_outcome"), Some("pending"));
        assert_eq!(
            receipt_field(receipt, FIELD_TRANSPORT_DISPATCHED),
            Some("false")
        );
        assert!(receipt.fields.contains_key("gate_decision_ref"));
    }
    assert_eq!(
        receipts[1].fields["retry_at"],
        (ONE_1768_EXECUTE_AT + 1).to_string()
    );
    assert_eq!(
        receipts[0].fields["retry_at"],
        (ONE_1768_EXECUTE_AT + 3).to_string()
    );
    let attempts = one_1768_bridge_attempts(&vault)?;
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0].state, AttemptState::Failed);
    assert_eq!(attempts[1].state, AttemptState::Failed);
    assert_eq!(attempts[1].retry_of, Some(attempts[0].id));
    assert_eq!(attempts[2].retry_of, Some(attempts[1].id));
    assert_eq!(attempts[2].state, AttemptState::Scheduled);
    assert_eq!(attempts[2].scheduled_at, Some(ONE_1768_EXECUTE_AT + 3));
    assert!(!send_receipt_exists_for_task(&vault, task_ref)?);
    assert_eq!(
        vault
            .store
            .get_delivered_send_task_by_idempotency(&actor, "one-1768:hold-audit-history",)?,
        None
    );
    Ok(())
}

fn leased_retry_source(vault: &Vault, task_ref: EntityId) -> crate::Result<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    queue.enqueue_with_task_ref(
        EnqueueAttempt {
            kind: crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
            payload: connector_send_attempt_payload(task_ref)?,
            dedupe_key: Some("atomic-audit".to_owned()),
            run_id: Some("run:atomic-audit".to_owned()),
            now: 100,
        },
        Some(task_ref.to_hex()),
    )?;
    match queue.claim(ClaimAttempt {
        lease_owner: "connector-task-executor".to_owned(),
        now: 101,
    })? {
        ClaimOutcome::Claimed(attempt) => Ok(attempt),
        ClaimOutcome::Empty => panic!("fixture is claimable"),
    }
}

fn audit_receipt(id: &str, outcome: &str) -> ReceiptRecord {
    outbound_intent_receipt(
        id,
        "intent:atomic-audit",
        &OutboundIntent::from_trigger(
            OutboundIntentDraft::new("actor:atomic-audit", "react", "slack", "channel:ops"),
            OutboundIntentTrigger::agent_immediate("session:atomic-audit"),
        ),
        101,
        outcome,
    )
}

type RawRows = Vec<(Vec<u8>, Vec<u8>)>;

/// Includes both receipt keyspaces, the idempotency/run indexes, and all queue
/// state. Every database is read in the same snapshot.
fn retry_storage_snapshot(vault: &Vault) -> crate::Result<Vec<RawRows>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut snapshot = Vec::new();
    for db in [
        &vault.store.vault_meta,
        &vault.store.attempt_records,
        &vault.store.attempt_ready,
        &vault.store.attempt_dedupe,
    ] {
        let mut rows = Vec::new();
        for row in db.iter(&rtxn)? {
            let (key, value) = row?;
            rows.push((key.into_owned(), value.into_owned()));
        }
        snapshot.push(rows);
    }
    Ok(snapshot)
}

#[test]
fn persist_and_retry_are_one_txn() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let task_ref = entity(0xE4);
    let source = leased_retry_source(&vault, task_ref)?;
    let queue = AttemptQueue::new(&vault);
    let before = retry_storage_snapshot(&vault)?;
    let mut stale = source.clone();
    stale.attempt_count += 1;
    let receipt = audit_receipt("outbound:atomic-audit", "failed");
    let error = persist_failed_send_receipt_and_retry(
        &vault,
        &stale,
        task_ref,
        receipt.clone(),
        "provider_busy",
        1_001,
        101,
    )
    .expect_err("the receipt write must roll back when retry rejects a stale lease");
    assert!(matches!(
        error,
        Error::InvalidAttemptQueueTransition {
            action: "retry",
            state: "stale_attempt",
        }
    ));
    assert_eq!(retry_storage_snapshot(&vault)?, before);
    assert!(vault.store.send_receipt_rows()?.is_empty());
    assert_eq!(vault.store.get_send_receipt_by_task(&task_ref)?, None);
    assert!(audit_receipts(&vault)?.is_empty());
    assert_eq!(queue.list()?, vec![source.clone()]);

    assert!(persist_failed_send_receipt_and_retry(
        &vault,
        &source,
        task_ref,
        receipt,
        "provider_busy",
        1_001,
        101,
    )?);
    // Read the summary and both attempt rows from one transaction, not from
    // snapshots that could each tell a different story.
    vault.with_write_txn(|wtxn| {
        #[derive(serde::Deserialize)]
        struct Summary {
            receipt: ReceiptRecord,
        }
        let raw = vault
            .store
            .get_send_receipt_by_task_in_txn(wtxn, &task_ref)?
            .expect("receipt committed");
        let summary: Summary = rmp_serde::from_slice(&raw).expect("receipt envelope");
        let attempts = queue.list_task_in_write_txn(wtxn, &task_ref.to_hex())?;
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].state, AttemptState::Failed);
        assert_eq!(attempts[0].last_error.as_deref(), Some("provider_busy"));
        assert_eq!(attempts[1].state, AttemptState::Scheduled);
        assert_eq!(attempts[1].retry_of, Some(source.id));
        assert_eq!(attempts[1].attempt_count, 0);
        assert_eq!(attempts[1].scheduled_at, Some(1_001));
        assert_eq!(summary.receipt.fields["retry_at"], "1001");
        Ok(())
    })?;
    assert_eq!(queue.list_run("run:atomic-audit")?.len(), 2);
    let retry = match queue.enqueue(EnqueueAttempt {
        kind: source.kind.clone(),
        payload: source.payload.clone(),
        dedupe_key: source.dedupe_key.clone(),
        run_id: source.run_id.clone(),
        now: 102,
    })? {
        EnqueueOutcome::Existing(retry) => retry,
        EnqueueOutcome::Enqueued(_) => panic!("the dedupe index must move to the successor"),
    };
    assert_eq!(retry.retry_of, Some(source.id));
    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "connector-task-executor".to_owned(),
            now: 1_000,
        })?,
        ClaimOutcome::Empty
    );
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "connector-task-executor".to_owned(),
        now: 1_001,
    })?
    else {
        panic!("the successor must be ready at the receipted edge");
    };
    assert_eq!(claimed.id, retry.id);
    Ok(())
}

#[test]
fn receipt_and_retry_caller_abort_rolls_back_every_index() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let task_ref = entity(0xE5);
    let source = leased_retry_source(&vault, task_ref)?;
    let queue = AttemptQueue::new(&vault);
    let before = retry_storage_snapshot(&vault)?;
    let result: crate::Result<()> = vault.with_write_txn(|wtxn| {
        let mut receipt = audit_receipt("outbound:caller-abort", "failed");
        receipt
            .fields
            .insert("retry_at".to_owned(), "1001".to_owned());
        assert!(persist_send_receipt_in_txn(
            &vault.store,
            wtxn,
            task_ref,
            receipt,
            SendReceiptOutcome::Failed,
            false,
            None,
        )?);
        queue.retry_in_txn(
            wtxn,
            RetryAttempt {
                id: source.id,
                lease_owner: "connector-task-executor".to_owned(),
                attempt_count: source.attempt_count,
                backoff_until: 1_001,
                last_error: Some("provider_busy".to_owned()),
                now: 101,
            },
        )?;
        assert_eq!(
            queue
                .list_task_in_write_txn(wtxn, &task_ref.to_hex())?
                .len(),
            2
        );
        Err(Error::InvariantViolation("forced abort after retry writes"))
    });
    assert!(matches!(
        result,
        Err(Error::InvariantViolation("forced abort after retry writes"))
    ));
    assert_eq!(retry_storage_snapshot(&vault)?, before);
    assert_eq!(queue.list()?, vec![source]);
    assert!(vault.store.send_receipt_rows()?.is_empty());
    Ok(())
}

#[test]
fn already_delivered_does_not_rearm() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let task_ref = entity(0xE6);
    let actor = entity(0xE7);
    let source = leased_retry_source(&vault, task_ref)?;
    assert!(persist_send_receipt(
        &vault,
        task_ref,
        audit_receipt("outbound:delivered-winner", "delivered_to_channel"),
        SendReceiptOutcome::Delivered,
        true,
        Some((actor, "delivered-winner")),
    )?);
    let delivered = delivered_send_receipt_for_task(&vault, task_ref)?;
    let before = retry_storage_snapshot(&vault)?;
    for reason in ["held", "degraded", "transport_failed_pending"] {
        assert!(!persist_failed_send_receipt_and_retry(
            &vault,
            &source,
            task_ref,
            audit_receipt("outbound:late-failed-audit", "failed"),
            reason,
            1_001,
            101,
        )?);
        assert_eq!(retry_storage_snapshot(&vault)?, before);
    }
    assert_eq!(AttemptQueue::new(&vault).list()?, vec![source]);
    assert_eq!(
        delivered_send_receipt_for_task(&vault, task_ref)?,
        delivered
    );
    assert_eq!(audit_receipts(&vault)?.len(), 1);
    assert_eq!(
        vault
            .store
            .get_delivered_send_task_by_idempotency(&actor, "delivered-winner")?,
        Some(task_ref)
    );
    Ok(())
}

#[test]
fn delivered_summary_and_idempotency_keep_first_winners() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0xE8);
    let first_task = entity(0xE9);
    let second_task = entity(0xEA);
    for (task_ref, id) in [
        (first_task, "outbound:first"),
        (second_task, "outbound:second"),
    ] {
        assert!(persist_send_receipt(
            &vault,
            task_ref,
            audit_receipt(id, "delivered_to_channel"),
            SendReceiptOutcome::Delivered,
            true,
            Some((actor, "shared-key")),
        )?);
    }
    let winner = delivered_send_receipt_for_task(&vault, first_task)?;
    let before = retry_storage_snapshot(&vault)?;
    assert!(!persist_send_receipt(
        &vault,
        first_task,
        audit_receipt("outbound:replacement", "delivered_to_channel"),
        SendReceiptOutcome::Delivered,
        true,
        Some((actor, "new-key")),
    )?);
    assert_eq!(retry_storage_snapshot(&vault)?, before);
    assert_eq!(delivered_send_receipt_for_task(&vault, first_task)?, winner);
    assert_eq!(
        vault
            .store
            .get_delivered_send_task_by_idempotency(&actor, "shared-key")?,
        Some(first_task)
    );
    assert_eq!(
        vault
            .store
            .get_delivered_send_task_by_idempotency(&actor, "new-key")?,
        None
    );
    assert_eq!(audit_receipts(&vault)?.len(), 2);
    Ok(())
}

#[test]
fn send_receipt_identity_cannot_replace_audit_evidence() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let task_ref = entity(0xEB);
    let first = audit_receipt("outbound:immutable-attempt", "failed");
    assert!(persist_send_receipt(
        &vault,
        task_ref,
        first.clone(),
        SendReceiptOutcome::Failed,
        false,
        None,
    )?);
    let before = retry_storage_snapshot(&vault)?;
    assert!(persist_send_receipt(
        &vault,
        task_ref,
        first.clone(),
        SendReceiptOutcome::Failed,
        false,
        None,
    )?);
    assert_eq!(retry_storage_snapshot(&vault)?, before);
    let mut changed = first;
    changed
        .fields
        .insert("retry_at".to_owned(), "2000".to_owned());
    assert!(matches!(
        persist_send_receipt(
            &vault,
            task_ref,
            changed,
            SendReceiptOutcome::Failed,
            false,
            None,
        ),
        Err(Error::InvariantViolation("send receipt identity reused"))
    ));
    assert_eq!(retry_storage_snapshot(&vault)?, before);
    Ok(())
}
