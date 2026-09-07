use super::*;
use crate::receipt::{
    MAX_RECEIPT_QUERY_SCAN, ReceiptScanPosition, SendReceiptOutcome, persist_send_receipt,
    put_attempt_pack_receipt_for_test,
};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

fn held(identity: EntityId, intent: &str, impact: u16, at: u64) -> ReceiptRecord {
    ReceiptRecord { receipt_id: format!("receipt:{intent}"), receipt_kind: ReceiptKind::Outbound,
        occurred_at: at, actor: Some(entity(0x71).to_hex()), on_behalf_of: None, outcome: "failed".to_owned(),
        job_ref: None, trigger_ref: None, policy_trace: Vec::new(),
        fields: BTreeMap::from([
            ("channel_identity_ref".to_owned(), identity.to_hex()),
            ("dispatch_outcome".to_owned(), "held".to_owned()),
            ("transport_dispatched".to_owned(), "false".to_owned()),
            ("intent_ref".to_owned(), intent.to_owned()), ("verb".to_owned(), "send".to_owned()),
            ("channel".to_owned(), "email".to_owned()), ("gate_outcome".to_owned(), "pending".to_owned()),
            ("impact".to_owned(), impact.to_string()), ("thread_ref".to_owned(), "thread:1".to_owned()),
            ("content_ref".to_owned(), "payload:1".to_owned()), ("facet_ref".to_owned(), entity(0x81).to_hex()),
        ]) }
}

fn query(identity_ref: Option<EntityId>, limit: usize) -> AgentInboxLensQuery {
    AgentInboxLensQuery { identity_ref, limit, before: None }
}

#[test]
fn approval_pile_filters_identity() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let a = entity(0x61); let b = entity(0x62);
    for (task, receipt) in [(entity(0x31), held(a, "a", 5, 1)), (entity(0x32), held(b, "b", 100, 2))] {
        persist_send_receipt(&vault, task, receipt, SendReceiptOutcome::Failed, false, None).unwrap();
    }
    let items = vault.agent_inbox_lens(query(Some(a), 10)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].identity_ref, a);
    assert_eq!(items[0].kind, AgentInboxItemKind::ApprovalRequired);
    assert_eq!(items[0].actor_ref, entity(0x71));
    assert_eq!(items[0].thread_ref.as_deref(), Some("thread:1"));
    assert_eq!(items[0].payload_ref.as_deref(), Some("payload:1"));
    assert_eq!(items[0].facet_ref, Some(entity(0x81)));
    assert_eq!(vault.agent_inbox_lens(query(None, 10)).unwrap().len(), 2);
    assert!(vault.agent_inbox_lens(query(Some(entity(0x63)), 10)).unwrap().is_empty());
}

#[test]
fn impact_order_beats_count() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let identity = entity(0x61);
    for n in 0..30 {
        persist_send_receipt(&vault, EntityId::now(), held(identity, &format!("low:{n}"), 1, 100 + n),
            SendReceiptOutcome::Failed, false, None).unwrap();
    }
    persist_send_receipt(&vault, entity(0x31), held(identity, "high", 500, 1), SendReceiptOutcome::Failed, false, None).unwrap();
    let items = vault.agent_inbox_lens(query(None, 1)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].impact, InboxImpact(500));
    assert_eq!(items[0].receipt_ref.as_deref(), Some("receipt:high"));
}

#[test]
fn approval_order_and_cursor_are_stable() {
    let identity = entity(0x61);
    let receipts = vec![held(identity, "b", 9, 2), held(identity, "c", 8, 9),
        held(identity, "a", 9, 2), held(identity, "d", 9, 1)];
    let all = project_approval_required(&receipts, query(None, 10)).unwrap();
    assert_eq!(all.iter().map(|i| i.receipt_ref.as_deref().unwrap()).collect::<Vec<_>>(),
        ["receipt:a", "receipt:b", "receipt:d", "receipt:c"]);
    let mut reversed = receipts.clone(); reversed.reverse();
    assert_eq!(project_approval_required(&reversed, query(None, 10)).unwrap(), all);
    let first = project_approval_required(&receipts, query(None, 2)).unwrap();
    let cursor = first.last().unwrap();
    let rest = project_approval_required(&receipts, AgentInboxLensQuery { identity_ref: None, limit: 10,
        before: Some((cursor.impact, cursor.occurred_at, cursor.item_id.clone())) }).unwrap();
    assert_eq!([first, rest].concat(), all);
}

#[test]
fn completed_sends_and_non_approval_holds_leave_the_pile() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let identity = entity(0x61);
    let task = entity(0x31);
    let pending = held(identity, "send:1", 10, 1);
    persist_send_receipt(&vault, task, pending.clone(), SendReceiptOutcome::Failed, false, None).unwrap();
    assert_eq!(vault.agent_inbox_lens(query(None, 10)).unwrap().len(), 1);
    let mut delivered = pending;
    delivered.receipt_id = "receipt:delivered".to_owned();
    delivered.occurred_at = 2;
    delivered.outcome = "delivered_to_channel".to_owned();
    persist_send_receipt(&vault, task, delivered, SendReceiptOutcome::Delivered, true, None).unwrap();
    assert!(vault.agent_inbox_lens(query(None, 10)).unwrap().is_empty());
    let mut window_hold = held(identity, "window", 99, 3);
    window_hold.fields.insert("gate_outcome".to_owned(), "allow".to_owned());
    let mut draft = held(identity, "draft", 99, 3);
    draft.fields.insert("verb".to_owned(), "mail.draft".to_owned());
    assert!(project_approval_required(&[window_hold, draft], query(None, 10)).unwrap().is_empty());
}

fn pack_scan_fixture(count: usize, filler_kind: ReceiptKind) -> (tempfile::TempDir, Vault) {
    let mut config = embedding_test_config();
    config.map_size = 256 * 1024 * 1024;
    let (dir, vault) = open_test_vault_with(config);
    let identity = entity(0x61);
    vault.with_write_txn(|wtxn| {
        for index in 0..count {
            let at = u64::try_from(index).unwrap() + 1;
            let mut receipt = if index == 0 {
                held(identity, "high", 500, at)
            } else if index == count - 1 {
                held(identity, "low", 1, at)
            } else {
                ReceiptRecord {
                    receipt_id: String::new(),
                    receipt_kind: filler_kind,
                    occurred_at: at,
                    actor: None,
                    on_behalf_of: None,
                    outcome: "completed".to_owned(),
                    job_ref: None,
                    trigger_ref: None,
                    policy_trace: Vec::new(),
                    fields: BTreeMap::new(),
                }
            };
            receipt.receipt_id = format!("attempt:{index:032x}");
            put_attempt_pack_receipt_for_test(&vault.store, wtxn, &receipt)?;
        }
        Ok(())
    }).unwrap();
    (dir, vault)
}

fn assert_incomplete_inbox(vault: &Vault) {
    for identity_ref in [None, Some(entity(0x61)), Some(entity(0x62))] {
        assert!(matches!(
            vault.agent_inbox_lens(query(identity_ref, 1)),
            Err(Error::InvalidConfig(message)) if message == "inbox receipt scan is incomplete"
        ));
    }
}

#[test]
fn below_cap_filtered_source_stays_incomplete_and_inbox_fails_closed() {
    // The fixture door can synthesize rows the current pack stamper cannot
    // emit. Off-kind filler makes the source cap fire while the actual inbox
    // receipt query returns only one row, not MAX matching rows.
    let (_dir, vault) = pack_scan_fixture(MAX_RECEIPT_QUERY_SCAN + 1, ReceiptKind::Gate);
    let receipt_query = ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN).with_kind(ReceiptKind::Outbound);
    let scan = vault.scan_receipts(receipt_query.clone()).unwrap();
    assert_eq!(scan.records.len(), 1);
    assert!(!scan.complete);
    let continuation = scan.continuation.unwrap();
    assert_eq!(
        continuation.attempt_pack_before,
        Some(format!("attempt_receipt:v1:attempt:{:032x}", 1).into_bytes())
    );
    assert!(continuation.next_record.is_none());
    assert_eq!(vault.receipts(receipt_query.clone()).unwrap().len(), 1);
    // A predicate matching no scanned row cannot turn a source prefix into
    // complete evidence either, nor can an identity filter authorize ranking.
    let empty = vault.scan_receipts(receipt_query.with_actor(entity(0x72).to_hex())).unwrap();
    assert!(empty.records.is_empty());
    assert!(!empty.complete);
    assert!(empty.continuation.unwrap().attempt_pack_before.is_some());
    assert_incomplete_inbox(&vault);
}

#[test]
fn exact_cap_source_is_complete_and_inbox_keeps_impact_top_n() {
    let (_dir, vault) = pack_scan_fixture(MAX_RECEIPT_QUERY_SCAN, ReceiptKind::Outbound);
    let scan = vault.scan_receipts(
        ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN).with_kind(ReceiptKind::Outbound)
    ).unwrap();
    assert_eq!(scan.records.len(), MAX_RECEIPT_QUERY_SCAN);
    assert!(scan.complete, "the extra source read is empty, not overflow");
    assert!(scan.continuation.is_none());
    let items = vault.agent_inbox_lens(query(Some(entity(0x61)), 1)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].impact, InboxImpact(500));
    assert_eq!(items[0].receipt_ref, Some(format!("attempt:{:032x}", 0)));
}

#[test]
fn capped_overflow_has_source_continuation_and_no_ranked_subset() {
    let (_dir, vault) = pack_scan_fixture(MAX_RECEIPT_QUERY_SCAN + 1, ReceiptKind::Outbound);
    // A larger caller limit cannot increase the source or family result cap.
    let scan = vault.scan_receipts(
        ReceiptQuery::new(usize::MAX).with_kind(ReceiptKind::Outbound)
    ).unwrap();
    assert_eq!(scan.records.len(), MAX_RECEIPT_QUERY_SCAN);
    assert!(!scan.complete);
    let continuation = scan.continuation.as_ref().unwrap();
    assert_eq!(
        continuation.attempt_pack_before,
        Some(format!("attempt_receipt:v1:attempt:{:032x}", 1).into_bytes())
    );
    assert!(continuation.next_record.is_none());
    // Ranking this prefix would return the low-impact ask and lose the older,
    // higher-impact ask beyond the source cap. The production lens must error.
    let prefix = project_approval_required(&scan.records, query(None, 1)).unwrap();
    assert_eq!(prefix[0].impact, InboxImpact(1));
    assert_incomplete_inbox(&vault);

    let limited = vault.scan_receipts(
        ReceiptQuery::new(1).with_kind(ReceiptKind::Outbound)
    ).unwrap();
    assert!(!limited.complete);
    assert_eq!(limited.records.len(), 1);
    let continuation = limited.continuation.unwrap();
    assert!(continuation.attempt_pack_before.is_some());
    assert_eq!(continuation.next_record.unwrap().receipt_id,
        format!("attempt:{:032x}", MAX_RECEIPT_QUERY_SCAN - 1));
}

#[test]
fn result_limit_reports_continuation_without_weakening_inbox_top_n() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let receipt_query = ReceiptQuery::new(0).with_kind(ReceiptKind::Outbound);
    let empty = vault.scan_receipts(receipt_query.clone()).unwrap();
    assert!(empty.complete);
    assert!(empty.records.is_empty());
    assert!(empty.continuation.is_none());
    let identity = entity(0x61);
    for (task, receipt) in [
        (entity(0x31), held(identity, "high", 500, 1)),
        (entity(0x32), held(identity, "low:a", 1, 2)),
        (entity(0x33), held(identity, "low:b", 1, 3)),
    ] {
        persist_send_receipt(&vault, task, receipt, SendReceiptOutcome::Failed, false, None).unwrap();
    }
    let zero = vault.scan_receipts(receipt_query).unwrap();
    assert!(zero.records.is_empty());
    assert!(!zero.complete);
    assert_eq!(zero.continuation.unwrap().next_record.unwrap().receipt_id, "receipt:low:b");
    let scan = vault.scan_receipts(ReceiptQuery::new(2).with_kind(ReceiptKind::Outbound)).unwrap();
    assert_eq!(scan.records.len(), 2);
    assert!(!scan.complete);
    let continuation = scan.continuation.unwrap();
    assert!(continuation.attempt_pack_before.is_none());
    assert_eq!(continuation.next_record, Some(ReceiptScanPosition {
        occurred_at: 1,
        receipt_kind: ReceiptKind::Outbound,
        receipt_id: "receipt:high".to_owned(),
    }));
    let exact = vault.scan_receipts(ReceiptQuery::new(3).with_kind(ReceiptKind::Outbound)).unwrap();
    assert!(exact.complete);
    assert_eq!(exact.records.len(), 3);
    assert!(exact.continuation.is_none());
    let items = vault.agent_inbox_lens(query(None, 1)).unwrap();
    assert_eq!(items[0].impact, InboxImpact(500));
    assert_eq!(items[0].receipt_ref.as_deref(), Some("receipt:high"));
}

#[test]
fn unproven_projectors_and_lineage_are_rejected_by_completeness_scan() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    for receipt_query in [
        ReceiptQuery::new(1),
        ReceiptQuery::new(1).with_kind(ReceiptKind::Gate),
        ReceiptQuery::new(1).with_kind(ReceiptKind::Outbound).with_kind(ReceiptKind::Gate),
        ReceiptQuery::new(1).with_kind(ReceiptKind::Outbound).with_job_ref("brief:1"),
    ] {
        assert!(matches!(vault.scan_receipts(receipt_query), Err(Error::InvalidConfig(_))));
    }
}
