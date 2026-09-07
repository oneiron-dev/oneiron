use super::*;
use crate::receipt::{SendReceiptOutcome, persist_send_receipt};
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
