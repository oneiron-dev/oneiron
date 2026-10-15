use super::*;
use crate::receipt::{SendReceiptOutcome, persist_send_receipt};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

fn held(identity: EntityId, intent: &str, impact: u16, at: u64) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: format!("receipt:{intent}"),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: at,
        actor: Some(entity(0x71).to_hex()),
        on_behalf_of: None,
        outcome: "failed".to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: BTreeMap::from([
            ("channel_identity_ref".to_owned(), identity.to_hex()),
            ("dispatch_outcome".to_owned(), "held".to_owned()),
            ("transport_dispatched".to_owned(), "false".to_owned()),
            ("intent_ref".to_owned(), intent.to_owned()),
            ("verb".to_owned(), "send".to_owned()),
            ("channel".to_owned(), "email".to_owned()),
            ("gate_outcome".to_owned(), "pending".to_owned()),
            ("impact".to_owned(), impact.to_string()),
            ("thread_ref".to_owned(), "thread:1".to_owned()),
            ("content_ref".to_owned(), "payload:1".to_owned()),
            ("facet_ref".to_owned(), entity(0x81).to_hex()),
        ]),
    }
}

fn query(identity_ref: Option<EntityId>, limit: usize) -> AgentInboxLensQuery {
    AgentInboxLensQuery {
        identity_ref,
        limit,
        before: None,
    }
}

mod inbound;
