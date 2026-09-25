//! Renderer-neutral inbox query. Visual composition is OWNER-SITTING.
//!
//! ApprovalRequired is a projection of existing identity-stamped held-send
//! receipts. No mailbox, renderer, or independent approval store is created.

use std::collections::BTreeMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};

pub const AGENT_INBOX_LENS_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InboxImpact(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInboxItemKind {
    Conversation,
    ApprovalRequired,
    CoordinationUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInboxLensItem {
    pub item_id: String,
    pub kind: AgentInboxItemKind,
    pub thread_ref: Option<String>,
    pub identity_ref: EntityId,
    pub actor_ref: EntityId,
    pub facet_ref: Option<EntityId>,
    pub impact: InboxImpact,
    pub occurred_at: u64,
    pub receipt_ref: Option<String>,
    pub payload_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInboxLensQuery {
    pub identity_ref: Option<EntityId>,
    pub limit: usize,
    /// Exclusive cursor in the same impact/time/id order as the result.
    pub before: Option<(InboxImpact, u64, String)>,
}

impl Vault {
    /// The TASK lane of the inbox. The plan-view `task_owner` saved-query
    /// operator reads this same index; neither keeps project-derived copies.
    pub fn agent_inbox_tasks(
        &self,
        owner: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        self.tasks_by_owner(owner, after, limit)
    }

    pub fn agent_inbox_lens(&self, query: AgentInboxLensQuery) -> Result<Vec<AgentInboxLensItem>> {
        if query.limit == 0 {
            return Ok(Vec::new());
        }
        // Fetch before filtering/limiting by impact. A capped chronological
        // scan cannot prove impact top-N, so reject instead of returning a
        // silently count-biased pile. The receipt substrate owns this cap.
        let cap = crate::receipt::MAX_RECEIPT_QUERY_SCAN;
        let scan = self.scan_receipts(ReceiptQuery::new(cap).with_kind(ReceiptKind::Outbound))?;
        if !scan.complete {
            return Err(Error::InvalidConfig(
                "inbox receipt scan is incomplete".to_owned(),
            ));
        }
        let mut items = project_receipts(
            &scan.records,
            AgentInboxLensQuery {
                identity_ref: query.identity_ref,
                limit: usize::MAX,
                before: None,
            },
            true,
        )?;
        items.extend(self.inbound_inbox_items(query.identity_ref)?);
        sort_page(&mut items, &query);
        Ok(items)
    }
}

/// Projects both durable and session-local engine receipts. A later non-held
/// outcome for the same identity/actor/intent removes its earlier approval ask.
/// Callers may use this seam for off-record receipts without persisting them.
pub fn project_approval_required(
    receipts: &[ReceiptRecord],
    query: AgentInboxLensQuery,
) -> Result<Vec<AgentInboxLensItem>> {
    project_receipts(receipts, query, false)
}

fn project_receipts(
    receipts: &[ReceiptRecord],
    query: AgentInboxLensQuery,
    unified: bool,
) -> Result<Vec<AgentInboxLensItem>> {
    let mut latest: BTreeMap<(EntityId, EntityId, String), &ReceiptRecord> = BTreeMap::new();
    for receipt in receipts {
        let field = |key: &str| receipt.fields.get(key).map(String::as_str);
        if receipt.receipt_kind != ReceiptKind::Outbound {
            continue;
        }
        let is_send = unified && field("verb") == Some("mail.draft")
            || field("verb") == Some("mail.send")
            || field("verb") == Some("send") && matches!(field("channel"), Some("mail" | "email"));
        if !is_send {
            continue;
        }
        let Some(identity) =
            field("channel_identity_ref").or_else(|| field("receiving_identity_ref"))
        else {
            continue;
        };
        let identity = EntityId::from_hex(identity)?;
        if query.identity_ref.is_some_and(|wanted| wanted != identity) {
            continue;
        }
        let Some(actor) = receipt.actor.as_deref() else {
            continue;
        };
        let actor = EntityId::from_hex(actor)?;
        let intent = field("intent_ref")
            .or_else(|| field("task_ref"))
            .unwrap_or(&receipt.receipt_id);
        let key = (identity, actor, intent.to_owned());
        if latest
            .get(&key)
            .is_none_or(|old| receipt_order(receipt) > receipt_order(old))
        {
            latest.insert(key, receipt);
        }
    }
    let mut items = Vec::new();
    for ((identity_ref, actor_ref, intent), receipt) in latest {
        let pending = receipt
            .fields
            .get("gate_outcome")
            .is_some_and(|v| v == "pending")
            || receipt
                .fields
                .get("hold_reason")
                .is_some_and(|v| v.starts_with("gate.pending."))
            || receipt
                .policy_trace
                .iter()
                .any(|v| v.starts_with("gate.pending."));
        let approval = pending
            && (held_send(receipt)
                || unified
                    && receipt
                        .fields
                        .get("verb")
                        .is_some_and(|v| v == "mail.draft"));
        if !approval && (!unified || held_send(receipt)) {
            continue;
        }
        let impact = receipt
            .fields
            .get("impact")
            .map(|v| v.parse::<u16>())
            .transpose()
            .map_err(|_| Error::InvalidConfig("invalid inbox impact".to_owned()))?
            .unwrap_or(0);
        items.push(AgentInboxLensItem {
            item_id: format!(
                "{}:{}:{}:{intent}",
                if approval { "approval" } else { "coordination" },
                identity_ref.to_hex(),
                actor_ref.to_hex()
            ),
            kind: if approval {
                AgentInboxItemKind::ApprovalRequired
            } else {
                AgentInboxItemKind::CoordinationUpdate
            },
            thread_ref: receipt.fields.get("thread_ref").cloned(),
            identity_ref,
            actor_ref,
            facet_ref: receipt
                .fields
                .get("facet_ref")
                .map(|v| EntityId::from_hex(v))
                .transpose()?,
            impact: InboxImpact(impact),
            occurred_at: receipt.occurred_at,
            receipt_ref: Some(receipt.receipt_id.clone()),
            payload_ref: receipt
                .fields
                .get("payload_ref")
                .or_else(|| receipt.fields.get("content_ref"))
                .cloned(),
        });
    }
    sort_page(&mut items, &query);
    Ok(items)
}

fn sort_page(items: &mut Vec<AgentInboxLensItem>, query: &AgentInboxLensQuery) {
    items.sort_by(|a, b| {
        b.impact
            .cmp(&a.impact)
            .then_with(|| b.occurred_at.cmp(&a.occurred_at))
            .then_with(|| a.item_id.cmp(&b.item_id))
    });
    if let Some((impact, at, id)) = &query.before {
        items.retain(|item| {
            item.impact < *impact
                || item.impact == *impact
                    && (item.occurred_at < *at || item.occurred_at == *at && item.item_id > *id)
        });
    }
    items.truncate(query.limit);
}

fn held_send(receipt: &ReceiptRecord) -> bool {
    // Scheduled holds use the landed failure-audit envelope. Dispatch outcome
    // is the held-send truth; "failed" alone is never an approval request.
    receipt.outcome == "held"
        || receipt.outcome == "failed"
            && receipt
                .fields
                .get("dispatch_outcome")
                .is_some_and(|v| v == "held")
            && receipt
                .fields
                .get("transport_dispatched")
                .is_some_and(|v| v == "false")
}

fn receipt_order(receipt: &ReceiptRecord) -> (u64, bool, &str) {
    (
        receipt.occurred_at,
        !held_send(receipt),
        &receipt.receipt_id,
    )
}

mod inbound;

#[cfg(test)]
mod tests;
