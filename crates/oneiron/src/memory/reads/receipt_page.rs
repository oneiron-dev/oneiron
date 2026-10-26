//! `vault.receipts`: the gate decision ledger, or the unified family's
//! receipts of the named kinds, newest first, a page at a time (FIX 10186).
//! A limit past [`VAULT_RECEIPTS_PAGE_MAX`] is served that many a page, and
//! `next_after` continues to the rest in the same order: the gate ledger
//! newest decision first (its cursor is the last receipt's `gate:<hex>`
//! ref), the family newest first, then by kind and id (its cursor is
//! `<occurred_at>:<kind>:<receipt id>`). A cursor is a position, not a
//! snapshot: it never expires, and a receipt written after it was read
//! lands ahead of it.

use super::family_receipt;
use crate::entity_id::EntityId;
use crate::memory::support::hex_string;
use crate::memory::{Memory, MemoryError, MemoryReceipt, MemoryResult};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::verbs::{VAULT_RECEIPTS_PAGE_MAX, VaultReceiptsPage};

/// Where a family page ends, in newest-first, then kind and id, order.
struct FamilyCursor {
    occurred_at: u64,
    kind: ReceiptKind,
    receipt_id: String,
}

impl FamilyCursor {
    fn of(record: &ReceiptRecord) -> Self {
        Self {
            occurred_at: record.occurred_at,
            kind: record.receipt_kind,
            receipt_id: record.receipt_id.clone(),
        }
    }

    fn to_text(&self) -> String {
        format!("{}:{}:{}", self.occurred_at, self.kind.as_str(), self.receipt_id)
    }

    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.splitn(3, ':');
        Some(Self {
            occurred_at: parts.next()?.parse().ok()?,
            kind: ReceiptKind::parse(parts.next()?)?,
            receipt_id: parts.next()?.to_owned(),
        })
    }

    /// Whether `record` comes after this cursor.
    fn precedes(&self, record: &ReceiptRecord) -> bool {
        record.occurred_at < self.occurred_at
            || (record.occurred_at == self.occurred_at
                && (record.receipt_kind, record.receipt_id.as_str())
                    > (self.kind, self.receipt_id.as_str()))
    }
}

/// An `after` no page of these kinds returned.
fn foreign_cursor() -> MemoryError {
    MemoryError::bad_request_with(
        "after is not a next_after of vault.receipts under these kinds",
        &["Send the next_after the page before returned, with the same kinds."],
    )
}

/// The family query of `kinds` (`ReceiptKind` names), `limit` receipts.
fn family_query(limit: usize, kinds: &[String]) -> MemoryResult<ReceiptQuery> {
    let mut query = ReceiptQuery::new(limit);
    for name in kinds {
        let kind = ReceiptKind::parse(name.trim()).ok_or_else(|| {
            MemoryError::bad_request_with(
                format!("unknown receipt kind {name:?}"),
                &[
                    "Use one of: outbound, gate, identity_lifecycle, scoped_read, share, artifact_settle, proposal_outcome, commitment_lifecycle, extraction, served_form, hook, reference_refusal, task_lifecycle.",
                ],
            )
        })?;
        query = query.with_kind(kind);
    }
    Ok(query)
}

impl Memory<'_> {
    /// Lists gate decision receipts. A caller off this device sees none about
    /// a device-local claim, and none takes a place in its page.
    pub fn receipts(&self, limit: usize) -> MemoryResult<Vec<MemoryReceipt>> {
        Ok(self
            .gate_records_before(None, limit)?
            .into_iter()
            .map(gate_receipt)
            .collect())
    }

    /// With no `kinds`, [`Self::receipts`], the gate decision ledger. With
    /// kinds (`ReceiptKind` names: `gate`, `hook`, `outbound`, ...), the
    /// unified receipt family's receipts of those kinds, newest first, each
    /// in the same shape with its own fields. A caller off this device sees
    /// none that names a device-local row, judged on its family's explicit
    /// rows (its trigger, a hook run's reads, a share's parties) before any
    /// takes a place in its page, which refills past them (FIX 1119, FIX
    /// 1120). An unknown kind is refused.
    pub fn receipts_of_kinds(
        &self,
        limit: usize,
        kinds: &[String],
    ) -> MemoryResult<Vec<MemoryReceipt>> {
        if kinds.is_empty() {
            return self.receipts(limit);
        }
        let query = family_query(limit, kinds)?;
        let mut receipts = self.vault.receipts_for_caller(query, &self.destination)?;
        // A world's name on the owner's own share receipt is his (FIX 5493).
        crate::share_travel::screen_owner_notice_fields(self, &mut receipts);
        Ok(receipts.into_iter().map(family_receipt).collect())
    }

    /// `vault.receipts` a page at a time: [`Self::receipts_of_kinds`]'s
    /// receipts after `after`, at most `limit` (at most
    /// [`VAULT_RECEIPTS_PAGE_MAX`] a page), and the `next_after` of the rest.
    ///
    /// # Errors
    ///
    /// A zero limit, an unknown kind, an `after` no page of these kinds
    /// returned, or the read's failure.
    pub fn receipts_page(
        &self,
        limit: usize,
        kinds: &[String],
        after: Option<&str>,
    ) -> MemoryResult<VaultReceiptsPage> {
        if limit == 0 {
            return Err(MemoryError::bad_request_with(
                "limit must be at least 1",
                &["Request one receipt or more and continue from next_after."],
            ));
        }
        let limit_clamped = limit > VAULT_RECEIPTS_PAGE_MAX;
        let page = limit.min(VAULT_RECEIPTS_PAGE_MAX);
        let (receipts, next_after) = if kinds.is_empty() {
            self.gate_page(after, page)?
        } else {
            self.family_page(kinds, after, page)?
        };
        Ok(VaultReceiptsPage {
            receipts,
            next_after,
            effective_limit: page,
            limit_clamped,
        })
    }

    /// The gate ledger's receipts before `after`, and the next page's cursor.
    fn gate_page(
        &self,
        after: Option<&str>,
        page: usize,
    ) -> MemoryResult<(Vec<MemoryReceipt>, Option<String>)> {
        let before = after
            .map(|text| {
                text.strip_prefix("gate:")
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .map(|id| GateDecisionId::from_bytes(*id.as_bytes()))
                    .ok_or_else(foreign_cursor)
            })
            .transpose()?;
        let mut records = self.gate_records_before(before, page.saturating_add(1))?;
        let more = records.len() > page;
        records.truncate(page);
        let receipts: Vec<MemoryReceipt> = records.into_iter().map(gate_receipt).collect();
        let next_after = if more {
            receipts.last().map(|receipt| receipt.receipt_ref.clone())
        } else {
            None
        };
        Ok((receipts, next_after))
    }

    /// The family's receipts of `kinds` after `after`, and the next page's
    /// cursor. A pass reads only receipts no newer than the cursor, and
    /// reads again past those at the cursor's own time it already served.
    fn family_page(
        &self,
        kinds: &[String],
        after: Option<&str>,
        page: usize,
    ) -> MemoryResult<(Vec<MemoryReceipt>, Option<String>)> {
        let cursor = after
            .map(|text| FamilyCursor::parse(text).ok_or_else(foreign_cursor))
            .transpose()?;
        let mut query = family_query(page, kinds)?;
        if let Some(cursor) = &cursor {
            query = query.with_time_bounds(None, Some(cursor.occurred_at));
        }
        let mut fetch = page.saturating_add(1);
        let mut records = loop {
            let pass = ReceiptQuery {
                limit: fetch,
                ..query.clone()
            };
            let read = self.vault.receipts_for_caller(pass, &self.destination)?;
            let read_count = read.len();
            let after_cursor: Vec<ReceiptRecord> = read
                .into_iter()
                .filter(|record| cursor.as_ref().is_none_or(|cursor| cursor.precedes(record)))
                .collect();
            let passed = read_count - after_cursor.len();
            if after_cursor.len() > page || read_count < fetch || passed == 0 {
                break after_cursor;
            }
            fetch = page.saturating_add(1).saturating_add(passed);
        };
        let more = records.len() > page;
        records.truncate(page);
        let next_after = if more {
            records.last().map(|record| FamilyCursor::of(record).to_text())
        } else {
            None
        };
        // A world's name on the owner's own share receipt is his (FIX 5493).
        crate::share_travel::screen_owner_notice_fields(self, &mut records);
        Ok((records.into_iter().map(family_receipt).collect(), next_after))
    }

    /// Up to `wanted` gate decisions before `before` (from the newest when
    /// `None`) this caller reads: off this device, none about a device-local
    /// claim takes a place, and the read refills past it.
    fn gate_records_before(
        &self,
        mut before: Option<GateDecisionId>,
        wanted: usize,
    ) -> MemoryResult<Vec<GateDecisionRecord>> {
        let mut records = Vec::new();
        while records.len() < wanted {
            let page = self.vault.store.gate_decisions_page(before, wanted)?;
            let exhausted = page.len() < wanted;
            before = page.last().map(|record| record.decision_id);
            for record in page {
                if records.len() == wanted {
                    break;
                }
                let kept = self.destination.is_off_device()
                    && match record.claim_id {
                        Some(id) => self.vault.device_local_keeps_for(
                            &EntityId::from_bytes(id)?,
                            &self.destination,
                        )?,
                        None => false,
                    };
                if !kept {
                    records.push(record);
                }
            }
            if exhausted || before.is_none() {
                break;
            }
        }
        Ok(records)
    }
}

/// One gate decision in the `vault.receipts` shape.
fn gate_receipt(record: GateDecisionRecord) -> MemoryReceipt {
    MemoryReceipt {
        receipt_ref: format!("gate:{}", record.decision_id.to_hex()),
        kind: ReceiptKind::Gate.as_str().to_owned(),
        outcome: record.outcome,
        created_at: record.created_at,
        reason_codes: record.reason_codes,
        actor_class: record.actor_class,
        actor_ref: record.actor_ref,
        content_kind: record.content_kind,
        claim_ref: record.claim_id.map(|id| hex_string(&id)),
        claim: record
            .claim_id
            .and_then(|id| EntityId::from_bytes(id).ok())
            .map(|id| crate::lens::RecordRef::from_id(ENTITY_TYPE_CLAIM, &id, None)),
        fields: std::collections::BTreeMap::new(),
    }
}
