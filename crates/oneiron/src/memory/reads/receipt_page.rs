//! `vault.receipts`: the gate decision ledger, or the unified family's
//! receipts of the named kinds, newest first, a page at a time (FIX 10186).
//! Both ledgers use the requested limit. `next_after` continues in the same order: the gate ledger
//! newest decision first (its cursor is the last receipt's `gate:<hex>`
//! ref), the family newest first, then by kind and id (its cursor is
//! `<occurred_at>:<kind>:<receipt id>`). A cursor is a position, not a
//! snapshot: it never expires, and a receipt written after it was read
//! lands ahead of it.
//!
//! One paging algorithm serves every reader ([`ReceiptReader`], FIX 7355): a
//! Memory reads base under its own handle, and a run in a room reads the
//! room's view under the key its host admitted. The room's served forms join
//! the family before it is ordered, screened, refilled and cut, so a page in
//! the room is one page of the room's receipts beside the vault's. The room
//! sees the vault and itself; the vault never sees the room.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::family_receipt;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::limit_ask::EngineLimit;
use crate::memory::support::hex_string;
use crate::memory::{Memory, MemoryError, MemoryReceipt, MemoryResult};
use crate::receipt::{
    MAX_RECEIPT_QUERY_SCAN, ReceiptContent, ReceiptKind, ReceiptQuery, ReceiptRecord,
    ReceiptScanPosition,
};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::settings::ReadDestination;
use crate::store::{GateDecisionId, GateDecisionRecord};

/// Who reads `vault.receipts`, and through what (FIX 7355): the vault, where
/// the read's rows go, the content its served forms are read from, the
/// trigger rows its key reads, and whether it is the vault owner.
pub(crate) trait ReceiptReader {
    /// The vault whose ledgers the read pages.
    fn receipt_vault(&self) -> &Vault;
    /// Where the read's rows go; off this device, each receipt is screened
    /// on the rows it names.
    fn receipt_destination(&self) -> &ReadDestination;
    /// The content target the family's served forms are read from.
    fn receipt_content(&self) -> ReceiptContent<'_>;
    /// Of `ids`, the rows this reader's key reads, each judged by its lane's
    /// point read; `None` for a handle bound to no credential, which keeps
    /// every receipt.
    fn readable_trigger_rows(&self, ids: &[EntityId]) -> MemoryResult<Option<BTreeSet<EntityId>>>;
    /// Whether a served form takes a page place only when this reader's key
    /// reads the ASSET and ASSET_TEXT it names, as well as its trigger: a
    /// room's reader does, since the room's served forms name rows of the
    /// room's other participants (FIX 7355). Base keeps its contract.
    fn screens_served_form_rows(&self) -> bool {
        false
    }
    /// Whether this reader is the vault owner, who reads the world names on
    /// his own notices (FIX 5493).
    fn reads_owner_notices(&self) -> bool;
}

impl ReceiptReader for Memory<'_> {
    fn receipt_vault(&self) -> &Vault {
        self.vault
    }

    fn receipt_destination(&self) -> &ReadDestination {
        &self.destination
    }

    fn receipt_content(&self) -> ReceiptContent<'_> {
        ReceiptContent::base(self.vault)
    }

    fn readable_trigger_rows(&self, ids: &[EntityId]) -> MemoryResult<Option<BTreeSet<EntityId>>> {
        self.credential_readable_ids(ids)
    }

    fn reads_owner_notices(&self) -> bool {
        self.secret_sight()
            .is_ok_and(|sight| sight == crate::secret_custody::SecretSight::Owner)
    }
}

/// One page of `vault.receipts`, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultReceiptsPage {
    pub receipts: Vec<crate::memory::MemoryReceipt>,
    /// The next page's `after`; absent once no older receipt is left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
    /// The requested number of receipts this page could hold.
    pub effective_limit: usize,
    /// Whether the page lowered the requested count; always false.
    #[serde(default)]
    pub limit_clamped: bool,
    /// Send receipt rows skipped as undecodable (FIX 12044): counted, never
    /// read as receipts. None on the gate ledger, which holds no sends.
    pub undecodable: u32,
}

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

    fn into_position(self) -> ReceiptScanPosition {
        ReceiptScanPosition {
            occurred_at: self.occurred_at,
            receipt_kind: self.kind,
            receipt_id: self.receipt_id,
        }
    }

    fn to_text(&self) -> String {
        format!(
            "{}:{}:{}",
            self.occurred_at,
            self.kind.as_str(),
            self.receipt_id
        )
    }

    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.splitn(3, ':');
        Some(Self {
            occurred_at: parts.next()?.parse().ok()?,
            kind: ReceiptKind::parse(parts.next()?)?,
            receipt_id: parts.next()?.to_owned(),
        })
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

/// The row a family receipt names for a credential-bound reader: its
/// trigger's entity id (32 hex after any `<kind>:` prefixes), as the
/// off-device screen reads it. `None` when it names none: pure metadata,
/// which stays.
fn trigger_row_of(receipt: &ReceiptRecord) -> Option<EntityId> {
    let hex = receipt.trigger_ref.as_deref()?.trim().rsplit(':').next()?;
    EntityId::from_hex(hex).ok()
}

impl Memory<'_> {
    /// Lists gate decision receipts. A caller off this device sees none about
    /// a device-local claim, and none takes a place in its page.
    pub fn receipts(&self, limit: usize) -> MemoryResult<Vec<MemoryReceipt>> {
        Ok(gate_records_before(self, None, limit)?
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
    /// 1120). A handle bound to a read credential sees only the receipts
    /// whose trigger row that credential reads, judged before the page cut
    /// with the same refill, and pure metadata. An unknown kind is refused.
    pub fn receipts_of_kinds(
        &self,
        limit: usize,
        kinds: &[String],
    ) -> MemoryResult<Vec<MemoryReceipt>> {
        receipts_of_kinds_for(self, limit, kinds)
    }

    /// `vault.receipts` a page at a time: [`Self::receipts_of_kinds`]'s
    /// receipts after `after`, up to the full requested `limit` on either ledger.
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
        receipts_page_for(self, limit, kinds, after)
    }
}

/// [`Memory::receipts_of_kinds`] for `reader`: with no `kinds` the gate
/// ledger, else the family's receipts of those kinds, its served forms read
/// from the reader's content target before any is screened or cut.
pub(crate) fn receipts_of_kinds_for(
    reader: &impl ReceiptReader,
    limit: usize,
    kinds: &[String],
) -> MemoryResult<Vec<MemoryReceipt>> {
    if kinds.is_empty() {
        return Ok(gate_records_before(reader, None, limit)?
            .into_iter()
            .map(gate_receipt)
            .collect());
    }
    let vault = reader.receipt_vault();
    let content = reader.receipt_content();
    // A credential cut refills past withheld receipts like the off-device
    // one (FIX 9955): an unbound handle keeps its single fetch.
    let mut fetch = limit;
    let mut kept = loop {
        let query = family_query(fetch, kinds)?;
        let receipts = vault.receipts_for_caller(query, reader.receipt_destination(), content)?;
        let exhausted = receipts.len() < fetch;
        let filtered = credential_kept_receipts(reader, receipts)?;
        if filtered.len() >= limit || exhausted || fetch >= MAX_RECEIPT_QUERY_SCAN {
            break filtered;
        }
        fetch = fetch.max(1).saturating_mul(2).min(MAX_RECEIPT_QUERY_SCAN);
    };
    kept.truncate(limit);
    // A world's name on the owner's own share receipt is his (FIX 5493).
    crate::share_travel::screen_owner_notice_fields(|| reader.reads_owner_notices(), &mut kept);
    Ok(kept.into_iter().map(family_receipt).collect())
}

/// `receipts` cut to what `reader`'s credential reads, before any page cut
/// (OF-172 D2): a receipt whose trigger names a row the lane withholds takes
/// no page place, and pure metadata stays. For a reader that screens served
/// forms, a served form's ASSET and ASSET_TEXT are judged the same way. An
/// unbound handle keeps them all, in one lane read over all named rows.
fn credential_kept_receipts(
    reader: &impl ReceiptReader,
    receipts: Vec<ReceiptRecord>,
) -> MemoryResult<Vec<ReceiptRecord>> {
    if receipts.is_empty() {
        return Ok(receipts);
    }
    let screens_forms = reader.screens_served_form_rows();
    let named = |receipt: &ReceiptRecord| -> Vec<EntityId> {
        let mut rows: Vec<EntityId> = trigger_row_of(receipt).into_iter().collect();
        if screens_forms && receipt.receipt_kind == ReceiptKind::ServedForm {
            rows.extend(crate::receipt::served_form_rows(receipt));
        }
        rows
    };
    let ids: Vec<EntityId> = receipts.iter().flat_map(&named).collect();
    if ids.is_empty() {
        return Ok(receipts);
    }
    let Some(readable) = reader.readable_trigger_rows(&ids)? else {
        return Ok(receipts);
    };
    Ok(receipts
        .into_iter()
        .filter(|receipt| named(receipt).iter().all(|id| readable.contains(id)))
        .collect())
}

/// [`Memory::receipts_page`] for `reader`.
///
/// # Errors
///
/// A zero limit, an unknown kind, an `after` no page of these kinds
/// returned, or the read's failure.
pub(crate) fn receipts_page_for(
    reader: &impl ReceiptReader,
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
    let page = limit;
    let (receipts, next_after) = if kinds.is_empty() {
        gate_page(reader, after, page)?
    } else {
        family_page(reader, kinds, after, page)?
    };
    Ok(VaultReceiptsPage {
        receipts,
        next_after,
        effective_limit: page,
        limit_clamped: false,
        undecodable: reader
            .receipt_vault()
            .undecodable_send_receipts_for_kinds(kinds)?,
    })
}

/// The gate ledger's receipts before `after`, and the next page's cursor.
fn gate_page(
    reader: &impl ReceiptReader,
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
    let _ = reader.receipt_vault().measure_limit(
        EngineLimit::RequestedResultRows,
        u64::try_from(page).unwrap_or(u64::MAX),
    );
    let mut records = gate_records_before(reader, before, page.saturating_add(1))?;
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

/// The family's receipts of `kinds` after `after`, in bounded source
/// windows. Each window starts after the last raw receipt walked, so
/// withheld rows and receipts sharing a timestamp never stall the page.
/// Only admitted rows count toward the requested page and its lookahead.
/// Every window reads its served forms from the reader's one content target.
fn family_page(
    reader: &impl ReceiptReader,
    kinds: &[String],
    after: Option<&str>,
    page: usize,
) -> MemoryResult<(Vec<MemoryReceipt>, Option<String>)> {
    let vault = reader.receipt_vault();
    let cursor = after
        .map(|text| FamilyCursor::parse(text).ok_or_else(foreign_cursor))
        .transpose()?;
    let mut query = family_query(page, kinds)?;
    if let Some(cursor) = cursor {
        query = query
            .with_time_bounds(None, Some(cursor.occurred_at))
            .with_after(cursor.into_position());
    }
    let _ = vault.measure_limit(
        EngineLimit::RequestedResultRows,
        u64::try_from(page).unwrap_or(u64::MAX),
    );
    let content = reader.receipt_content();
    let mut records = Vec::new();
    loop {
        let fetch = page
            .saturating_sub(records.len())
            .saturating_add(1)
            .min(MAX_RECEIPT_QUERY_SCAN);
        let pass = ReceiptQuery {
            limit: fetch,
            ..query.clone()
        };
        let (read, walked, exhausted) =
            vault.receipts_window_for_caller(pass, reader.receipt_destination(), content)?;
        records.extend(credential_kept_receipts(reader, read)?);
        if records.len() > page || exhausted {
            break;
        }
        // The full raw window advances even when both screens kept none.
        query.after = walked;
    }
    let more = records.len() > page;
    records.truncate(page);
    let next_after = if more {
        records
            .last()
            .map(|record| FamilyCursor::of(record).to_text())
    } else {
        None
    };
    // A world's name on the owner's own share receipt is his (FIX 5493).
    crate::share_travel::screen_owner_notice_fields(|| reader.reads_owner_notices(), &mut records);
    Ok((
        records.into_iter().map(family_receipt).collect(),
        next_after,
    ))
}

/// Up to `wanted` gate decisions before `before` (from the newest when
/// `None`) `reader` reads: off this device, none about a device-local claim
/// takes a place, and a reader bound to a read credential sees only the
/// decisions whose claim that credential reads, each row by its claim id
/// with pure metadata staying; the read refills past either. The ledger is
/// the vault's: a room keeps no gate decision of its own.
fn gate_records_before(
    reader: &impl ReceiptReader,
    mut before: Option<GateDecisionId>,
    wanted: usize,
) -> MemoryResult<Vec<GateDecisionRecord>> {
    let vault = reader.receipt_vault();
    let destination = reader.receipt_destination();
    let mut records = Vec::new();
    while records.len() < wanted {
        let page = vault.store.gate_decisions_page(before, wanted)?;
        let exhausted = page.len() < wanted;
        before = page.last().map(|record| record.decision_id);
        // A credential-bound reader sees only the rows its read lane admits
        // (OF-172 D2), judged in one lane read per page before any count. An
        // unbound handle reads nothing here, as before.
        let ids: Vec<EntityId> = page
            .iter()
            .filter_map(|record| EntityId::from_bytes(record.claim_id?).ok())
            .collect();
        let readable = if ids.is_empty() {
            None
        } else {
            reader.readable_trigger_rows(&ids)?
        };
        for record in page {
            if records.len() == wanted {
                break;
            }
            // A claim id that does not parse is withheld from such a reader,
            // never an error.
            if let (Some(id), Some(readable)) = (record.claim_id, &readable)
                && !EntityId::from_bytes(id).is_ok_and(|id| readable.contains(&id))
            {
                continue;
            }
            let kept = destination.is_off_device()
                && match record.claim_id {
                    Some(id) => {
                        vault.device_local_keeps_for(&EntityId::from_bytes(id)?, destination)?
                    }
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
