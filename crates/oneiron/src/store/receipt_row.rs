//! Core half of `store::receipt_row`: its store-layer items live in `oneiron_store::receipt_row` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::receipt_row::*;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Query filters for the unified receipt family.
///
/// Empty `kinds` means all supported receipt kinds. `start_at` and `end_at`
/// are inclusive Unix-second bounds over the receipt event time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptQuery {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub kinds: BTreeSet<ReceiptKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_at: Option<u64>,
    /// Only receipts naming this ASSET (lower hex) in their `asset_ref`
    /// field: the served-form receipts of one asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    /// Exclusive cursor: only receipts after this position in newest-first
    /// order, the last row of the page before (FIX 11297). A walk pages by it,
    /// so no number of receipts sharing one second stops the walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<ReceiptScanPosition>,
    #[serde(default = "default_receipt_query_limit")]
    pub limit: usize,
}

impl Default for ReceiptQuery {
    fn default() -> Self {
        Self {
            kinds: BTreeSet::new(),
            actor: None,
            outcome: None,
            job_ref: None,
            start_at: None,
            end_at: None,
            asset_ref: None,
            after: None,
            limit: DEFAULT_RECEIPT_QUERY_LIMIT,
        }
    }
}

impl ReceiptQuery {
    /// Builds an all-kind query with an explicit result limit.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Adds one kind filter.
    #[must_use]
    pub fn with_kind(mut self, kind: ReceiptKind) -> Self {
        self.kinds.insert(kind);
        self
    }

    /// Adds an actor filter.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Adds an outcome filter.
    #[must_use]
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    /// Adds a brief/attempt filter for brief-rooted receipt projections.
    #[must_use]
    pub fn with_job_ref(mut self, job_ref: impl Into<String>) -> Self {
        self.job_ref = Some(job_ref.into());
        self
    }

    /// Adds an asset filter: receipts whose `asset_ref` field names
    /// `asset_ref`, such as the served-form receipts of one ASSET.
    #[must_use]
    pub fn with_asset_ref(mut self, asset_ref: impl Into<String>) -> Self {
        self.asset_ref = Some(asset_ref.into());
        self
    }

    /// Starts the query after `position`, the last receipt of the page
    /// before, in newest-first order (FIX 11297).
    #[must_use]
    pub fn with_after(mut self, position: ReceiptScanPosition) -> Self {
        self.after = Some(position);
        self
    }

    /// Adds inclusive Unix-second time bounds.
    #[must_use]
    pub const fn with_time_bounds(mut self, start_at: Option<u64>, end_at: Option<u64>) -> Self {
        self.start_at = start_at;
        self.end_at = end_at;
        self
    }

    pub(crate) fn includes_kind(&self, kind: ReceiptKind) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&kind)
    }

    pub(crate) fn matches(&self, receipt: &ReceiptRecord) -> bool {
        if !self.includes_kind(receipt.receipt_kind) {
            return false;
        }
        if let Some(actor) = self.actor.as_deref()
            && receipt.actor.as_deref() != Some(actor)
            && receipt.on_behalf_of.as_deref() != Some(actor)
        {
            return false;
        }
        if let Some(outcome) = self.outcome.as_deref()
            && receipt.outcome != outcome
        {
            return false;
        }
        if let Some(start_at) = self.start_at
            && receipt.occurred_at < start_at
        {
            return false;
        }
        if let Some(end_at) = self.end_at
            && receipt.occurred_at > end_at
        {
            return false;
        }
        if let Some(asset_ref) = self.asset_ref.as_deref()
            && receipt.fields.get(FIELD_ASSET_REF).map(String::as_str) != Some(asset_ref)
        {
            return false;
        }
        if let Some(after) = &self.after
            && !after.precedes(receipt)
        {
            return false;
        }
        true
    }
}

/// One projected receipt-family row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptRecord {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub occurred_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_trace: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl ReceiptRecord {
    /// This receipt's free text as the side-row wall keeps it (OF-067), read in
    /// the caller's transaction for the row at `at` (its place and key); `true`
    /// when the wall placed a handle.
    ///
    /// Free text is the open `fields` map, names and values, but for the names
    /// in `except` that the row's own identity or evidence reads. The kind,
    /// outcome, ids, refs, stamps and policy trace are engine-authored and stay
    /// as written.
    pub(crate) fn admit_free_text(
        &mut self,
        dbs: &impl crate::side_table::SideTableDbs,
        wtxn: &mut heed::RwTxn<'_>,
        at: (&str, &[u8]),
        except: &[&str],
    ) -> crate::Result<bool> {
        let mut free: BTreeMap<String, String> = self
            .fields
            .iter()
            .filter(|(name, _)| !except.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        if free.is_empty() {
            return Ok(false);
        }
        let names: BTreeSet<String> = free.keys().cloned().collect();
        if !crate::batch::secret_scan::admit_typed(dbs, wtxn, at, &mut free)? {
            return Ok(false);
        }
        self.fields.retain(|name, _| !names.contains(name));
        self.fields.extend(free);
        Ok(true)
    }
}

/// A receipt-family result with explicit source and result-limit completeness.
///
/// Only `complete` proves that `records` contains every matching receipt.
/// Incomplete records are not a safe candidate set for ranking or lifecycle folds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptScan {
    pub records: Vec<ReceiptRecord>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<ReceiptScanContinuation>,
    /// Send receipt rows skipped as undecodable (FIX 12044): counted, never
    /// read as receipts. A diagnostic of the scan.
    pub undecodable: u32,
}

/// Boundaries of omitted data, not a snapshot or a globally ordered page token.
///
/// Source and result truncation are independent: both boundaries can be present.
/// A source boundary is retained even when every scanned row is filtered out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptScanContinuation {
    /// Exclusive raw ledger key for continuing the reverse attempt-pack walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_pack_before: Option<Vec<u8>>,
    /// First matching record omitted by the result limit, in receipt sort order.
    /// This does not describe rows omitted by a source work cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_record: Option<ReceiptScanPosition>,
}

/// Inclusive position in newest-first receipt order (time descending, kind/id ascending).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptScanPosition {
    pub occurred_at: u64,
    pub receipt_kind: ReceiptKind,
    pub receipt_id: String,
}

impl ReceiptScanPosition {
    /// The position of `receipt` in newest-first receipt order.
    #[must_use]
    pub fn of(receipt: &ReceiptRecord) -> Self {
        Self {
            occurred_at: receipt.occurred_at,
            receipt_kind: receipt.receipt_kind,
            receipt_id: receipt.receipt_id.clone(),
        }
    }

    /// Whether `receipt` comes after this position in newest-first order:
    /// older, or as old and after it by kind, then id.
    #[must_use]
    pub fn precedes(&self, receipt: &ReceiptRecord) -> bool {
        receipt
            .occurred_at
            .cmp(&self.occurred_at)
            .then_with(|| self.receipt_kind.cmp(&receipt.receipt_kind))
            .then_with(|| self.receipt_id.as_str().cmp(receipt.receipt_id.as_str()))
            .is_lt()
    }
}

impl ReceiptScan {
    pub(crate) fn from_complete_records(records: Vec<ReceiptRecord>) -> Self {
        Self {
            records,
            complete: true,
            continuation: None,
            undecodable: 0,
        }
    }

    pub(crate) fn mark_incomplete(&mut self) -> &mut ReceiptScanContinuation {
        self.complete = false;
        self.continuation
            .get_or_insert_with(ReceiptScanContinuation::default)
    }
}

/// Minimal OF-367/RCPT-3 seam for consumers that render receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptView {
    pub component: String,
    pub receipt: ReceiptRecord,
}

impl ReceiptView {
    #[must_use]
    pub fn new(receipt: ReceiptRecord) -> Self {
        Self {
            component: RECEIPT_VIEW_COMPONENT.to_owned(),
            receipt,
        }
    }
}

pub(crate) fn projection_scan_query(mut query: ReceiptQuery) -> ReceiptQuery {
    query.limit = MAX_RECEIPT_QUERY_SCAN;
    query
}

pub(crate) fn lineage_scan_query() -> ReceiptQuery {
    ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN)
}

pub(crate) fn receipt_newest_first_order(
    left: &ReceiptRecord,
    right: &ReceiptRecord,
) -> std::cmp::Ordering {
    right
        .occurred_at
        .cmp(&left.occurred_at)
        .then_with(|| left.receipt_kind.cmp(&right.receipt_kind))
        .then_with(|| left.receipt_id.cmp(&right.receipt_id))
}

/// Keeps at most `limit` records, evicting the oldest under
/// [`receipt_newest_first_order`] — the SAME order
/// [`finalize_receipt_query_records`] finally sorts by, which is what makes a
/// bounded projector buffer lossless with respect to the public answer.
pub(crate) fn retain_newest_receipt(
    receipts: &mut Vec<ReceiptRecord>,
    receipt: ReceiptRecord,
    limit: usize,
) {
    if receipts.len() < limit {
        receipts.push(receipt);
        return;
    }
    let Some((oldest_index, oldest)) = receipts
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| receipt_newest_first_order(left, right))
    else {
        return;
    };
    if receipt_newest_first_order(&receipt, oldest).is_lt() {
        receipts[oldest_index] = receipt;
    }
}
