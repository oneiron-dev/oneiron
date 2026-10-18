//! A caller off this device and the receipt family (FIX 1119, FIX 1120):
//! the rows each receipt names, by its family's explicit set, and the page
//! of receipts such a caller reads, each screened whole on those rows before
//! any is mapped, and refilled past the ones withheld.

use super::family::collect_receipt_records;
use super::kernel::{
    MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery, ReceiptRecord, lineage_scan_query,
};
use super::projection::finalize_receipt_query_records;
use crate::Vault;
use crate::claim::CallerLocality;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The `fields` a receipt of each family names rows in, beside its
/// `trigger_ref`: each value a row id (32 hex, after any `<kind>:`
/// prefixes) or a comma-joined list of them. Only these names count: no
/// other field's text is read as a row, so no free string withholds or
/// admits a receipt.
const ROW_FIELDS: &[(ReceiptKind, &[&str])] = &[
    // A hook run: its binding and its body's CODE row. The rows its reads
    // served are its run's own record's (`HOOK_RUN_KEY`).
    (ReceiptKind::Hook, &["binding", "code"]),
    // A share: its parties, and what it shared.
    (
        ReceiptKind::Share,
        &[
            "recipient_ref",
            "subject_ref",
            "audience_ref",
            "share_id",
            "world_refs",
            "facet_refs",
            "artifact",
            "agent",
            "code_artifact_id",
            "blob_artifact_id",
        ],
    ),
];

/// The families whose `actor` and `on_behalf_of` are parties the receipt
/// names as rows: a share's granter, member or recipient.
const PARTY_KINDS: &[ReceiptKind] = &[ReceiptKind::Share];

/// The field a Hook receipt names its run by: the run whose reads it served.
const HOOK_RUN_KEY: &str = "run_key";

/// How much further each refill reaches: the family's projectors run again
/// over this many times the rows the last pass kept.
const REFILL_GROWTH: usize = 2;

/// Every row `receipt` names, by its family's explicit set: its trigger, the
/// rows its family's [`ROW_FIELDS`] hold, a share's parties, and the rows a
/// hook run's reads served. `None` when they cannot be known: a hook receipt
/// whose run is not kept.
fn referenced_rows(vault: &Vault, receipt: &ReceiptRecord) -> Result<Option<Vec<EntityId>>> {
    let mut rows: Vec<EntityId> = receipt
        .trigger_ref
        .as_deref()
        .and_then(row_of)
        .into_iter()
        .collect();
    if PARTY_KINDS.contains(&receipt.receipt_kind) {
        rows.extend(
            [receipt.actor.as_deref(), receipt.on_behalf_of.as_deref()]
                .into_iter()
                .flatten()
                .filter_map(row_of),
        );
    }
    let names = ROW_FIELDS
        .iter()
        .filter(|(kind, _)| *kind == receipt.receipt_kind)
        .flat_map(|(_, names)| names.iter());
    for name in names {
        if let Some(value) = receipt.fields.get(*name) {
            rows.extend(value.split(',').filter_map(row_of));
        }
    }
    if receipt.receipt_kind == ReceiptKind::Hook {
        let read = match receipt.fields.get(HOOK_RUN_KEY) {
            Some(key) => crate::runtime_hooks::hook_run_read_rows(vault, key)?,
            None => None,
        };
        let Some(read) = read else {
            return Ok(None);
        };
        rows.extend(read);
    }
    Ok(Some(rows))
}

/// The row `value` names: 32 hex, after any `<kind>:` prefixes.
fn row_of(value: &str) -> Option<EntityId> {
    let hex = value.trim().rsplit(':').next()?;
    EntityId::from_hex(hex).ok()
}

/// Whether a caller off this device reads `receipt`: its rows are known and
/// no device-local world keeps any of them ([`Vault::off_device_readable`]).
fn off_device_admits(vault: &Vault, receipt: &ReceiptRecord) -> Result<bool> {
    let Some(rows) = referenced_rows(vault, receipt)? else {
        return Ok(false);
    };
    if rows.is_empty() {
        return Ok(true);
    }
    let named = rows.len();
    Ok(vault.off_device_readable(rows)?.len() == named)
}

impl Vault {
    /// The family receipts of `query` a caller at `locality` reads, newest
    /// first, at most `query.limit` of them: on this device, those
    /// [`Vault::receipts`] answers. Off it, each receipt is screened whole on
    /// the rows it names ([`referenced_rows`]) before it takes a place, and
    /// the page refills past the ones withheld: the family's projectors run
    /// again over [`REFILL_GROWTH`] times the rows until the page fills
    /// within receipts no projector's bound could have cut, the receipts run
    /// out under it, or the bound reaches the family's work cap
    /// ([`MAX_RECEIPT_QUERY_SCAN`]). A page at the cap claims no more than
    /// it read.
    pub(crate) fn receipts_for_caller(
        &self,
        query: ReceiptQuery,
        locality: CallerLocality,
    ) -> Result<Vec<ReceiptRecord>> {
        if locality == CallerLocality::OnDevice || query.limit == 0 {
            return self.receipts(query);
        }
        let limit = query.limit;
        let lineage = match query.job_ref {
            Some(_) => Some(collect_receipt_records(self, &lineage_scan_query())?),
            None => None,
        };
        // Every collected receipt in the family's order, none cut yet.
        let whole = ReceiptQuery {
            limit: usize::MAX,
            ..query.clone()
        };
        let mut bound = limit;
        loop {
            let pass = ReceiptQuery {
                limit: bound,
                ..query.clone()
            };
            let ordered = finalize_receipt_query_records(
                collect_receipt_records(self, &pass)?,
                &whole,
                lineage.as_deref(),
            );
            let collected = ordered.len();
            let mut page = Vec::new();
            let mut walked = 0;
            for receipt in ordered {
                if page.len() == limit {
                    break;
                }
                walked += 1;
                if off_device_admits(self, &receipt)? {
                    page.push(receipt);
                }
            }
            // A projector held to `bound` drops only receipts older than
            // every one it kept, so a page filled within the first `bound`
            // receipts, or a pass that collected fewer than `bound`, is the
            // whole answer.
            let settled = if page.len() == limit {
                walked <= bound
            } else {
                collected < bound
            };
            if settled || bound >= MAX_RECEIPT_QUERY_SCAN {
                return Ok(page);
            }
            bound = bound
                .saturating_mul(REFILL_GROWTH)
                .min(MAX_RECEIPT_QUERY_SCAN);
        }
    }
}
