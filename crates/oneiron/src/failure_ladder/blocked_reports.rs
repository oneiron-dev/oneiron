//! Blocked-report refs, verification against the vault, and Issues ingestion.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_MESSAGE;

/// Reference-only projection of ONE-1686's durable `report_blocked` receipt.
///
/// The category/detail stay owned by and decoded through ONE-1686. This lane
/// deliberately does not duplicate that four-category enum or its receipt
/// codec, so the ref stays opaque here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedReportRef {
    /// Lowercase-hex EntityId spelling.
    pub receipt_ref: String,
}

/// Internal verification result. Dropped reports remain unit-testable without
/// becoming case/card data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BlockedReportVerification {
    Verified(BlockedReportRef),
    Dropped { receipt_ref: String },
}

/// Verifies each supplementary report ref against the landed ONE-1686 surface.
///
/// SEAM (ONE-1686): the landed 1686 surface exposes the `self.*` effect
/// vocabulary and its witnessed MESSAGE ceiling, but no `report_blocked`
/// receipt kind or codec. Until one lands there is nothing to import and
/// nothing to re-implement, so verification stays at the structural floor the
/// landed surface does support: the ref must resolve to a LIVE witnessed
/// MESSAGE row. Everything else — an unparseable ref, an absent row, a
/// header-only (soft-deleted) shell, a foreign entity type — is fail-closed
/// [`BlockedReportVerification::Dropped`]. A dropped ref never reaches a case
/// or a card, and no report of either kind decides a failure class.
pub(super) fn verify_blocked_reports(
    vault: &Vault,
    reports: &[BlockedReportRef],
) -> Result<Vec<BlockedReportVerification>> {
    reports
        .iter()
        .map(|report| verify_blocked_report(vault, report))
        .collect()
}

fn verify_blocked_report(
    vault: &Vault,
    report: &BlockedReportRef,
) -> Result<BlockedReportVerification> {
    let dropped = || BlockedReportVerification::Dropped {
        receipt_ref: report.receipt_ref.clone(),
    };
    let Ok(receipt) = EntityId::from_hex(&report.receipt_ref) else {
        return Ok(dropped());
    };
    let Some(raw) = vault.get_raw(&receipt)? else {
        return Ok(dropped());
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(dropped());
    };
    // A header-only row is the ARCH-0038 soft-delete shell (or an empty body):
    // it parses, but it is not a durable receipt.
    if header.entity_type != ENTITY_TYPE_MESSAGE
        || raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN
    {
        return Ok(dropped());
    }
    Ok(BlockedReportVerification::Verified(report.clone()))
}

/// One verified `report_blocked` receipt, projected for the Dreamer Issues job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureIssueEntry {
    pub report: BlockedReportRef,
    pub semi_trusted: bool,
}

/// Verifies and projects a report into Issues.
///
/// This function never calls a queue, dispatcher, landing requester, or human
/// surface: a report is supplementary, semi-trusted evidence and is NEVER
/// sufficient to arm the ladder. An unverifiable ref is refused here rather
/// than projected, so a dropped receipt cannot reach an Issues feed either.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the ref does not verify.
pub fn ingest_report_blocked(vault: &Vault, report: BlockedReportRef) -> Result<FailureIssueEntry> {
    match verify_blocked_report(vault, &report)? {
        BlockedReportVerification::Verified(report) => Ok(FailureIssueEntry {
            report,
            semi_trusted: true,
        }),
        BlockedReportVerification::Dropped { receipt_ref } => Err(Error::InvalidConfig(format!(
            "blocked report {receipt_ref} does not resolve to a durable report_blocked receipt"
        ))),
    }
}
