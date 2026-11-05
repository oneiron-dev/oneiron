//! Core half of `origin::smart_http::evidence::scan`: its store-layer items live in `oneiron_store::origin::smart_http::evidence::scan` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::smart_http::evidence::scan::*;

use super::{receive_pack_field, receive_pack_fields, receive_pack_provenance_refused};
use crate::error::Result;
use crate::write_envelope::claim_body::ClaimBody;
use rmpv::Value;
use serde::{Deserialize, Serialize};

/// What one outcome says of its push's scan.
#[derive(Clone, Copy)]
pub(super) enum OutcomeScan {
    /// The landed door scanned the push: its intent's summary.
    Landed(ReceivePackScanSummary),
    /// The no-op seam scanned nothing.
    NotPerformed,
}

impl OutcomeScan {
    /// The scan an outcome says under its admission's `door_seam`: the
    /// landed door's `summary`, or none for the no-op seam.
    ///
    /// # Errors
    /// A seam no admission is written with.
    pub(super) fn of(door_seam: Option<&str>, summary: ReceivePackScanSummary) -> Result<Self> {
        match door_seam {
            Some("landed") => Ok(Self::Landed(summary)),
            Some("noop") => Ok(Self::NotPerformed),
            _ => Err(receive_pack_provenance_refused(
                "unknown admitted door seam",
            )),
        }
    }

    /// Whether the landed door scanned the push, clean or marked: such an
    /// outcome is checked against the push once it is written.
    pub(super) const fn landed(self) -> bool {
        matches!(self, Self::Landed(_))
    }

    /// The schema the outcome is written at.
    pub(super) const fn schema_version(self) -> u16 {
        match self {
            Self::Landed(ReceivePackScanSummary::Marked { .. }) => MARKED_OUTCOME_SCHEMA,
            Self::Landed(ReceivePackScanSummary::Clean) | Self::NotPerformed => OUTCOME_SCHEMA,
        }
    }

    /// The outcome's `scan`.
    pub(super) const fn tag(self) -> &'static str {
        match self {
            Self::Landed(ReceivePackScanSummary::Clean) => "clean",
            Self::Landed(ReceivePackScanSummary::Marked { .. }) => "marked",
            Self::NotPerformed => "not_performed",
        }
    }

    /// The outcome's claim value from `fields`: a marked outcome's
    /// `mark_count` goes right after its `scan`, and every other outcome
    /// keeps exactly `fields`.
    pub(super) fn outcome_fields(self, mut fields: Vec<(&str, Value)>) -> Value {
        if let Self::Landed(ReceivePackScanSummary::Marked { mark_count }) = self
            && let Some(at) = fields.iter().position(|(key, _)| *key == "scan")
        {
            fields.insert(at + 1, ("mark_count", Value::from(mark_count)));
        }
        receive_pack_fields(fields)
    }
}

/// Whether `outcome` says a scan a landed, admitted push's outcome can say:
/// clean, as every outcome before marks said, or marked at the marked
/// schema with its count. Any count is one; no count refuses on its own.
///
/// # Errors
/// An outcome with no `scan`.
pub(super) fn landed_scan_reads(outcome: &ClaimBody) -> Result<bool> {
    let field = |key: &str| receive_pack_field(outcome, key).ok();
    Ok(match receive_pack_field(outcome, "scan")?.as_str() {
        Some("clean") => true,
        Some("marked") => {
            field("schema_version").and_then(Value::as_u64)
                == Some(u64::from(MARKED_OUTCOME_SCHEMA))
                && field("mark_count").and_then(Value::as_u64).is_some()
        }
        _ => false,
    })
}
