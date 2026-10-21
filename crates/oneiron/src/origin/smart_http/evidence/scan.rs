//! What a receive-pack outcome says of its push's scan (FIX 8032): the
//! summary the intent's writer records in the transaction that writes the
//! push's marks, the outcome fields that carry it, and the check a reader of
//! the outcome holds it to. A clean outcome is written as every outcome was
//! before marks; a marked one says so at its own schema, with how many marks
//! the push's writer added. Neither names a key, an excerpt, a member, or a
//! hash of any of them.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{receive_pack_field, receive_pack_fields, receive_pack_provenance_refused};
use crate::claim::ClaimBody;
use crate::error::Result;

/// The schema a clean or unscanned outcome is written at, as before marks.
const OUTCOME_SCHEMA: u16 = 1;
/// The schema a marked outcome is written at: its `scan` says `marked`, and
/// its `mark_count` follows.
const MARKED_OUTCOME_SCHEMA: u16 = 2;

/// What the landed door's scan of one admitted push came to, as its intent
/// records it in the transaction that writes the push's marks. It is the
/// outcome's only source for the scan: a recovered push's door report is
/// rebuilt clean whatever its scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::origin::smart_http) enum ReceivePackScanSummary {
    /// The scan found no key.
    Clean,
    /// The door admitted the push with its keys marked (FIX 7608). The
    /// door's disposition makes it marked, never its count.
    Marked {
        /// How many `repo.secret_mark` facts the intent's transaction newly
        /// wrote: one per source and placement, spans and opaque residue
        /// alike.
        mark_count: u64,
    },
}

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
