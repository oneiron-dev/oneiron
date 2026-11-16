//! Moved from `crates/oneiron/src/feedback/report/routing.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::edit_distance::publisher::vocab::IssueCategory;
use oneiron_verb_wire::feedback::report::ReportKind;
pub use oneiron_verb_wire::feedback::report::routing::ReportDisclosureChoice;
pub use oneiron_verb_wire::feedback::report::routing::ReportRoute;
use serde::Deserialize;
use serde::Serialize;

/// Fixed-shape content-free evidence. No caller-authored reference or prose crosses here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSignature {
    pub issue_ref: String,
    pub subject_hash: [u8; 32],
    pub category: IssueCategory,
    pub kind: ReportKind,
}
