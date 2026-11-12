//! Moved from `crates/oneiron/src/feedback/report/routing.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::edit_distance::publisher::vocab::IssueCategory;
use crate::feedback::report::ReportDisclosure;
use crate::feedback::report::ReportKind;
use crate::feedback::report::ReportStatus;
use crate::feedback::report::invalid;
use crate::feedback::report::validate_ref;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "destination", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportRoute {
    #[default]
    OwnerInbox,
    Publisher {
        publisher_ref: String,
    },
}

/// The three DEC-0006 choices, scoped to this issue or its already-resolved publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportDisclosureChoice {
    ApproveOnce,
    StopAskingForPublisher,
    Deny,
}
