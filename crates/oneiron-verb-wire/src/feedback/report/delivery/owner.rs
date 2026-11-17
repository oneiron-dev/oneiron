//! Moved from `crates/oneiron/src/feedback/report/delivery/owner.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::feedback::report::delivery::ReportPublisherEndpoint;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The owner's run-now ask. It carries no plan, lease or stamp: the
/// production delivery runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryRunRequest {}

/// The delivery run a run-now ask queued, or the queued one it joined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryRun {
    /// 32 hex: the run's attempt.
    pub attempt: EntityId,
}

/// Which issue's delivery to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryStatusRequest {
    /// 32 hex: the ISSUE.
    pub issue_ref: String,
}

/// The owner's change of one publisher's binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportPublisherBindingRequest {
    /// The publisher, as reports are routed to it.
    pub publisher_ref: String,
    /// `true` binds it to this host's feedback destination; `false` unbinds.
    pub bound: bool,
}

/// One publisher's binding after a change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportPublisherBinding {
    /// The publisher.
    pub publisher_ref: String,
    /// Where its signatures go; `None` while unbound.
    pub endpoint: Option<ReportPublisherEndpoint>,
}
