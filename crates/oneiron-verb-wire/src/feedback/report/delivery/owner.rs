//! Moved from `crates/oneiron/src/feedback/report/delivery/owner.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::feedback::report::delivery::ReportDeliveryKey;
use crate::feedback::report::delivery::ReportDeliveryRecord;
use crate::feedback::report::delivery::ReportPublisherEndpoint;
use crate::feedback::report::validate_ref;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::dreamer_attempt_payload::DreamerAttemptPayload;
use oneiron_store::side_table::key::SideKey;
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

/// One issue's delivery, as the owner reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryStatus {
    /// The ISSUE.
    pub issue_ref: String,
    /// Whether it is routed to a publisher at all: a local, duplicate,
    /// rejected or denied report sends nothing.
    pub routed: bool,
    /// The signature lane: its key, hold, frozen signature and send,
    /// receipt and outcome. `None` until a run reaches it.
    pub delivery: Option<ReportDeliveryRecord>,
    /// The owner's binding for the issue's publisher, if any.
    pub binding: Option<ReportPublisherEndpoint>,
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
