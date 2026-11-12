//! Moved from `crates/oneiron/src/linear_sync/mirror_event.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::linear_sync::model::LinearFieldConflict;
use crate::linear_sync::model::LinearIssueRef;
use crate::linear_sync::webhook::LinearExternalActor;
use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Bound;

/// The first byte of an event key: what made the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDirection {
    /// A verified webhook delivery.
    IssueToTask = 1,
    /// A push the scheduler sent.
    TaskToIssue = 2,
    /// A mapping edit (link, unlink, mirror).
    MappingEdit = 3,
    /// A public title edit on `tasks.update`.
    TaskEdit = 4,
}

impl EventDirection {
    /// The row's stable wire token.
    pub const fn token(self) -> &'static str {
        match self {
            Self::IssueToTask => "issue_to_task",
            Self::TaskToIssue => "task_to_issue",
            Self::MappingEdit => "mapping_edit",
            Self::TaskEdit => "task_edit",
        }
    }
}

/// One stored mirror event, as the provenance read returns it. Refs and
/// digests are lowercase hex; the external actor is the provider's own
/// evidence, never a vault actor, writer or owner (C3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearMirrorEvent {
    /// `issue_to_task`, `task_to_issue`, `mapping_edit` or `task_edit`.
    pub direction: String,
    /// The TASK the event changed or names; `None` for an ignored delivery.
    pub task_ref: Option<String>,
    /// The issue the event names.
    pub issue: Option<LinearIssueRef>,
    /// The `Linear-Delivery` id of a webhook.
    pub delivery_id: Option<String>,
    /// The mirror operation id the event applied or sent.
    pub operation_id: Option<String>,
    /// Digest of the request the event's key names: a webhook's raw body,
    /// an edit's request.
    pub body_digest: Option<String>,
    /// The archived provider body of a webhook.
    pub payload_ref: Option<String>,
    /// The provider's actor of a webhook.
    pub external_actor: Option<LinearExternalActor>,
    /// The provider's webhook id.
    pub webhook_id: Option<String>,
    /// The provider's organization id.
    pub organization_id: Option<String>,
    /// The provider's `webhookTimestamp`, kept as evidence only.
    pub webhook_timestamp_ms: Option<u64>,
    /// The mirrored fields a webhook says it changed.
    pub changed_fields: Vec<String>,
    /// What happened: `applied`, `conflict`, `noop`, `ignored`, `admitted`,
    /// `linked`, `link`, `unlink`, `mirror` or `edited`.
    pub status: String,
    /// The fields both sides moved.
    pub conflicts: Vec<LinearFieldConflict>,
    /// The verified vault writer of a push or an edit.
    pub writer_actor: Option<String>,
    /// That writer's actor class.
    pub writer_class: Option<String>,
    /// The gate decision that admitted a push.
    pub gate_ref: Option<String>,
    /// The JSON receipt the event answered, which a replay answers again.
    pub receipt: Option<String>,
    /// The vault clock when the event was recorded.
    pub at: u64,
}

impl LinearMirrorEvent {
    /// A row of `direction` with `status` and nothing else known yet.
    pub fn blank(direction: EventDirection, status: &str, at: u64) -> Self {
        Self {
            direction: direction.token().to_owned(),
            task_ref: None,
            issue: None,
            delivery_id: None,
            operation_id: None,
            body_digest: None,
            payload_ref: None,
            external_actor: None,
            webhook_id: None,
            organization_id: None,
            webhook_timestamp_ms: None,
            changed_fields: Vec::new(),
            status: status.to_owned(),
            conflicts: Vec::new(),
            writer_actor: None,
            writer_class: None,
            gate_ref: None,
            receipt: None,
            at,
        }
    }

    /// Names `actor` of `class` as the row's verified writer.
    pub fn written_by(&mut self, actor: EntityId, class: EdgeActorClass) {
        self.writer_actor = Some(actor.to_hex());
        self.writer_class = Some(class.gate_actor_class().to_owned());
    }
}
