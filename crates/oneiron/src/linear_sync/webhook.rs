//! The engine half of the signed Linear webhook (OF-427 C1, C3–C5).
//!
//! The host verifies the delivery, archives its body and normalizes it; this
//! applies it. An `Issue` update on an issue linked to a TASK goes through
//! the mirror's ordinary inbound merge, [`LinearSyncAdapter::apply_issue_change`],
//! with the same five fields, conflicts and permanent event digests a
//! scheduled pull has. Anything else, and an update for an unlinked issue,
//! is acknowledged as `ignored`. A webhook never creates, deletes or relinks
//! a TASK and never adds an edge.
//!
//! Every delivery is recorded once under its `Linear-Delivery` id, after the
//! engine's two guarded writes (C5): a crash between them is healed by the
//! link's permanent event digest, so the redelivery applies as `noop` and
//! then records its row. The same id with the same body answers the stored
//! receipt as a replay and writes nothing; the same id with another body is
//! refused (C4). The provider's actor is evidence on the row, never a vault
//! actor, writer or owner (C3).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;

use super::mirror_event::{
    EventDirection, LinearMirrorEvent, LinearMirrorRecord, delivery_key, event_in, put_event_in,
};
use super::model::{
    LinearChangePage, LinearChangeSource, LinearEgress, LinearFieldConflict, LinearIssueChange,
    LinearIssueRef, LinearMirrorStatus, LinearSyncError, LinearSyncResult, LinearTaskStore,
    MirroredTaskFields,
};
use super::{LinearSyncAdapter, VaultLinearTaskStore};

/// The provider's actor of one webhook: evidence, never a vault actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearExternalActor {
    /// The provider's actor id.
    pub id: String,
    /// The provider's actor type (`user`, `integration`, ...).
    pub kind: String,
    /// The provider's display name, when it sent one.
    pub name: Option<String>,
}

/// What one webhook delivery carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinearWebhookKind {
    /// An `Issue` update, normalized as a scheduled pull normalizes one.
    Issue(LinearIssueChange),
    /// Any other type or action, acknowledged and recorded.
    Ignored {
        /// The provider's `type`.
        type_name: String,
        /// The provider's `action`.
        action: String,
    },
}

/// One verified Linear webhook delivery, normalized by the host adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearWebhookEvent {
    /// The `Linear-Delivery` header: the delivery's identity.
    pub delivery_id: String,
    /// What it carries.
    pub kind: LinearWebhookKind,
    /// The provider's actor.
    pub actor: Option<LinearExternalActor>,
    /// The provider's webhook id.
    pub webhook_id: Option<String>,
    /// The provider's organization id.
    pub organization_id: Option<String>,
    /// The provider's `webhookTimestamp`, evidence only: the permanent
    /// delivery dedupe answers replays, so no skew window reads it.
    pub webhook_timestamp_ms: Option<u64>,
    /// The mirrored fields `updatedFrom` names.
    pub changed_fields: Vec<String>,
    /// Digest of the raw body.
    pub body_digest: [u8; 32],
}

/// What one delivery did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearWebhookStatus {
    /// Issue-owned fields applied to the linked TASK.
    Applied,
    /// A field both sides moved was left untouched and pinned.
    Conflict,
    /// Nothing to apply: unchanged, an echo or an already-seen event.
    Noop,
    /// Not an update of a linked issue.
    Ignored,
}

impl LinearWebhookStatus {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Conflict => "conflict",
            Self::Noop => "noop",
            Self::Ignored => "ignored",
        }
    }
}

/// The receipt one delivery answers, and a replay of it answers again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinearWebhookReceipt {
    /// The delivery.
    pub delivery_id: String,
    /// What it did.
    pub status: LinearWebhookStatus,
    /// The linked TASK it changed or found unchanged.
    pub task_ref: Option<String>,
    /// The issue it named.
    pub issue: Option<LinearIssueRef>,
    /// The fields both sides moved.
    pub conflicts: Vec<LinearFieldConflict>,
    /// The mirror operation it ran, for a linked issue.
    pub mirror: Option<LinearMirrorRecord>,
    /// The event row it is recorded under, in hex.
    pub event_ref: String,
    /// Whether this answers an already-recorded delivery.
    pub replayed: bool,
    /// The vault clock when the delivery was recorded.
    pub recorded_at: u64,
}

/// A webhook apply reads no tracker page.
struct NoPages;

impl LinearChangeSource for NoPages {
    fn changes_since(&mut self, _cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        Err(LinearSyncError::Transport(
            "a webhook apply reads no tracker pages".to_owned(),
        ))
    }
}

/// A webhook apply sends nothing.
struct NoEgress;

impl LinearEgress for NoEgress {
    fn create_issue(
        &mut self,
        _operation_id: [u8; 32],
        _task_ref: EntityId,
        _fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        Err(LinearSyncError::Transport(
            "a webhook apply sends nothing".to_owned(),
        ))
    }
}

const fn webhook_status(status: LinearMirrorStatus) -> LinearWebhookStatus {
    match status {
        LinearMirrorStatus::Linked | LinearMirrorStatus::Applied => LinearWebhookStatus::Applied,
        LinearMirrorStatus::Conflict => LinearWebhookStatus::Conflict,
        LinearMirrorStatus::Noop => LinearWebhookStatus::Noop,
    }
}

/// The stored receipt of `delivery_id`, marked a replay, when the same body
/// was recorded under it; [`LinearSyncError::DeliveryReused`] for another.
fn replay_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    delivery_id: &str,
    body_digest: &[u8; 32],
) -> LinearSyncResult<Option<LinearWebhookReceipt>> {
    let Some(row) = event_in(vault, txn, &delivery_key(delivery_id))? else {
        return Ok(None);
    };
    if row.body_digest.as_deref() != Some(bytes_to_hex_lower(body_digest).as_str()) {
        return Err(LinearSyncError::DeliveryReused);
    }
    let mut receipt: LinearWebhookReceipt = row
        .receipt
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .ok_or(Error::CorruptedIndex("linear webhook receipt"))?;
    receipt.replayed = true;
    Ok(Some(receipt))
}

impl Vault {
    /// The stored receipt of an already-recorded delivery, marked a replay,
    /// before its host archives the body again (OF-427 C4).
    ///
    /// # Errors
    /// [`LinearSyncError::DeliveryReused`] when the delivery id was recorded
    /// with another body; otherwise a store error.
    pub fn linear_webhook_replay(
        &self,
        delivery_id: &str,
        body_digest: &[u8; 32],
    ) -> LinearSyncResult<Option<LinearWebhookReceipt>> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        replay_in(self, &txn, delivery_id, body_digest)
    }

    /// Applies one verified, normalized Linear webhook delivery (OF-427).
    /// `payload_ref` is the archived provider body the row keeps; `now` is
    /// the mirror clock its inbound merge stamps, as a scheduled pass's.
    ///
    /// # Errors
    /// [`LinearSyncError::DeliveryReused`] for a delivery id recorded with
    /// another body; the inbound merge's error, such as
    /// [`LinearSyncError::Conflict`] when the TASK moved under it, with
    /// nothing recorded; otherwise a store error.
    pub fn apply_linear_webhook(
        &self,
        event: &LinearWebhookEvent,
        payload_ref: Option<&str>,
        now: u64,
    ) -> LinearSyncResult<LinearWebhookReceipt> {
        if event.delivery_id.trim().is_empty() {
            return Err(Error::InvariantViolation("linear webhook delivery id is blank").into());
        }
        if let Some(receipt) = self.linear_webhook_replay(&event.delivery_id, &event.body_digest)? {
            return Ok(receipt);
        }
        let (issue, applied) = match &event.kind {
            LinearWebhookKind::Ignored { .. } => (None, None),
            LinearWebhookKind::Issue(change) => {
                let store = VaultLinearTaskStore::new(self);
                let applied = if store.link_for_issue(&change.issue)?.is_some() {
                    Some(
                        LinearSyncAdapter::new(store, NoPages, NoEgress)
                            .apply_issue_change(change.clone(), now)?,
                    )
                } else {
                    None
                };
                (Some(change.issue.clone()), applied)
            }
        };
        let key = delivery_key(&event.delivery_id);
        let recorded_at = self.now_recorded_at();
        let receipt = LinearWebhookReceipt {
            delivery_id: event.delivery_id.clone(),
            status: applied
                .as_ref()
                .map_or(LinearWebhookStatus::Ignored, |mirror| {
                    webhook_status(mirror.status)
                }),
            task_ref: applied.as_ref().map(|mirror| mirror.task_ref.to_hex()),
            issue,
            conflicts: applied
                .as_ref()
                .map_or_else(Vec::new, |mirror| mirror.conflicts.clone()),
            mirror: applied.as_ref().map(LinearMirrorRecord::from),
            event_ref: bytes_to_hex_lower(&key),
            replayed: false,
            recorded_at,
        };
        let mut row = LinearMirrorEvent::blank(
            EventDirection::IssueToTask,
            receipt.status.as_str(),
            recorded_at,
        );
        row.task_ref.clone_from(&receipt.task_ref);
        row.issue.clone_from(&receipt.issue);
        row.delivery_id = Some(event.delivery_id.clone());
        row.operation_id = receipt
            .mirror
            .as_ref()
            .map(|mirror| mirror.operation_id.clone());
        row.body_digest = Some(bytes_to_hex_lower(&event.body_digest));
        row.payload_ref = payload_ref.map(str::to_owned);
        row.external_actor.clone_from(&event.actor);
        row.webhook_id.clone_from(&event.webhook_id);
        row.organization_id.clone_from(&event.organization_id);
        row.webhook_timestamp_ms = event.webhook_timestamp_ms;
        row.changed_fields.clone_from(&event.changed_fields);
        row.conflicts.clone_from(&receipt.conflicts);
        row.receipt = Some(
            serde_json::to_string(&receipt)
                .map_err(|_| Error::InvariantViolation("linear webhook receipt encoding"))?,
        );
        self.try_with_write_txn_grouped::<_, _, LinearSyncError>(move |txn| {
            // A concurrent handler of the same delivery may have recorded it
            // meanwhile: its row answers, and this one writes nothing.
            if let Some(stored) = replay_in(self, txn, &event.delivery_id, &event.body_digest)? {
                return Ok(stored);
            }
            put_event_in(self, txn, &key, &row)?;
            Ok(receipt)
        })
    }
}
