//! FIX 11074: a vault VM's outbox carrier keeps a copy of a member the
//! carrier never agreed on, as the member's origin retired the agreed
//! version, as the owners' inbox Ask ("remove or keep"). The host raises one
//! Ask NOTIFICATION per live owner, naming the copy, its words on it
//! (`source.detail`) and the route that takes the answer. It clears them,
//! seen and acked for each owner, once an owner answered or the copy went;
//! a host that starts clears every one whose copy no longer waits.

use super::notification::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Producer name of a diverged outbox copy's ask.
const NOTIFICATION_PRODUCER_OUTBOX_DIVERGED: &str = "outbox.diverged";

impl Vault {
    /// Raises the ask for the diverged outbox copy `copy` (its kind, member
    /// and digest, as the host names it) as one inbox Ask per live owner,
    /// and returns their rows. The source's result is `answer`, the route
    /// that takes the owner's answer, and its detail is `detail`. The event
    /// is the ask's identity: `<copy>:<owner>`. Raising the same ask again
    /// finds its rows.
    pub fn raise_outbox_diverged_ask(
        &self,
        copy: &str,
        detail: &str,
        answer: &str,
    ) -> Result<Vec<EntityId>> {
        let mut txn = self.store.env.write_txn()?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let mut raised = Vec::new();
        for owner in crate::policy_model::owners_in_txn(self, &txn)? {
            raised.push(self.record_notification_in_txn(
                &mut txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_OUTBOX_DIVERGED.to_owned(),
                        event: format!("{copy}:{}", owner.to_hex()),
                        result: Some(answer.to_owned()),
                        detail: Some(detail.to_owned()),
                        ..NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient: Some(owner),
                    created_at: now,
                    origin_conversation: None,
                },
            )?);
        }
        txn.commit()?;
        // A raw writer has no owner to send the notification signal after
        // its commit, so it sends its own (FIX 3084).
        if !raised.is_empty() {
            self.store.notify_notification_updates();
        }
        Ok(raised)
    }

    /// Clears a diverged outbox copy's ask rows, each seen and acked for the
    /// owner it was raised for.
    pub fn clear_outbox_diverged_ask(&self, asks: &[EntityId]) -> Result<()> {
        self.clear_takeover_ask(asks)
    }

    /// Clears every diverged outbox copy's ask still open whose copy is not
    /// in `waiting`, and returns how many it cleared: a host that starts
    /// finds the copies its carrier still keeps unanswered, and an ask for
    /// any other was answered or went while it was down.
    pub fn clear_settled_outbox_diverged_asks(&self, waiting: &[String]) -> Result<usize> {
        let ids = self.entities_by_type(ENTITY_TYPE_NOTIFICATION)?;
        let mut settled = Vec::new();
        {
            let txn = self.store.env.read_txn()?;
            for id in ids {
                let LiveEntityRow::Live { entity_type, body } =
                    live_entity_row_in_txn(&self.store, &txn, &id)?
                else {
                    continue;
                };
                if entity_type != ENTITY_TYPE_NOTIFICATION {
                    continue;
                }
                // Another producer's row is not this one's to read.
                let Ok(body) = decode_notification_body(&body) else {
                    continue;
                };
                if body.source.producer != NOTIFICATION_PRODUCER_OUTBOX_DIVERGED {
                    continue;
                }
                let Some(owner) = body.recipient.as_ref() else {
                    continue;
                };
                if body.acked_by.get(owner) == Some(&true) {
                    continue;
                }
                let copy = body
                    .source
                    .event
                    .strip_suffix(&format!(":{owner}"))
                    .unwrap_or(&body.source.event);
                if !waiting.iter().any(|waits| waits == copy) {
                    settled.push(id);
                }
            }
        }
        self.clear_takeover_ask(&settled)?;
        Ok(settled.len())
    }
}
