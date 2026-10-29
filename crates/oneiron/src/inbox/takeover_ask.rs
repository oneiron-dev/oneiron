//! CUA-001: a run guest's takeover ask as the owners' inbox Ask ("Needs
//! you"). An agent's handover raises one Ask NOTIFICATION per live owner,
//! naming the run, the agent's reason (`source.detail`) and the route that
//! takes the guest over. The host clears it, seen and acked for each owner,
//! once an owner takes the guest or hands it back, or the guest goes away;
//! a host that starts clears every one still open, since no guest outlives
//! it.

use super::notification::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Producer name of a run guest's takeover ask.
const NOTIFICATION_PRODUCER_TAKEOVER_ASK: &str = "guest.takeover";

impl Vault {
    /// Raises run `run_id`'s `guest` takeover ask, asked at `asked_at_ms`
    /// for `reason`, as one inbox Ask per live owner, and returns their
    /// rows. The source names the run, its result is `take`, the route that
    /// takes the guest over, and its detail is the agent's reason. The event
    /// is the ask's identity: `<guest>:<run>:<asked_at_ms>:<owner>`. Raising
    /// the same ask again finds its rows.
    pub fn raise_takeover_ask(
        &self,
        guest: &str,
        run_id: EntityId,
        reason: &str,
        asked_at_ms: u64,
        take: &str,
    ) -> Result<Vec<EntityId>> {
        let mut txn = self.store.env.write_txn()?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let run = run_id.to_hex();
        let mut raised = Vec::new();
        for owner in crate::policy_model::owners_in_txn(self, &txn)? {
            raised.push(self.record_notification_in_txn(
                &mut txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_TAKEOVER_ASK.to_owned(),
                        event: format!("{guest}:{run}:{asked_at_ms}:{}", owner.to_hex()),
                        run: Some(run.clone()),
                        result: Some(take.to_owned()),
                        detail: Some(reason.to_owned()),
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

    /// Clears a takeover ask's inbox rows: each is seen and acked for the
    /// owner it was raised for. A row already acked, or gone, stays as it is.
    pub fn clear_takeover_ask(&self, asks: &[EntityId]) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let mut cleared = false;
        for ask in asks {
            let LiveEntityRow::Live { entity_type, body } =
                live_entity_row_in_txn(&self.store, &txn, ask)?
            else {
                continue;
            };
            if entity_type != ENTITY_TYPE_NOTIFICATION {
                continue;
            }
            let mut body = decode_notification_body(&body)?;
            let Some(owner) = body.recipient.clone() else {
                continue;
            };
            if body.acked_by.get(&owner) == Some(&true) {
                continue;
            }
            body.seen_by.insert(owner.clone(), true);
            body.acked_by.insert(owner, true);
            self.put_notification_in_txn(&mut txn, ask, &body)?;
            cleared = true;
        }
        txn.commit()?;
        if cleared {
            self.store.notify_notification_updates();
        }
        Ok(())
    }

    /// Clears every takeover ask still open, each seen and acked for the
    /// owner it was raised for, and returns how many it cleared: a host
    /// that just started holds no run guest, so none of them can be
    /// answered.
    pub fn clear_open_takeover_asks(&self) -> Result<usize> {
        let ids = self.entities_by_type(ENTITY_TYPE_NOTIFICATION)?;
        let mut open = Vec::new();
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
                if body.source.producer != NOTIFICATION_PRODUCER_TAKEOVER_ASK {
                    continue;
                }
                if body
                    .recipient
                    .as_ref()
                    .is_some_and(|owner| body.acked_by.get(owner) != Some(&true))
                {
                    open.push(id);
                }
            }
        }
        self.clear_takeover_ask(&open)?;
        Ok(open.len())
    }
}
