//! CUA-001: a run guest's takeover ask as the owners' inbox Ask ("Needs
//! you"). An agent's handover raises one Ask NOTIFICATION per live owner,
//! naming the run, the agent's reason and the route that takes the guest
//! over. The host clears it, seen and acked for each owner, once an owner
//! takes the guest or hands it back, or the guest goes away.

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
    /// rows. The source names the run, and its result is `take`, the route
    /// that takes the guest over. The event is the ask's identity with the
    /// agent's reason last: `<guest>:<run>:<asked_at_ms>:<owner>:<reason>`.
    /// Raising the same ask again finds its rows.
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
                        event: format!("{guest}:{run}:{asked_at_ms}:{}:{reason}", owner.to_hex()),
                        run: Some(run.clone()),
                        result: Some(take.to_owned()),
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
        Ok(raised)
    }

    /// Clears a takeover ask's inbox rows: each is seen and acked for the
    /// owner it was raised for. A row already acked, or gone, stays as it is.
    pub fn clear_takeover_ask(&self, asks: &[EntityId]) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
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
        }
        txn.commit()?;
        Ok(())
    }
}
