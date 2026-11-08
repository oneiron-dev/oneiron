//! The owner's ask on a send that may have gone out (FIX 4747; canon
//! ARCH-0023b, pending outbound send: "Still unknown: ask the owner before
//! any retry. Never a blind retry."). Entry: `Vault::answer_uncertain_send`.
//!
//! When no provider lookup can tell whether a connector-send TASK's send
//! went, its TASK holds and the engine raises one inbox Ask per live owner,
//! naming the channel, the target (never the body) and when the send was
//! approved. Its two taps answer `vault.outbound.uncertain_send.answer`:
//! resend, and the TASK's executor sends it once under the same engine send
//! id; or not, and the TASK settles with the owner's word. Only an owner
//! answers, and the first answer settles it.

use super::connector_task::{
    ConnectorSendTask, UncertainSendAnswerOutcome, UncertainSendHold, answer_uncertain_send_in_txn,
    hold_uncertain_send_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Producer name of an uncertain send's ask.
pub(crate) const UNCERTAIN_SEND_NOTIFICATION_PRODUCER: &str = "outbound.uncertain_send";

/// The verb the ask's taps call.
pub(crate) const UNCERTAIN_SEND_ANSWER_VERB: &str = "vault.outbound.uncertain_send.answer";

/// The ask's identity for `owner`: the TASK, when it was asked, the owner.
fn uncertain_send_ask_source(
    task_ref: EntityId,
    hold: UncertainSendHold,
    owner: EntityId,
) -> NotificationSource {
    NotificationSource {
        producer: UNCERTAIN_SEND_NOTIFICATION_PRODUCER.to_owned(),
        event: format!("{}:{}:{}", task_ref.to_hex(), hold.asked_at, owner.to_hex()),
        result: Some(task_ref.to_hex()),
        ..NotificationSource::default()
    }
}

/// The ask's words: the channel, the target and when the send was approved.
/// Never the send's body. Engine call (CALLS, FIX 4747): the approval instant
/// is the TASK's own, when its schedule chokepoint admitted it.
fn uncertain_send_ask_detail(task: &ConnectorSendTask) -> String {
    let approved_at = i64::try_from(task.occurred_at)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .map_or_else(|| task.occurred_at.to_string(), |at| at.to_rfc3339());
    format!(
        "A {} {} to {}, approved at {approved_at}, may have gone out, and the provider cannot tell. Send it again, or leave it?",
        task.intent.channel, task.intent.verb, task.intent.target
    )
}

/// Holds `task` for the owner's word on a send that may have gone out (FIX
/// 4747) and, the first time, raises its ask: one inbox Ask per live owner,
/// in the same write.
pub(super) fn hold_uncertain_send(vault: &Vault, task: &ConnectorSendTask, now: u64) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        let Some((hold, newly_held)) = hold_uncertain_send_in_txn(vault, wtxn, task.task_ref, now)?
        else {
            return Ok(());
        };
        if !newly_held {
            return Ok(());
        }
        let created_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
        let detail = uncertain_send_ask_detail(task);
        for owner in crate::policy_model::owners_in_txn(vault, &*wtxn)? {
            vault.record_notification_in_txn(
                wtxn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        detail: Some(detail.clone()),
                        ..uncertain_send_ask_source(task.task_ref, hold, owner)
                    },
                    subject_refs: vec![task.task_ref],
                    recipient: Some(owner),
                    created_at,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    })
}

/// Marks the ask `hold` raised seen and acked for each live owner, in the
/// caller's write: an answered ask offers no tap any more.
fn clear_uncertain_send_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    hold: UncertainSendHold,
) -> Result<()> {
    for owner in crate::policy_model::owners_in_txn(vault, &*wtxn)? {
        let ask = crate::inbox::notification_id(&uncertain_send_ask_source(task_ref, hold, owner))?;
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*wtxn, &ask)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = crate::inbox::decode_notification_body(&body)?;
        let Some(recipient) = body.recipient.clone() else {
            continue;
        };
        if body.acked_by.get(&recipient) == Some(&true) {
            continue;
        }
        body.seen_by.insert(recipient.clone(), true);
        body.acked_by.insert(recipient, true);
        vault.put_notification_in_txn(wtxn, &ask, &body)?;
    }
    Ok(())
}

impl Vault {
    /// The owner's answer to the ask a connector-send TASK's uncertain send
    /// raised (FIX 4747): `resend` releases it for one send under its engine
    /// send id, which the TASK's executor makes; no resend settles the TASK
    /// with his word, sent no more. The proof is the vault owner's,
    /// rechecked in the writer; the first answer settles the ask and clears
    /// its rows, and a later one finds it settled.
    ///
    /// # Errors
    ///
    /// A proof that is not a live owner's; a TASK that does not read.
    pub fn answer_uncertain_send(
        &self,
        owner: &AuthenticatedOwner,
        task_ref: EntityId,
        resend: bool,
    ) -> Result<UncertainSendAnswerOutcome> {
        self.with_write_txn_grouped(|wtxn| {
            owner.revalidate_in_txn(self, &*wtxn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
            let (outcome, hold) = answer_uncertain_send_in_txn(self, wtxn, task_ref, resend, now)?;
            if let Some(hold) = hold {
                clear_uncertain_send_ask_in_txn(self, wtxn, task_ref, hold)?;
            }
            Ok(outcome)
        })
    }

    /// Whether `task_ref`'s send waits for the owner's answer now, read in
    /// `txn`: the inbox offers the ask's taps only then.
    pub(crate) fn uncertain_send_awaits_owner_in(
        &self,
        txn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Result<bool> {
        Ok(self
            .connector_send_task_in(txn, &task_ref)?
            .is_some_and(|task| {
                task.outcome.is_none()
                    && task
                        .uncertain_send
                        .is_some_and(|hold| !hold.resend_released)
            }))
    }
}
