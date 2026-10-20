//! An ended delivery settles (OF-415, FIX 6363, Engine ruling 10-20). An
//! invitation or reminder whose document ended (voided, expired or past its
//! deadline, declined, or sealed) or whose recipient ended (it signed or
//! declined, or its signing window closed) before its export never waits for
//! a link forever. Its queue row fails terminally under its current lease with
//! a typed reason, `document_ended` or `recipient_ended`: nothing is sent and
//! nothing is dropped. That failed row is the owner's receipt, read back on
//! `vault.esign.get` as `delivery_receipts`.
//!
//! Only a delivery that carries a signing link settles here. A void, expiry,
//! rejection or completion notice is sent because the document ended, and
//! goes out as before.

use super::delivery_capability::{DELIVERY_KIND, delivery_key, notice_of};
use super::ledger::delivery_chain_in;
use super::model::{DocumentStatus, EsignState, SigningStatus, invalid};
use super::notice_dispatch::EsignNotice;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState, FailAttempt};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// Why an invitation or reminder ended unsent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsignDeliveryEndReason {
    /// The document ended first: voided, expired or past its deadline,
    /// declined, or sealed.
    DocumentEnded,
    /// The recipient ended first: it signed or declined, or its signing
    /// window closed.
    RecipientEnded,
}

impl EsignDeliveryEndReason {
    /// The reason's code, as the settled queue row keeps it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DocumentEnded => "document_ended",
            Self::RecipientEnded => "recipient_ended",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        [Self::DocumentEnded, Self::RecipientEnded]
            .into_iter()
            .find(|reason| reason.code() == code)
    }
}

/// One invitation or reminder that ended unsent: the owner's receipt. It
/// says the delivery's last lease was never exported; an earlier lease that
/// lapsed with no ack may still have reached its sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignDeliveryReceipt {
    /// The queued delivery, 32 lower-hex.
    pub attempt_ref: String,
    /// The lease it settled on.
    pub attempt_count: u32,
    /// The recipient it was for, by id.
    pub recipient: String,
    /// `invite` or `reminder`.
    pub transition: String,
    pub reason: EsignDeliveryEndReason,
    /// When it settled, Unix seconds.
    pub at: u64,
}

impl Vault {
    /// Settles the invitation or reminder `attempt` delivers under its
    /// current lease (`lease_owner`, `attempt_count`) when its document or
    /// recipient ended, re-read under this writer: the row fails with the
    /// typed reason, which comes back. `None` while the delivery may still
    /// go, or when the row no longer reads as that lease of a bound
    /// invitation or reminder. It mints nothing and writes nothing outside
    /// the vault. A read decides first, so a delivery that may still go
    /// opens no writer. A document whose trail does not read has not ended
    /// here: its mint holds that delivery alone (FIX 6423).
    /// # Errors
    /// A storage failure.
    pub fn settle_esign_delivery_if_ended(
        &self,
        attempt: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
    ) -> Result<Option<EsignDeliveryEndReason>> {
        {
            let txn = self.store.env.read_txn()?;
            let Some((_, notice)) =
                bound_delivery_in(self, &txn, attempt, lease_owner, attempt_count)?
            else {
                return Ok(None);
            };
            if ended_in(self, &txn, &notice, self.now_recorded_at())?.is_none() {
                return Ok(None);
            }
        }
        self.with_write_txn_grouped(|txn| {
            let Some((row, notice)) =
                bound_delivery_in(self, txn, attempt, lease_owner, attempt_count)?
            else {
                return Ok(None);
            };
            settle_ended_in_txn(self, txn, &row, &notice, self.now_recorded_at())
        })
    }
}

/// Settles `row`, a current lease of `notice`'s invitation or reminder the
/// caller re-read under this writer, when its document or recipient ended at
/// `now`: the row fails with the reason's code, and the reason comes back.
pub(super) fn settle_ended_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &AttemptRecord,
    notice: &EsignNotice,
    now: u64,
) -> Result<Option<EsignDeliveryEndReason>> {
    let Some(reason) = ended_in(vault, txn, notice, now)? else {
        return Ok(None);
    };
    let lease_owner = row
        .lease_owner
        .clone()
        .ok_or_else(|| invalid("delivery lease owner"))?;
    AttemptQueue::new(vault).fail_in_txn(
        txn,
        FailAttempt {
            id: row.id,
            lease_owner,
            attempt_count: row.attempt_count,
            reason: reason.code().to_owned(),
            now,
        },
    )?;
    Ok(Some(reason))
}

/// The invitations and reminders of `document` that ended unsent, oldest
/// first: every failed delivery row that carries an end reason.
pub(super) fn delivery_receipts_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
) -> Result<Vec<EsignDeliveryReceipt>> {
    let document = document.to_hex();
    let mut receipts = Vec::new();
    for entry in vault.store.attempt_records.iter(txn)? {
        let (key, raw) = entry?;
        let row = crate::attempt_queue::decode_record(&raw, AttemptId::from_bytes(&key)?)?;
        if row.kind != DELIVERY_KIND || row.state != AttemptState::Failed {
            continue;
        }
        let Some(reason) = row
            .last_error
            .as_deref()
            .and_then(EsignDeliveryEndReason::from_code)
        else {
            continue;
        };
        let Ok(notice) = notice_of(&row) else {
            continue;
        };
        if notice.document == document {
            receipts.push(EsignDeliveryReceipt {
                attempt_ref: crate::entity_id::bytes_to_hex_lower(row.id.as_bytes()),
                attempt_count: row.attempt_count,
                recipient: notice.recipient,
                transition: notice.transition,
                reason,
                at: row.updated_at,
            });
        }
    }
    receipts.sort_by(|a, b| {
        a.at.cmp(&b.at)
            .then_with(|| a.attempt_ref.cmp(&b.attempt_ref))
    });
    Ok(receipts)
}

/// The invitation or reminder `attempt` delivers under the lease
/// (`lease_owner`, `attempt_count`), with its notice, when its dedupe key
/// binds that notice; `None` for any other row, lease or notice.
fn bound_delivery_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    lease_owner: &str,
    attempt_count: u32,
) -> Result<Option<(AttemptRecord, EsignNotice)>> {
    let Some(raw) = vault.store.attempt_records.get(txn, attempt.as_bytes())? else {
        return Ok(None);
    };
    let row = crate::attempt_queue::decode_record(&raw, attempt)?;
    if row.kind != DELIVERY_KIND
        || row.state != AttemptState::Leased
        || row.lease_owner.as_deref() != Some(lease_owner)
        || row.attempt_count != attempt_count
    {
        return Ok(None);
    }
    let Ok(notice) = notice_of(&row) else {
        return Ok(None);
    };
    let bound = notice.carries_signing_link()
        && notice.dispatch_ref.as_deref().is_some_and(|dispatch_ref| {
            row.dedupe_key.as_deref() == Some(delivery_key(&notice, dispatch_ref).as_str())
        });
    Ok(bound.then_some((row, notice)))
}

/// Why `notice`'s delivery ended at `now`, or `None` while it may still go
/// or its document's trail does not read.
fn ended_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    notice: &EsignNotice,
    now: u64,
) -> Result<Option<EsignDeliveryEndReason>> {
    let Ok(document) = EntityId::from_hex(&notice.document) else {
        return Ok(None);
    };
    let Some((state, held)) = delivery_chain_in(vault, txn, document)? else {
        return Ok(None);
    };
    Ok(ended_reason(&state, held, notice, now))
}

/// Why `notice`'s delivery ended, the document's end before its recipient's.
/// `state` folds the whole chain, so an event awaiting its owner's answer
/// (`held`) cannot hide a later void, decline or expiry; a recipient's own
/// answer is read only off a chain with none held, since a held sign act may
/// yet be refused. A draft, or a recipient that changed since the send, has
/// not ended: it holds as before.
fn ended_reason(
    state: &EsignState,
    held: bool,
    notice: &EsignNotice,
    now: u64,
) -> Option<EsignDeliveryEndReason> {
    let document_ended = match state.status {
        DocumentStatus::Draft => false,
        DocumentStatus::Pending => state.rejection.is_some() || now >= state.document.expires_at,
        DocumentStatus::Completed
        | DocumentStatus::Rejected
        | DocumentStatus::Voided
        | DocumentStatus::Expired => true,
    };
    if document_ended {
        return Some(EsignDeliveryEndReason::DocumentEnded);
    }
    if held || state.status != DocumentStatus::Pending {
        return None;
    }
    let named = state
        .document
        .recipients
        .iter()
        .any(|recipient| recipient.id == notice.recipient && recipient.email == notice.email);
    let progress = state.recipients.get(&notice.recipient).filter(|_| named)?;
    let answered = matches!(
        progress.signing,
        SigningStatus::Completed | SigningStatus::Rejected
    );
    (answered || now >= progress.expires_at).then_some(EsignDeliveryEndReason::RecipientEnded)
}
