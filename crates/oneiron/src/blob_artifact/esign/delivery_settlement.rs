//! An ended delivery settles (OF-415, FIX 6363, Engine ruling 10-20). An
//! invitation or reminder whose document ended (voided, expired or past its
//! deadline, declined, or sealed) or whose recipient ended (it signed or
//! declined, or its signing window closed) before its export never waits for
//! a link forever. Its queue row fails terminally under its current lease with
//! a typed reason, `document_ended` or `recipient_ended`: nothing is sent and
//! nothing is dropped. That failed row is the owner's receipt, read back on
//! `vault.esign.get` as `delivery_receipts`, its `state` `ended`.
//!
//! Only a delivery that carries a signing link settles here. A void, expiry,
//! rejection or completion notice is sent because the document ended, and
//! goes out as before.
//!
//! The same `delivery_receipts` list each invitation or reminder still
//! queued and unexported that waits on its own (FIX 6423, 6455, 6482), its
//! `state` `waits` with its typed reason: an event of its document awaits
//! the owner's answer (`document_awaits_owner`), its document's trail does
//! not read (`document_unreadable`), the send's dispatch marker or admitted
//! call does not read (`send_unreadable`), or its recipient's signing links
//! do not read (`links_unreadable`). The view reads each one now through the
//! mint's own classifier, so it lists exactly what the next export would
//! wait on, and lists it even when the document's own trail does not read
//! (FIX 6481). A lease whose link was minted is out, and is not listed. A
//! queued notice that does not read (`notice_unreadable`) names no document
//! to list it under; the exporter logs that wait alone.

use super::delivery_capability::{
    DELIVERY_KIND, DeliveryRead, EsignDeliveryWait, delivery_key, delivery_read_in,
    lease_digest_in, notice_of,
};
use super::ledger::delivery_chain_in;
use super::model::{DocumentStatus, EsignState, SigningStatus, invalid};
use super::notice_dispatch::EsignNotice;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState, FailAttempt};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// Why an invitation or reminder ended unsent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

/// One invitation or reminder that ended unsent, or that waits unexported:
/// the owner's receipt. An ended one says the delivery's last lease was never
/// exported; an earlier lease that lapsed with no ack may still have reached
/// its sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EsignDeliveryReceipt {
    /// The queued delivery, 32 lower-hex.
    pub attempt_ref: String,
    /// The lease it settled on, or its latest one.
    pub attempt_count: u32,
    /// The recipient it is for, by id.
    pub recipient: String,
    /// `invite` or `reminder`.
    pub transition: String,
    /// `state` and its typed `reason`.
    #[serde(flatten)]
    pub state: EsignDeliveryReceiptState,
    /// When it settled, or when its queue row last moved while it waits,
    /// Unix seconds.
    pub at: u64,
}

/// Where one receipt's delivery stands (FIX 6455).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum EsignDeliveryReceiptState {
    /// It settled unsent, for this reason (FIX 6363).
    Ended(EsignDeliveryEndReason),
    /// It is still queued and unexported, and waits on its own for this
    /// reason (FIX 6423, 6455).
    Waits(EsignDeliveryWait),
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
    /// here: its mint waits that delivery alone (FIX 6423).
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
            let now = self.now_recorded_at();
            let Some(reason) = ended_in(self, txn, &notice, now)? else {
                return Ok(None);
            };
            fail_ended_in_txn(self, txn, &row, reason, now)?;
            Ok(Some(reason))
        })
    }
}

/// Settles `row`, a current lease of an invitation or reminder the caller
/// re-read under this writer and found ended at `now`: the row fails with
/// `reason`'s code.
pub(super) fn fail_ended_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &AttemptRecord,
    reason: EsignDeliveryEndReason,
    now: u64,
) -> Result<()> {
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
    Ok(())
}

/// The invitations and reminders of `document` that ended unsent or wait
/// unexported, oldest first: every failed delivery row that carries an end
/// reason, and every one still queued whose read waits now (FIX 6455). Only
/// delivery rows are read, through the attempt kind index (FIX 6422).
pub(super) fn delivery_receipts_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
) -> Result<Vec<EsignDeliveryReceipt>> {
    let document = document.to_hex();
    let now = vault.now_recorded_at();
    let mut receipts = Vec::new();
    for row in AttemptQueue::new(vault).kind_rows_in_txn(txn, DELIVERY_KIND)? {
        let Ok(notice) = notice_of(&row) else {
            continue;
        };
        if notice.document != document {
            continue;
        }
        let Some(state) = receipt_state_in(vault, txn, &row, &notice, now)? else {
            continue;
        };
        receipts.push(EsignDeliveryReceipt {
            attempt_ref: crate::entity_id::bytes_to_hex_lower(row.id.as_bytes()),
            attempt_count: row.attempt_count,
            recipient: notice.recipient,
            transition: notice.transition,
            state,
            at: row.updated_at,
        });
    }
    receipts.sort_by(|a, b| {
        a.at.cmp(&b.at)
            .then_with(|| a.attempt_ref.cmp(&b.attempt_ref))
    });
    Ok(receipts)
}

/// Where `row`, a delivery of `notice`, stands for the owner's receipts:
/// ended with the reason its failed row keeps, waiting with the reason the
/// mint's own read gives now, or `None` while it may still go or once it is
/// out (a lease whose link was minted) or done. A lease whose recipient's
/// links do not read is not known to be out, so the mint's read lists it.
fn receipt_state_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
    notice: &EsignNotice,
    now: u64,
) -> Result<Option<EsignDeliveryReceiptState>> {
    if row.state == AttemptState::Failed {
        return Ok(row
            .last_error
            .as_deref()
            .and_then(EsignDeliveryEndReason::from_code)
            .map(EsignDeliveryReceiptState::Ended));
    }
    if row.state.is_terminal()
        || !notice.carries_signing_link()
        || (row.state == AttemptState::Leased
            && matches!(lease_digest_in(vault, txn, row)?, Ok(Some(_))))
    {
        return Ok(None);
    }
    let DeliveryRead::Waits(wait) = delivery_read_in(vault, txn, row, now)? else {
        return Ok(None);
    };
    Ok(Some(EsignDeliveryReceiptState::Waits(wait)))
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
pub(super) fn ended_reason(
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
