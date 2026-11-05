//! Explicit owner retry after the outbound ledger proves non-delivery.

use serde::{Deserialize, Serialize};

use super::super::{store, validate_ref};
use super::{
    DELIVERIES, ENDPOINTS, ReportDeliveryKey, ReportDeliveryRecord, ReportFrozenSend, publisher_of,
};
use crate::consent::AuthenticatedOwner;
use crate::outbound::{OutboundDispatchError, outbound_dispatch_attempt_id};
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentResolution, UnconfirmedDelivery, read_intent_for_attempt_in_txn,
};
use crate::{EntityId, Error, Result, Vault};

/// A new logical send for exactly the failed send the owner read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryRetryRequest {
    /// The ISSUE, 32 hex.
    pub issue_ref: String,
    /// The current frozen send's exact reference from delivery status.
    pub expected_send_ref: String,
}

impl Vault {
    /// Prepares a fresh logical send of the same content-free signature to
    /// the publisher's current binding. The ordinary delivery run sends it.
    /// Repeating the same request returns that successor without minting
    /// another. The old intent, receipt and destination are unchanged.
    ///
    /// # Errors
    ///
    /// A stale owner proof or send reference, an unbound publisher, a send
    /// not proved definitively undelivered, or storage errors.
    pub fn retry_report_signature_send(
        &self,
        owner: &AuthenticatedOwner,
        input: &ReportDeliveryRetryRequest,
    ) -> Result<ReportDeliveryRecord> {
        let id = EntityId::from_hex(&input.issue_ref)?;
        validate_ref(&input.expected_send_ref)?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let issue = store::read(self, txn, &id)?.ok_or(Error::EntityNotFound)?;
            let publisher = publisher_of(&issue).ok_or_else(|| {
                Error::InvalidConfig("report issue is not routed to a publisher".into())
            })?;
            let key = ReportDeliveryKey::signature(&issue.issue_ref, publisher);
            let row = key.row()?;
            let mut record = DELIVERIES.get(&self.store, txn, &row)?.ok_or_else(|| {
                Error::InvalidConfig("report signature has no send to retry".into())
            })?;
            let send = record.send.as_ref().ok_or_else(|| {
                Error::InvalidConfig("report signature has no send to retry".into())
            })?;
            let next_ref = retry_send_ref(&input.expected_send_ref);
            if send.send_ref != input.expected_send_ref {
                if send.send_ref == next_ref {
                    return Ok(record);
                }
                return Err(Error::InvalidConfig("report signature send changed".into()));
            }
            if record.signature.is_none() {
                return Err(Error::CorruptedIndex(
                    "report signature send has no signature",
                ));
            }
            let attempt =
                outbound_dispatch_attempt_id(&send.send_ref).map_err(|error| match error {
                    OutboundDispatchError::Engine(error) => error,
                    _ => Error::InvariantViolation("outbound dispatch attempt id"),
                })?;
            let intent = read_intent_for_attempt_in_txn(self, txn, attempt, 0)
                .map_err(ledger_error)?
                .ok_or_else(|| {
                    Error::InvalidConfig("report signature send has no outbound intent".into())
                })?;
            if !matches!(
                IntentResolution::from_record(&intent).map_err(ledger_error)?,
                IntentResolution::Stopped {
                    delivery: UnconfirmedDelivery::DefiniteNonDelivery,
                    ..
                }
            ) {
                return Err(Error::InvalidConfig(
                    "report signature send is not proved undelivered".into(),
                ));
            }
            let destination = ENDPOINTS
                .get(&self.store, txn, &key.publisher_ref)?
                .ok_or_else(|| Error::InvalidConfig("report publisher is unbound".into()))?;
            record.send = Some(ReportFrozenSend {
                destination,
                send_ref: next_ref,
            });
            record.hold = None;
            record.receipt = None;
            record.outcome = None;
            record.last_error = None;
            record.updated_at = self.now_recorded_at();
            DELIVERIES.put(&self.store, txn, &row, &record)?;
            Ok(record)
        })
    }
}

fn retry_send_ref(previous: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.report.delivery.retry.v1\0");
    hasher.update(previous.as_bytes());
    format!("report-signature:{}", hasher.finalize().to_hex())
}

fn ledger_error(error: IntentLedgerError) -> Error {
    match error {
        IntentLedgerError::Engine(error) => error,
        _ => Error::CorruptedIndex("outbound intent ledger row"),
    }
}

/// Prevents an old delivery pass from overwriting an explicit owner retry.
pub(super) fn send_is_current_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &ReportDeliveryKey,
    expected: &Option<ReportFrozenSend>,
) -> Result<bool> {
    let current = DELIVERIES.get(&vault.store, txn, &key.row()?)?;
    Ok(current.and_then(|record| record.send).as_ref() == expected.as_ref())
}
