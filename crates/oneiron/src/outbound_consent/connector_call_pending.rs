//! Expiry of held and pending-delivery connector calls (ONE-2510).
//!
//! A call nobody settles expires [`CONNECTOR_CALL_PENDING_TTL_MS`] after it
//! was first held; a retry never moves that deadline. Expiry settles the
//! call's row, so the settler answers its wait and acknowledges it like any
//! other terminal outcome. A call the ledger never admitted, or whose send
//! definitely never reached the connector, is refused as
//! [`CONNECTOR_CALL_EXPIRED`]. An admitted send whose delivery is unknown
//! keeps that uncertainty: the ledger stops it, and the call ends as a
//! pending delivery the ledger will not send again, never as a refusal. A
//! delivered call stays delivered.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentLedgerError, IntentLedgerRecord, IntentResolution,
    UnconfirmedDelivery, abandon_record, read_intent_for_attempt_in_txn, record_possible_delivery,
};

use super::connector_call::{
    ConnectorCallOutcome, PENDING_CALLS, PendingConnectorCall, SettledConnectorCall,
    intent_escalation_code,
};

/// How long a held or pending-delivery connector call waits for its hold to
/// clear or its send to settle, from when it was first held: 7 days. One
/// constant, so a later ruling changes one line.
pub(super) const CONNECTOR_CALL_PENDING_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// The stable reason an expired call carries.
pub(super) const CONNECTOR_CALL_EXPIRED: &str = "connector_call_expired";

/// The moment a call first held at `held_at_ms` expires.
const fn connector_call_deadline(held_at_ms: u64) -> u64 {
    held_at_ms.saturating_add(CONNECTOR_CALL_PENDING_TTL_MS)
}

impl Vault {
    /// Settles every held or pending-delivery connector call whose deadline
    /// has passed at `now_ms`, and returns how many it settled. Settled rows
    /// are left for the settler's acknowledgement. One call that fails to
    /// expire is logged and left for the next pass.
    pub fn expire_connector_calls(&self, now_ms: u64) -> Result<usize, IntentLedgerError> {
        let rows = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.scan(&self.store, &txn)?
        };
        let mut expired = 0;
        for (call_ref, pending) in rows {
            if pending.settled.is_some() {
                continue;
            }
            match self.expire_connector_call_if_due(&call_ref, &pending, now_ms) {
                Ok(Some(_)) => expired += 1,
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        call_ref = %call_ref.to_hex(),
                        %error,
                        "connector call expiry failed"
                    );
                }
            }
        }
        Ok(expired)
    }

    /// The outcome `pending` (the unsettled row `call_ref` names) settles
    /// with once its deadline has passed at `now_ms`; `None` while it may
    /// still be resumed.
    pub(super) fn expire_connector_call_if_due(
        &self,
        call_ref: &EntityId,
        pending: &PendingConnectorCall,
        now_ms: u64,
    ) -> Result<Option<ConnectorCallOutcome>, IntentLedgerError> {
        if now_ms < connector_call_deadline(pending.held_at_ms) {
            return Ok(None);
        }
        let record = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            read_intent_for_attempt_in_txn(self, &txn, pending.attempt_id, pending.call_seq)?
        };
        let settled = match record {
            None => SettledConnectorCall::Refused {
                decision_ref: None,
                reasons: vec![CONNECTOR_CALL_EXPIRED.to_owned()],
            },
            Some(record) => self.expire_admitted_intent(record, now_ms)?,
        };
        // A resume that settled the row first keeps its own outcome.
        let settled = self.with_write_txn(|txn| {
            let Some(mut row) = PENDING_CALLS.get(&self.store, txn, call_ref)? else {
                return Ok(settled);
            };
            if let Some(known) = row.settled {
                return Ok(known);
            }
            row.settled = Some(settled.clone());
            PENDING_CALLS.put(&self.store, txn, call_ref, &row)?;
            Ok(settled)
        })?;
        Ok(Some(settled.outcome()))
    }

    /// Stops an expired call's admitted ledger row, if it is still pending,
    /// and reads what is known about its delivery. Possible delivery is
    /// recorded before the stop, as a replay of an outcome-free row does,
    /// so the stop never reads as a definite non-delivery.
    fn expire_admitted_intent(
        &self,
        mut record: IntentLedgerRecord,
        now_ms: u64,
    ) -> Result<SettledConnectorCall, IntentLedgerError> {
        let resolution = IntentResolution::from_record(&record)?;
        if let IntentResolution::Pending { delivery, .. } = resolution {
            if delivery == UnconfirmedDelivery::Unresolved
                && record.recorded_outcome.is_none()
                && !record.delivery_uncertain
            {
                record_possible_delivery(self, record.id)?;
            }
            record = abandon_record(
                self,
                record.id,
                IntentEscalationReason::PreviouslyAbandoned,
                now_ms,
            )?;
        }
        Ok(match IntentResolution::from_record(&record)? {
            IntentResolution::Delivered => SettledConnectorCall::Delivered {
                intent: Some(record.id),
            },
            IntentResolution::Stopped {
                delivery: UnconfirmedDelivery::DefiniteNonDelivery,
                reason,
            } => SettledConnectorCall::Refused {
                decision_ref: None,
                reasons: expired_reasons(reason),
            },
            IntentResolution::Stopped {
                delivery: UnconfirmedDelivery::Unresolved,
                reason,
            } => {
                let mut reasons = expired_reasons(reason);
                reasons.push("delivery_unconfirmed".to_owned());
                SettledConnectorCall::Unsettled {
                    intent: record.id,
                    reasons,
                }
            }
            IntentResolution::Pending { .. } => {
                return Err(IntentLedgerError::InvalidRecord(
                    "an expired connector intent stayed pending",
                ));
            }
        })
    }
}

/// An expired call's reasons: the expiry, then the ledger's own stop when
/// something other than this expiry stopped it.
fn expired_reasons(stop: IntentEscalationReason) -> Vec<String> {
    let mut reasons = vec![CONNECTOR_CALL_EXPIRED.to_owned()];
    if stop != IntentEscalationReason::PreviouslyAbandoned {
        reasons.push(intent_escalation_code(stop).to_owned());
    }
    reasons
}
