//! Expiry of held and pending-delivery connector calls (ONE-2510).
//!
//! A call nobody settles expires the owner's `connectors.calls.pending_ttl_secs`
//! (seven days by default; [`CONNECTOR_CALL_PENDING_TTL`]) after it was first
//! held; a retry never moves that deadline, and neither does a count window
//! that paces the call (FIX 8753). The lifetime is read at each check, so the
//! owner's change moves every held call's deadline. Expiry settles the
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
use crate::store::Store;

use super::connector_call::{
    ConnectorCallOutcome, PENDING_CALLS, PendingConnectorCall, SettledConnectorCall,
    intent_escalation_code,
};
use super::setting_keys::CONNECTOR_CALL_PENDING_TTL;

/// The stable reason an expired call carries.
pub(super) const CONNECTOR_CALL_EXPIRED: &str = "connector_call_expired";

/// How long a held or pending-delivery connector call waits for its hold to
/// clear or its send to settle, in seconds from when it was first held, as
/// `txn` reads the owner's `connectors.calls.pending_ttl_secs` (seven days by
/// default). A connector event wake a count window paces fixes its deadline
/// with it at its first deferral (FIX 8753).
///
/// # Errors
///
/// Storage errors reading the key's rows.
pub(crate) fn connector_call_pending_ttl_secs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> crate::Result<u64> {
    Ok(CONNECTOR_CALL_PENDING_TTL
        .read_in_dbs_txn(store, txn, &[], None)?
        .value
        .0)
}

/// The moment a call first held at `held_at_ms` expires, for a lifetime of
/// `ttl_secs`.
pub(super) const fn connector_call_deadline(held_at_ms: u64, ttl_secs: u64) -> u64 {
    held_at_ms.saturating_add(ttl_secs.saturating_mul(1000))
}

/// A lifetime of `secs` in words, for the owner's questions: whole days,
/// else whole hours, else whole minutes, else seconds.
pub(super) fn connector_call_lifetime_words(secs: u64) -> String {
    let (count, unit) = [(86_400, "day"), (3_600, "hour"), (60, "minute")]
        .into_iter()
        .find(|(size, _)| secs % size == 0)
        .map_or((secs, "second"), |(size, unit)| (secs / size, unit));
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
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
    /// still be resumed. A call whose connector asked for input never
    /// expires here: its send was delivered (FIX 3837). A call a count
    /// window paces keeps the deadline of its first hold (FIX 8753): pacing
    /// queues it, and neither a later window nor a re-pace moves that
    /// deadline, so a window that opens after it finds the call expired,
    /// never sent.
    pub(super) fn expire_connector_call_if_due(
        &self,
        call_ref: &EntityId,
        pending: &PendingConnectorCall,
        now_ms: u64,
    ) -> Result<Option<ConnectorCallOutcome>, IntentLedgerError> {
        if pending.input.is_some() {
            return Ok(None);
        }
        let record = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let ttl_secs = connector_call_pending_ttl_secs_in_txn(&self.store, &txn)?;
            if now_ms < connector_call_deadline(pending.held_at_ms, ttl_secs) {
                return Ok(None);
            }
            read_intent_for_attempt_in_txn(self, &txn, pending.attempt_id, pending.call_seq)?
        };
        let settled = match record {
            None => SettledConnectorCall::Refused {
                decision_ref: None,
                reasons: vec![CONNECTOR_CALL_EXPIRED.to_owned()],
            },
            Some(record) => self.expire_admitted_intent(record, now_ms)?,
        };
        // A resume that settled the row first keeps its own outcome, and one
        // that met a connector's questions keeps them (FIX 3837).
        // The expired row withdraws its owner questions in the same write
        // (FIX 2551).
        let (settled, withdrawn) = self.with_write_txn(|txn| {
            let Some(mut row) = PENDING_CALLS.get(&self.store, txn, call_ref)? else {
                return Ok((Some(settled), Vec::new()));
            };
            if row.input.is_some() {
                return Ok((None, Vec::new()));
            }
            if let Some(known) = row.settled {
                return Ok((Some(known), Vec::new()));
            }
            row.settled = Some(settled.clone());
            let withdrawn = self.withdraw_call_owner_asks_in_txn(txn, call_ref, &mut row);
            PENDING_CALLS.put(&self.store, txn, call_ref, &row)?;
            // The actual expired outcome settles the code consent wait the
            // actual row names in this same writer (FIX 4518): no second
            // settlement, and no reply bytes inferred from the receipt.
            if let Some(wait_id) = row.code_consent_wait {
                let outcome = settled.outcome();
                crate::code_run::settle_code_consent_wait_listing_in_txn(
                    self,
                    txn,
                    wait_id,
                    &outcome,
                    row.source_rows.as_deref(),
                )?;
            }
            Ok((Some(settled), withdrawn))
        })?;
        self.signal_withdrawn_call_asks(&withdrawn);
        Ok(settled.map(|settled| settled.outcome()))
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
            // FIX 7960: the connector took the call as a remote task; its
            // outcome is still out when its caller expires.
            IntentResolution::Deferred => SettledConnectorCall::Unsettled {
                intent: record.id,
                reasons: vec![
                    CONNECTOR_CALL_EXPIRED.to_owned(),
                    super::connector_call_dispatch::REMOTE_TASK_DEFERRED.to_owned(),
                ],
            },
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

/// Test seam (`--cfg oneiron_test_support`): keeps a held call first held at
/// `held_at_ms`, which the ledger never admitted, as a hold does, and returns
/// its ref. Nothing asks the owner about it.
#[cfg(oneiron_test_support)]
pub(crate) fn put_held_connector_call(vault: &Vault, held_at_ms: u64) -> crate::Result<EntityId> {
    let call_ref = EntityId::now();
    let pending = PendingConnectorCall {
        name: "test-connector".to_owned(),
        tool: "test_tool".to_owned(),
        arguments: "{}".to_owned(),
        mutation: super::tool_call::MutationIntent::ExplicitMutation,
        grant_id: None,
        attempt_id: crate::attempt_queue::AttemptId::now(),
        call_seq: 0,
        principal_ref: EntityId::now().to_hex(),
        remember_context: None,
        held_at_ms,
        settled: None,
        held_reasons: Vec::new(),
        owner_ask_seq: None,
        credential: None,
        grant: None,
        secret_use: None,
        sweep_minted: false,
        sweep_dry_run_forced: false,
        live_use: false,
        code_consent_wait: None,
        source_rows: Some(Vec::new()),
        approval: None,
        input: None,
        code: None,
        sealed_arguments: None,
        off_record: false,
        paced_until: None,
        agent_run: None,
    };
    vault.with_write_txn(|txn| PENDING_CALLS.put(&vault.store, txn, &call_ref, &pending))?;
    Ok(call_ref)
}

/// Test seam (`--cfg oneiron_test_support`): whether the held call
/// `call_ref` settled (expiry settles it), `None` when no row holds it.
#[cfg(oneiron_test_support)]
pub(crate) fn held_connector_call_settled(
    vault: &Vault,
    call_ref: &EntityId,
) -> crate::Result<Option<bool>> {
    let txn = vault.store.env.read_txn()?;
    Ok(PENDING_CALLS
        .get(&vault.store, &txn, call_ref)?
        .map(|row| row.settled.is_some()))
}
