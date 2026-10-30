//! Connector-call resume, the pending listing, delivery acknowledgement and the
//! caller's status read.
//! Entry: `Vault::resume_connector_call`. Defines its own items.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::IntentLedgerError;

use super::connector_call::{
    ACKNOWLEDGED_CALLS, AcknowledgedConnectorCall, ConnectorCallHost, ConnectorCallOutcome,
    ConnectorCallState, PENDING_CALLS, PendingConnectorCallRef, SettledConnectorCall,
};
use super::connector_call_erase::delete_pending_call_in_txn;

impl Vault {
    /// Re-enters one held or pending-delivery call from its durable row:
    /// the same request, principal, attempt id and call seq. A call the
    /// ledger already admitted resumes from that frozen row by intent id;
    /// one it never admitted is rechecked against live authority through
    /// prepare and execute. It takes no new arguments. A call past its
    /// expiry deadline settles as expired instead. Once the call is
    /// delivered or refused its row keeps that outcome, without the tool's
    /// reply, until [`Self::ack_connector_call_delivery`]; a resume of a
    /// settled row answers that receipt again and sends nothing.
    pub fn resume_connector_call<H: ConnectorCallHost>(
        &self,
        call_ref: &EntityId,
        host: &mut H,
    ) -> Result<ConnectorCallOutcome, IntentLedgerError> {
        self.resume_connector_call_listing(call_ref, host)
            .map(|(outcome, _)| outcome)
    }

    /// Every held or pending-delivery call's row, settled ones included, for
    /// a settler that resumes each and answers its wait. A call whose
    /// connector asked for input is not one: its send was delivered, and its
    /// row is its caller's to poll (FIX 3837).
    ///
    /// The rows come in the fair line's order (FIX 12157): round-robin
    /// across the principals whose calls wait, oldest held first within one,
    /// so the calls a full window paced, which all open at one instant, share
    /// it by principal when the settler drives them in this order.
    pub fn pending_connector_calls(
        &self,
    ) -> Result<Vec<PendingConnectorCallRef>, IntentLedgerError> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        let now = crate::ports::job_recorded_at_in_txn(&self.store, &txn)?;
        let mut pending: Vec<_> = PENDING_CALLS
            .scan(&self.store, &txn)?
            .into_iter()
            .filter(|(_, pending)| pending.input.is_none())
            .collect();
        pending.sort_by_key(|(_, pending)| pending.held_at_ms);
        Ok(crate::outbound::fair_line_order(pending.into_iter().map(
            |(call_ref, pending)| {
                (
                    pending.principal_ref,
                    PendingConnectorCallRef {
                        call_ref,
                        name: pending.name,
                        tool: pending.tool,
                        settled: pending.settled.is_some(),
                        paced: pending.paced_until.map(|until| until > now),
                    },
                )
            },
        )))
    }

    /// Drops a settled call's row once the wait reply that carries its
    /// outcome has committed; `true` when it dropped one. A held or
    /// retryable row stays for its next resume, and a row that keeps a
    /// connector's questions stays for its caller's polls (FIX 3837).
    pub fn ack_connector_call_delivery(
        &self,
        call_ref: &EntityId,
    ) -> Result<bool, IntentLedgerError> {
        Ok(
            self.with_write_txn(|txn| match PENDING_CALLS.get(&self.store, txn, call_ref)? {
                Some(pending) if pending.settled.is_some() && pending.input.is_none() => {
                    delete_pending_call_in_txn(&self.store, txn, call_ref)
                }
                _ => Ok(false),
            })?,
        )
        .inspect(|_| self.finish_connector_resume_retirements_after_commit())
    }

    /// One connector call's state by its ref, for the caller-bound status
    /// read (FIX 2279): the held row while one stands, else the caller an
    /// acknowledgement kept. `None` for a ref this vault never held, or one
    /// held before acknowledgements kept their caller.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn connector_call_state(
        &self,
        call_ref: &EntityId,
    ) -> Result<Option<ConnectorCallState>, IntentLedgerError> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        if let Some(pending) = PENDING_CALLS.get(&self.store, &txn, call_ref)? {
            return Ok(Some(ConnectorCallState {
                input: pending.input.as_ref().map(|input| input.view()),
                settled: pending.settled.as_ref().map(SettledConnectorCall::outcome),
                approval_digest: super::approval::ConnectorCallApproval::current_digest(
                    pending.approval.as_ref(),
                )
                .filter(|_| pending.settled.is_none())
                .map(str::to_owned),
                principal_ref: pending.principal_ref,
                name: pending.name,
                tool: pending.tool,
                held_at_ms: Some(pending.held_at_ms),
                reasons: pending.held_reasons,
                acknowledged: false,
                source_rows: pending.source_rows,
            }));
        }
        Ok(ACKNOWLEDGED_CALLS
            .get(&self.store, &txn, call_ref)?
            .map(|row| ConnectorCallState {
                settled: row.settled.as_ref().map(SettledConnectorCall::outcome),
                principal_ref: row.principal_ref,
                name: row.name,
                tool: row.tool,
                held_at_ms: None,
                reasons: Vec::new(),
                acknowledged: true,
                source_rows: row.source_rows,
                approval_digest: None,
                input: None,
            }))
    }

    /// [`Self::ack_connector_call_delivery`], keeping who called the call
    /// and what it calls in the same commit, so its caller, or the owner,
    /// can still read its status by ref (FIX 2279). `true` when it dropped
    /// the held row.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn ack_connector_call_delivery_keeping_caller(
        &self,
        call_ref: &EntityId,
    ) -> Result<bool, IntentLedgerError> {
        Ok(
            self.with_write_txn(|txn| match PENDING_CALLS.get(&self.store, txn, call_ref)? {
                Some(pending) if pending.settled.is_some() && pending.input.is_none() => {
                    let caller = AcknowledgedConnectorCall {
                        principal_ref: pending.principal_ref,
                        name: pending.name,
                        tool: pending.tool,
                        settled: None,
                        source_rows: None,
                    };
                    ACKNOWLEDGED_CALLS.put(&self.store, txn, call_ref, &caller)?;
                    delete_pending_call_in_txn(&self.store, txn, call_ref)
                }
                _ => Ok(false),
            })?,
        )
        .inspect(|_| self.finish_connector_resume_retirements_after_commit())
    }
}
