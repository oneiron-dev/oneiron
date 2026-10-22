//! The rows a connector call's passes pick (FIX 5455): the listing a call
//! and its resume answer beside their outcome, and the row list each pass
//! adds to (FIX 5820).

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::IntentLedgerError;

use super::{ConnectorCallHost, ConnectorCallOutcome, PENDING_CALLS, PendingConnectorCall, now_ms};

impl PendingConnectorCall {
    /// Lists `rows` among the rows the call's passes picked (FIX 5455),
    /// each once; an unknown set stays unknown.
    pub(in crate::outbound_consent) fn list_rows(
        &mut self,
        rows: impl IntoIterator<Item = EntityId>,
    ) {
        if let Some(listed) = &mut self.source_rows {
            listed.extend(rows);
            listed.sort_unstable();
            listed.dedup();
        }
    }
}

impl Vault {
    /// [`Self::resume_connector_call`], beside the rows the call's passes
    /// picked, kept on its row through every resume (FIX 5455): what a
    /// settler delivers beside the wait reply.
    pub fn resume_connector_call_listing<H: ConnectorCallHost>(
        &self,
        call_ref: &EntityId,
        host: &mut H,
    ) -> Result<(ConnectorCallOutcome, Option<Vec<EntityId>>), IntentLedgerError> {
        let pending = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.get(&self.store, &txn, call_ref)?
        };
        // An off-record caller's sealed arguments open for the resume
        // (FIX 9159).
        let pending = pending
            .map(|pending| pending.opened(&self.store, call_ref))
            .transpose()?;
        let Some(pending) = pending else {
            return Ok((
                ConnectorCallOutcome::Refused {
                    decision_ref: None,
                    reasons: vec!["connector_call_not_held".to_owned()],
                },
                Some(Vec::new()),
            ));
        };
        // A call whose connector asked for input answers from its row
        // (FIX 3837).
        if let Some(outcome) = pending.input_outcome(*call_ref) {
            return Ok((outcome, pending.source_rows));
        }
        // A call a code consent wait owns settles that wait too, and an
        // answered one runs only on its host's answered pass.
        if pending.code_consent_wait.is_some() {
            return self.resume_code_owned_connector_call(call_ref, pending, host, false);
        }
        if let Some(settled) = &pending.settled {
            return Ok((settled.outcome(), pending.source_rows));
        }
        if let Some(expired) = self.expire_connector_call_if_due(call_ref, &pending, now_ms())? {
            return Ok((expired, pending.source_rows));
        }
        self.drive_connector_call(Some(*call_ref), None, pending, host)
    }
}
