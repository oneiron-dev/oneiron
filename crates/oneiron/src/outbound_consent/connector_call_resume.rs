//! Resuming a held connector call the ledger already admitted (ONE-2510).
//!
//! Once admission wrote a call's Pending ledger row, that row is the call:
//! its frozen bytes, grant binding and endpoint. A resume drives it by intent
//! id instead of preparing the request again, so a call whose endpoint,
//! manifest, slate class or grant changed since admission no longer fails the
//! ledger's replay identity check and strands its row. The frozen binding,
//! key, manifest and endpoint checks still refuse or hold such a call; only
//! the identity mismatch is gone. A call the ledger never admitted keeps the
//! live route, grant and prepare path.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::{IntentLedgerError, read_intent_for_attempt_in_txn};

use super::authority::OutboundBindingAuthority;
use super::connector_call::{
    ConnectorCallCaller, ConnectorCallHost, PendingConnectorCall, Step, now_ms, step_from_host,
};
use super::execution::resume_scoped_mcp_outbound_intent;

impl Vault {
    /// One pass of the held call `pending` through the ledger row its
    /// attempt and call seq admitted, if one exists; `None` when the ledger
    /// never admitted it, so the caller resolves and prepares it live.
    pub(super) fn resume_connector_call_intent<H: ConnectorCallHost>(
        &self,
        pending: &PendingConnectorCall,
        host: &mut H,
    ) -> Result<Option<Step>, IntentLedgerError> {
        let record = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            read_intent_for_attempt_in_txn(self, &txn, pending.attempt_id, pending.call_seq)?
        };
        let Some(record) = record else {
            return Ok(None);
        };
        let authority = OutboundBindingAuthority::for_vault(self)?;
        // A question the connector asks binds to the caller and the grant
        // the row admitted under; a row with no grant binds none.
        host.bind_caller(
            pending
                .grant_id
                .as_deref()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .map(|grant_id| ConnectorCallCaller {
                    principal_ref: pending.principal_ref.clone(),
                    grant_id,
                    name: pending.name.clone(),
                }),
        );
        // A reply or questions left from an earlier send are never this
        // call's, and no caller holds such questions (FIX 3844).
        drop(host.take_result());
        if let Some(left) = host.take_awaiting_input() {
            host.abandon_awaiting_input(&left.handle);
        }
        let dispatch =
            resume_scoped_mcp_outbound_intent(self, &authority, record.id, now_ms(), &mut *host)?;
        Ok(Some(step_from_host(&dispatch, host)))
    }
}
