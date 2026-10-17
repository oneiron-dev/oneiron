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
use crate::error::Error;
use crate::outbound_intent_ledger::{IntentLedgerError, read_intent_for_attempt_in_txn};

use super::authority::OutboundBindingAuthority;
use super::connector_call::{
    ConnectorCallHost, PendingConnectorCall, Step, now_ms, step_from_dispatch,
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
        // A reply left from an earlier send is never this call's.
        drop(host.take_result());
        let dispatch =
            resume_scoped_mcp_outbound_intent(self, &authority, record.id, now_ms(), &mut *host)?;
        let reply = host.take_result();
        Ok(Some(step_from_dispatch(&dispatch, reply)))
    }
}
