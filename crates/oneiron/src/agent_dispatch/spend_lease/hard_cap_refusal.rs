//! Read-only identification of a spend tree's refusing open hard cap.

use crate::error::Result;

use super::super::AgentDispatcher;
use super::super::spend_record::{SpendScopeId, SpendState};
use super::super::widen_record::invalid;

impl AgentDispatcher<'_> {
    /// Finds the open hard scope whose own cap refuses `units`, without moving funds.
    pub(crate) fn hard_cap_refusal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
        units: u64,
    ) -> Result<Option<SpendScopeId>> {
        let booking = self.booking_in_txn(txn, scope)?;
        if booking
            .boundaries
            .iter()
            .any(|boundary| boundary.boundary_available() < units)
        {
            return Ok(None);
        }
        let mut current = booking.host;
        let mut hosts = std::collections::HashSet::from([current.scope.clone()]);
        let mut wanted = units;
        loop {
            // A ceiling is a separate limit; raising the hard cap does not clear it.
            if current.clamp_available(wanted) < wanted {
                return Ok(None);
            }
            let local = current.local_available();
            if local >= wanted {
                return Ok(None);
            }
            if current.hard || current.parent.is_none() {
                return Ok(
                    (current.hard && current.state == SpendState::Open).then_some(current.scope)
                );
            }
            let deficit = wanted - local;
            let hop = self.host_in_txn(txn, &current)?;
            if !hosts.insert(hop.host.scope.clone()) {
                return Err(invalid("spend scope ancestor cycle"));
            }
            if hop
                .boundaries
                .iter()
                .any(|boundary| boundary.boundary_available() < deficit)
            {
                return Ok(None);
            }
            current = hop.host;
            wanted = deficit;
        }
    }
}
