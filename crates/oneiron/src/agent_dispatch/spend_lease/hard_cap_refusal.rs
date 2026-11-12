//! Read-only identification of a spend tree's refusing open hard cap, and of
//! that cap's generation.

use crate::error::Result;

use super::super::AgentDispatcher;
use super::super::spend_record::{SCOPE, SpendCapGeneration, SpendScope, SpendScopeId, SpendState};
use super::super::widen_record::invalid;

impl AgentDispatcher<'_> {
    /// Finds the open hard scope whose own cap refuses `units`, without moving funds, with the
    /// units the reservation asks of that scope: what the scopes below it cannot cover.
    pub(crate) fn hard_cap_refusal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
        units: u64,
    ) -> Result<Option<(SpendScopeId, u64)>> {
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
                return Ok((current.hard && current.state == SpendState::Open)
                    .then_some((current.scope, wanted)));
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

    /// The cap generation of `scope`'s nearest hard scope, read now: the scope
    /// a hard-cap refusal of `scope`'s spend names. A host reads it before it
    /// builds a step's guards, so a top-up that lands after the guards read
    /// their room shows as a moved generation where the step parks. `None`
    /// when that scope is closed, or the walk ends at a soft root.
    pub fn spend_cap_generation(&self, scope: &SpendScopeId) -> Result<Option<SpendCapGeneration>> {
        let txn = self.vault.store.env.read_txn()?;
        let hard = self.nearest_hard_in_txn(&txn, scope)?;
        Ok(
            (hard.hard && hard.state == SpendState::Open).then(|| SpendCapGeneration {
                scope: hard.scope,
                cap_units: hard.cap_units,
            }),
        )
    }

    /// Whether `generation`'s scope holds another cap now, in the caller's
    /// snapshot: a top-up landed since `generation` was read.
    pub(crate) fn spend_cap_moved_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        generation: &SpendCapGeneration,
    ) -> Result<bool> {
        let scope = SCOPE
            .get(&self.vault.store, txn, &generation.scope.0)?
            .ok_or_else(|| invalid("spend scope is missing"))?;
        Ok(scope.cap_units != generation.cap_units)
    }

    /// The scope where [`Self::hard_cap_refusal_in_txn`]'s walk stops, whatever
    /// the room: `scope`'s booking host, then its hosts up to the first hard
    /// scope or the root.
    fn nearest_hard_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<SpendScope> {
        let mut current = self.booking_in_txn(txn, scope)?.host;
        let mut hosts = std::collections::HashSet::from([current.scope.clone()]);
        while !current.hard && current.parent.is_some() {
            let hop = self.host_in_txn(txn, &current)?;
            if !hosts.insert(hop.host.scope.clone()) {
                return Err(invalid("spend scope ancestor cycle"));
            }
            current = hop.host;
        }
        Ok(current)
    }
}
