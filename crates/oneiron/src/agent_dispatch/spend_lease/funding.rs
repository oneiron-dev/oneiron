//! Funding a scope from its existing parent tree.

use super::super::AgentDispatcher;
use super::super::spend_record::{SCOPE, SpendRefused, SpendScope};
use super::super::widen_record::invalid;
use super::ancestry::ScopeWalk;

impl AgentDispatcher<'_> {
    /// Makes `need` units local to `scope`, topping a soft scope up from its
    /// open ancestors, no more through a closed hard scope than its room
    /// (FIX 9563), and returns it for the caller to spend or hold from and
    /// write. The ancestors' and boundaries' moves are written here, and only
    /// once the whole chain is known to cover `need`: a refusal writes
    /// nothing. The chain is read however long it is (rule 5).
    pub(super) fn make_local_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: SpendScope,
        need: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        // Each entry draws its deficit from the next one up, through the
        // closed hard scopes between them.
        let mut chain: Vec<(SpendScope, u64, Vec<SpendScope>)> = Vec::new();
        let from = scope.scope.clone();
        let mut hosts = std::collections::HashSet::from([from.clone()]);
        let mut walk = ScopeWalk::default();
        let mut current = scope;
        let mut wanted = need;
        let mut reachable = 0u64;
        let drawn = loop {
            let room = current.clamp_available(wanted);
            if room < wanted {
                break Err(SpendRefused::OverCap {
                    scope: current.scope,
                    available_units: reachable.saturating_add(room),
                    asked_units: need,
                });
            }
            let local = current.local_available();
            reachable = reachable.saturating_add(local);
            if local >= wanted {
                chain.push((current, 0, Vec::new()));
                break Ok(());
            }
            if current.hard || current.parent.is_none() {
                break Err(SpendRefused::OverCap {
                    scope: current.scope,
                    available_units: reachable,
                    asked_units: need,
                });
            }
            let deficit = wanted - local;
            let hop = match self.host_in_walk(txn, &current, &mut walk) {
                Ok(hop) => hop,
                Err(error) => break Err(error.into()),
            };
            if !hosts.insert(hop.host.scope.clone()) {
                break Err(invalid("spend scope ancestor cycle").into());
            }
            if let Some(boundary) = hop
                .boundaries
                .iter()
                .find(|boundary| boundary.boundary_available() < deficit)
            {
                break Err(SpendRefused::OverCap {
                    scope: boundary.scope.clone(),
                    available_units: reachable.saturating_add(boundary.boundary_available()),
                    asked_units: need,
                });
            }
            chain.push((current, deficit, hop.boundaries));
            current = hop.host;
            wanted = deficit;
        };
        walk.finish(&self.vault.store, txn, &from);
        drawn?;
        for index in 0..chain.len() - 1 {
            let deficit = chain[index].1;
            chain[index].0.cap_units = chain[index].0.cap_units.saturating_add(deficit);
            for boundary in &mut chain[index].2 {
                boundary.held_units = boundary.held_units.saturating_add(deficit);
            }
            chain[index + 1].0.held_units = chain[index + 1].0.held_units.saturating_add(deficit);
        }
        for (index, (scope, _, boundaries)) in chain.iter().enumerate() {
            if index > 0 {
                SCOPE.put(&self.vault.store, txn, &scope.scope.0, scope)?;
            }
            for boundary in boundaries {
                SCOPE.put(&self.vault.store, txn, &boundary.scope.0, boundary)?;
            }
        }
        Ok(chain.swap_remove(0).0)
    }
}
