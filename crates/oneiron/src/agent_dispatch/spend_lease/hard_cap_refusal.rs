//! Read-only identification of the spend scope that refuses a reservation,
//! and why: an open hard cap a top-up frees, or a closed boundary or a
//! ceiling that no write frees (BUDGET-TRAP-UNTYPED-NO-SENDER); and of the
//! nearest hard cap's generation.

use crate::error::Result;

use super::super::AgentDispatcher;
use super::super::spend_record::{SCOPE, SpendCapGeneration, SpendScope, SpendScopeId, SpendState};
use super::super::widen_record::invalid;

/// The scope of a spend tree that refuses a reservation, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpendCapRefusal {
    /// An open hard scope's own cap refuses `asked_units` of it, what the
    /// scopes below it cannot cover: a top-up of that scope frees it.
    HardCap {
        scope: SpendScopeId,
        asked_units: u64,
    },
    /// A closed boundary on the way, or a closed hard scope that keeps its
    /// own books, has `available_units` of the `asked_units` that pass
    /// through it. Nothing reopens a closed scope.
    BoundaryClosed {
        scope: SpendScopeId,
        available_units: u64,
        asked_units: u64,
    },
    /// `scope`'s ceiling has `available_units` of the `asked_units` asked of
    /// it. The ceiling is set at launch, and a top-up does not raise it.
    CeilingReached {
        scope: SpendScopeId,
        available_units: u64,
        asked_units: u64,
    },
}

impl AgentDispatcher<'_> {
    /// Finds the scope that refuses `units` booked at `scope`, without moving
    /// funds, with the units the reservation asks of it: what the scopes
    /// below it cannot cover. `None` when the tree has room for them, or the
    /// walk ends at a soft root no hard cap bounds.
    pub(crate) fn hard_cap_refusal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
        units: u64,
    ) -> Result<Option<SpendCapRefusal>> {
        let booking = self.booking_in_txn(txn, scope)?;
        if let Some(refusal) = closed_boundary_refusal(&booking.boundaries, units) {
            return Ok(Some(refusal));
        }
        let mut current = booking.host;
        let mut hosts = std::collections::HashSet::from([current.scope.clone()]);
        let mut wanted = units;
        loop {
            // A ceiling is a separate limit; raising the hard cap does not clear it.
            let under_ceiling = current.clamp_available(wanted);
            if under_ceiling < wanted {
                return Ok(Some(SpendCapRefusal::CeilingReached {
                    scope: current.scope,
                    available_units: under_ceiling,
                    asked_units: wanted,
                }));
            }
            let local = current.local_available();
            if local >= wanted {
                return Ok(None);
            }
            if current.hard || current.parent.is_none() {
                return Ok(match (current.hard, current.state) {
                    (true, SpendState::Open) => Some(SpendCapRefusal::HardCap {
                        scope: current.scope,
                        asked_units: wanted,
                    }),
                    (true, SpendState::Closed) => Some(SpendCapRefusal::BoundaryClosed {
                        scope: current.scope,
                        available_units: local,
                        asked_units: wanted,
                    }),
                    (false, _) => None,
                });
            }
            let deficit = wanted - local;
            let hop = self.host_in_txn(txn, &current)?;
            if !hosts.insert(hop.host.scope.clone()) {
                return Err(invalid("spend scope ancestor cycle"));
            }
            if let Some(refusal) = closed_boundary_refusal(&hop.boundaries, deficit) {
                return Ok(Some(refusal));
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

/// The refusal of the first of `boundaries`, closed scopes all, without room
/// for `units`; `None` when each has room.
fn closed_boundary_refusal(boundaries: &[SpendScope], units: u64) -> Option<SpendCapRefusal> {
    boundaries
        .iter()
        .find(|boundary| boundary.boundary_available() < units)
        .map(|boundary| SpendCapRefusal::BoundaryClosed {
            scope: boundary.scope.clone(),
            available_units: boundary.boundary_available(),
            asked_units: units,
        })
}
