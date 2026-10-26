//! The closed hard scopes one booking passes through (FIX 10541). A child of
//! a closed scope keeps that scope as its parent and books at its nearest
//! open ancestor; each closed hard scope between stays a cap boundary for
//! its subtree (FIX 9563). What passes through one is no more than its room;
//! a reservation or a top-up is held there once and released there at the
//! child's settlement; spend already made is tallied there whole. Only the
//! host pays, so nothing is charged twice.

use crate::error::Result;

use super::super::AgentDispatcher;
use super::super::spend_record::{SCOPE, SpendRefused, SpendScope, SpendScopeId};
use super::ancestry::Host;

impl AgentDispatcher<'_> {
    /// What a child reserved under `parent` may draw, and the hard scope
    /// whose cap binds it: `parent`'s booking, a closed hard scope on the way
    /// binding first. A launch states it before it reserves.
    pub(in crate::agent_dispatch) fn reservable_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent: &SpendScopeId,
    ) -> Result<(u64, SpendScope)> {
        let booking = self.booking_in_txn(txn, parent)?;
        let available = self.available_through_in_txn(txn, &booking)?;
        let binding = match booking.boundaries.first() {
            Some(boundary) => boundary.clone(),
            None => self.binding_cap_in_txn(txn, &booking.host)?,
        };
        Ok((available, binding))
    }

    /// What `booking` may still draw: its host's available, no more than
    /// any boundary's room.
    pub(super) fn available_through_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        booking: &Host,
    ) -> Result<u64> {
        let available = self.available_from_in_txn(txn, &booking.host)?;
        Ok(booking
            .boundaries
            .iter()
            .fold(available, |available, boundary| {
                available.min(boundary.local_available())
            }))
    }
}

/// The scope that refuses `units` through `booking`: the first boundary
/// without room for them, else the host.
pub(super) fn refusing_scope(booking: &Host, units: u64) -> SpendScopeId {
    booking
        .boundaries
        .iter()
        .find(|boundary| boundary.local_available() < units)
        .map_or_else(
            || booking.host.scope.clone(),
            |boundary| boundary.scope.clone(),
        )
}

/// The refusal of the first of `boundaries` without room for `units`;
/// `None` when each has room.
pub(super) fn boundary_refusal(boundaries: &[SpendScope], units: u64) -> Option<SpendRefused> {
    boundaries
        .iter()
        .find(|boundary| boundary.local_available() < units)
        .map(|boundary| SpendRefused::OverCap {
            scope: boundary.scope.clone(),
            available_units: boundary.local_available(),
            asked_units: units,
        })
}

/// Holds `units` once at each of `boundaries`, a reservation's or a
/// top-up's.
pub(super) fn hold_through(
    dispatcher: &AgentDispatcher<'_>,
    txn: &mut heed::RwTxn<'_>,
    boundaries: Vec<SpendScope>,
    units: u64,
) -> Result<()> {
    for mut boundary in boundaries {
        boundary.held_units = boundary.held_units.saturating_add(units);
        SCOPE.put(&dispatcher.vault.store, txn, &boundary.scope.0, &boundary)?;
    }
    Ok(())
}

/// Tallies `units` already spent at each of `boundaries`, whole and past a
/// boundary's cap too; the host alone pays them.
pub(super) fn tally_through(
    dispatcher: &AgentDispatcher<'_>,
    txn: &mut heed::RwTxn<'_>,
    boundaries: Vec<SpendScope>,
    units: u64,
) -> Result<()> {
    for mut boundary in boundaries {
        boundary.spent_units = boundary.spent_units.saturating_add(units);
        SCOPE.put(&dispatcher.vault.store, txn, &boundary.scope.0, &boundary)?;
    }
    Ok(())
}
