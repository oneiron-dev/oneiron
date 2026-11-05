//! Core half of `store::key_custody::recovery::unopened`: its store-layer items live in `oneiron_store::key_custody::recovery::unopened` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::recovery::unopened::*;

use super::super::head::CompartmentScope;
use super::CustodyLanding;
use std::collections::BTreeSet;

impl CustodyLanding {
    /// Whether the head this restore landed holds an owner-only compartment
    /// its opener did not open (FIX-LIST 9246 item 4): the one place an
    /// eligible credential's missing key may still ride.
    pub(crate) fn owner_compartment_unopened(&self) -> bool {
        self.admitted.owner_unopened
    }
}
