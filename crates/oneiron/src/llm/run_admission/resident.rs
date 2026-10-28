//! Each resident's share of the vault's host-paid allocation (ARCH-0011
//! `#budget-lease`, FIX 7767). A resident is a person or agent with a home in
//! the vault: the one a call's handle names as its initiator, else the agent
//! a bound run serves. Each resident holds a soft share of the allocation by
//! default: a call past it is still admitted, and its overdraft writes a
//! receipt. Only a share the owner pinned refuses new paid work, once the
//! call's reservation no longer fits it. What each resident's settled calls
//! charged is the host's durable [`ResidentLedger`]; what its admitted calls
//! hold in flight is kept here.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::admission::{RunDenied, RunInner};
use super::host::AllocationRef;
use super::receipt::RunEvent;
use crate::EntityId;

/// The owner's setting for one resident's share of the allocation.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ResidentShare {
    /// The share, in the allocation's unit. `None` is the default share:
    /// what the residents with no share of their own split equally, once the
    /// shares the owner set are taken from the allocation.
    pub units: Option<u64>,
    /// The owner pinned it: past it, new paid work for the resident is
    /// refused. An unpinned share is soft, and spend past it writes an
    /// overdraft receipt.
    pub pinned: bool,
}

/// One resident's standing on one allocation, as its ledger reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidentStanding {
    /// The resident's share of the allocation, in its unit.
    pub share_units: u64,
    /// Whether the owner pinned the share.
    pub pinned: bool,
    /// What the resident's settled calls charged the allocation.
    pub used_units: u64,
}

/// Where a host keeps each resident's share and its depletion, durably.
pub trait ResidentLedger: Send + Sync {
    /// `resident`'s standing on `allocation`, which holds `allocation_units`.
    /// A row the ledger cannot read stands as the default share with nothing
    /// used: reading a share never refuses work.
    fn standing(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        allocation_units: u64,
    ) -> ResidentStanding;

    /// Records that one of `resident`'s calls charged `allocation` `units`,
    /// `overdraft_units` of them past its share.
    fn charge(
        &self,
        resident: EntityId,
        allocation: &AllocationRef,
        units: u64,
        overdraft_units: u64,
    );
}

/// The residents of one host account: their durable ledger, and what each
/// one's admitted calls hold on each allocation until they settle.
pub(super) struct Residents {
    ledger: Arc<dyn ResidentLedger>,
    in_flight: Mutex<HashMap<(EntityId, AllocationRef), u64>>,
}

impl std::fmt::Debug for Residents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Residents").finish_non_exhaustive()
    }
}

/// One admitted call's draw on its resident's share: what it reserved, and
/// the part of that past the share when it was admitted.
#[derive(Debug)]
pub(super) struct ResidentDraw {
    residents: Arc<Residents>,
    pub(super) resident: EntityId,
    pub(super) allocation: AllocationRef,
    pub(super) share_units: u64,
    /// What the resident had used and held in flight before this call.
    pub(super) used_units: u64,
    reserved_units: u64,
    pub(super) overdraft_units: u64,
}

impl Residents {
    pub(super) fn new(ledger: Arc<dyn ResidentLedger>) -> Arc<Self> {
        Arc::new(Self {
            ledger,
            in_flight: Mutex::default(),
        })
    }

    /// Draws `units` of `allocation` for one of `resident`'s calls. A soft
    /// share admits the call whatever its standing, and the draw names the
    /// part past the share; a pinned share the reservation does not fit
    /// refuses it.
    pub(super) fn draw(
        self: &Arc<Self>,
        resident: EntityId,
        allocation: &AllocationRef,
        allocation_units: u64,
        units: u64,
    ) -> Result<ResidentDraw, RunDenied> {
        let standing = self
            .ledger
            .standing(resident, allocation, allocation_units);
        let mut in_flight = self.lock();
        let key = (resident, allocation.clone());
        let held = in_flight.get(&key).copied().unwrap_or(0);
        let committed = standing.used_units.saturating_add(held);
        let after = committed.saturating_add(units);
        let overdraft_units = after.saturating_sub(standing.share_units.max(committed));
        if standing.pinned && overdraft_units > 0 {
            return Err(RunDenied::ResidentShareSpent { resident });
        }
        in_flight.insert(key, held.saturating_add(units));
        Ok(ResidentDraw {
            residents: Arc::clone(self),
            resident,
            allocation: allocation.clone(),
            share_units: standing.share_units,
            used_units: committed,
            reserved_units: units,
            overdraft_units,
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(EntityId, AllocationRef), u64>> {
        self.in_flight
            .lock()
            .expect("resident share mutex poisoned")
    }
}

impl ResidentDraw {
    /// Settles the draw: its call charged the allocation `units`. Its hold
    /// leaves the in-flight tally, and the ledger records the charge and the
    /// part of it past the share as the call's admission read it.
    pub(super) fn settle(&self, units: u64) {
        {
            let mut in_flight = self.residents.lock();
            let key = (self.resident, self.allocation.clone());
            let held = in_flight.get(&key).copied().unwrap_or(0);
            let left = held.saturating_sub(self.reserved_units);
            if left == 0 {
                in_flight.remove(&key);
            } else {
                in_flight.insert(key, left);
            }
        }
        if units == 0 {
            return;
        }
        let room = self.share_units.saturating_sub(self.used_units);
        let overdraft_units = units.saturating_sub(room);
        self.residents
            .ledger
            .charge(self.resident, &self.allocation, units, overdraft_units);
    }
}

impl RunInner {
    /// The overdraft receipt of a call admitted past its resident's soft
    /// share, on lease `lease`: one row each time a call overdraws. Units are
    /// the reservation's, as admitted, even if the call settles for less.
    pub(super) fn note_overdraft(&self, revision: u32, lease: &str, draw: &ResidentDraw) {
        if draw.overdraft_units == 0 {
            return;
        }
        self.record(
            revision,
            RunEvent::ResidentOverdraft {
                lease: lease.to_owned(),
                resident: draw.resident,
                allocation: draw.allocation.clone(),
                share_units: draw.share_units,
                used_units: draw.used_units,
                overdraft_units: draw.overdraft_units,
            },
        );
    }
}
