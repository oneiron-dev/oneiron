//! The run browsers live on this host (CUA-001), so the owner's door can
//! reach the same guest a run's door drives, to sign in or pay inside it.
//! A run's door registers its browser when it binds and releases it when it
//! drops; the guest still goes with the door. The registry holds no browser
//! alive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use oneiron::EntityId;
use oneiron_browser::BrowserSession;

/// One run's browser: its session once the run's first browser call started
/// the guest. The run's calls and the owner's acts take turns on this lock.
pub(crate) type BrowserSeat = Mutex<Option<BrowserSession>>;

#[derive(Default)]
pub(crate) struct BrowserSeats(Mutex<HashMap<EntityId, Weak<BrowserSeat>>>);

impl BrowserSeats {
    pub(crate) fn register(&self, run: EntityId, seat: &Arc<BrowserSeat>) {
        self.seats().insert(run, Arc::downgrade(seat));
    }

    /// Drops run `run`'s entry when it is still `seat`: a newer door of the
    /// same run keeps its own.
    pub(crate) fn release(&self, run: EntityId, seat: &Arc<BrowserSeat>) {
        let mut seats = self.seats();
        if seats
            .get(&run)
            .is_some_and(|held| std::ptr::eq(held.as_ptr(), Arc::as_ptr(seat)))
        {
            seats.remove(&run);
        }
    }

    pub(crate) fn get(&self, run: EntityId) -> Option<Arc<BrowserSeat>> {
        self.seats().get(&run).and_then(Weak::upgrade)
    }

    /// Every run browser whose door is still bound.
    pub(crate) fn live(&self) -> Vec<(EntityId, Arc<BrowserSeat>)> {
        self.seats()
            .iter()
            .filter_map(|(run, seat)| Some((*run, seat.upgrade()?)))
            .collect()
    }

    fn seats(&self) -> std::sync::MutexGuard<'_, HashMap<EntityId, Weak<BrowserSeat>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
