//! The run desktops live on this host (CUA-001), so the owner's door can
//! reach the same guest a run's door drives. A run's door registers its
//! desktop when it binds and releases it when it drops; the guest still
//! goes with the door. The registry holds no desktop alive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use oneiron::EntityId;
use oneiron_browser::DesktopSession;

/// One run's desktop: its session once the run's first desktop call started
/// the guest. The run's calls and the owner's acts take turns on this lock.
pub(crate) type DesktopSeat = Mutex<Option<DesktopSession>>;

#[derive(Default)]
pub(crate) struct DesktopSeats(Mutex<HashMap<EntityId, Weak<DesktopSeat>>>);

impl DesktopSeats {
    pub(crate) fn register(&self, run: EntityId, seat: &Arc<DesktopSeat>) {
        self.seats().insert(run, Arc::downgrade(seat));
    }

    /// Drops run `run`'s entry when it is still `seat`: a newer door of the
    /// same run keeps its own.
    pub(crate) fn release(&self, run: EntityId, seat: &Arc<DesktopSeat>) {
        let mut seats = self.seats();
        if seats
            .get(&run)
            .is_some_and(|held| std::ptr::eq(held.as_ptr(), Arc::as_ptr(seat)))
        {
            seats.remove(&run);
        }
    }

    pub(crate) fn get(&self, run: EntityId) -> Option<Arc<DesktopSeat>> {
        self.seats().get(&run).and_then(Weak::upgrade)
    }

    /// Every run desktop whose door is still bound.
    pub(crate) fn live(&self) -> Vec<(EntityId, Arc<DesktopSeat>)> {
        self.seats()
            .iter()
            .filter_map(|(run, seat)| Some((*run, seat.upgrade()?)))
            .collect()
    }

    fn seats(&self) -> std::sync::MutexGuard<'_, HashMap<EntityId, Weak<DesktopSeat>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
