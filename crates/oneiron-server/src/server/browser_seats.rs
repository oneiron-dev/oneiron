//! The run browsers live on this host (CUA-001), so the owner's door can
//! reach the same guest a run's door drives, to sign in or pay inside it.
//! A run's door registers its browser when it binds and releases it when it
//! drops; the guest still goes with the door. The registry holds no browser
//! alive.
//!
//! An agent's handover raises the owners' inbox Ask ("Needs you",
//! [`BrowserSeats::asked`]), through the desktop's raiser with guest
//! `browser`; the owner's take or return clears it
//! ([`BrowserSeats::answered`]), and so does the door's drop.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use oneiron::{EntityId, Vault};
use oneiron_browser::{BrowserSession, Takeover};

use super::desktop_seats::{clear_ask, raise_ask};

/// One run's browser: its session once the run's first browser call started
/// the guest. The run's calls and the owner's acts take turns on this lock.
pub(crate) type BrowserSeat = Mutex<Option<BrowserSession>>;

/// The route an owner takes a run's browser over at; its inbox Ask names it.
const TAKE_ROUTE: &str = "/v1/owner/browsers/take";

#[derive(Default)]
pub(crate) struct BrowserSeats {
    seats: Mutex<HashMap<EntityId, Weak<BrowserSeat>>>,
    /// The inbox Ask each run's open handover raised: when it asked, and
    /// each owner's row.
    asks: Mutex<HashMap<EntityId, (u64, Vec<EntityId>)>>,
}

impl BrowserSeats {
    pub(crate) fn register(&self, run: EntityId, seat: &Arc<BrowserSeat>) {
        self.seats().insert(run, Arc::downgrade(seat));
    }

    /// Drops run `run`'s entry when it is still `seat`: a newer door of the
    /// same run keeps its own. The browser goes with the door, so its ask's
    /// inbox Ask clears.
    pub(crate) fn release(&self, vault: &Vault, run: EntityId, seat: &Arc<BrowserSeat>) {
        let mut seats = self.seats();
        if seats
            .get(&run)
            .is_some_and(|held| std::ptr::eq(held.as_ptr(), Arc::as_ptr(seat)))
        {
            seats.remove(&run);
            drop(seats);
            self.answered(vault, run);
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

    /// After a call of run `run`'s agent on its browser, under the seat's
    /// lock: an ask the agent opened raises the owners' inbox Ask, once per
    /// ask. An Ask that does not land is logged; the owner still finds the
    /// ask at `GET /v1/owner/browsers`.
    pub(crate) fn asked(&self, vault: &Vault, run: EntityId, takeover: &Takeover) {
        let Takeover::Waiting {
            reason,
            asked_at_ms,
        } = takeover
        else {
            return;
        };
        if self
            .asks()
            .get(&run)
            .is_some_and(|(at, _)| at == asked_at_ms)
        {
            return;
        }
        let Some(rows) = raise_ask(vault, "browser", run, reason, *asked_at_ms, TAKE_ROUTE) else {
            return;
        };
        let stale = self.asks().insert(run, (*asked_at_ms, rows));
        if let Some((_, rows)) = stale {
            clear_ask(vault, run, &rows);
        }
    }

    /// The owner took run `run`'s browser over or handed it back, or its
    /// door dropped: the agent's ask is answered, and its inbox Ask clears.
    pub(crate) fn answered(&self, vault: &Vault, run: EntityId) {
        let ask = self.asks().remove(&run);
        if let Some((_, rows)) = ask {
            clear_ask(vault, run, &rows);
        }
    }

    fn seats(&self) -> std::sync::MutexGuard<'_, HashMap<EntityId, Weak<BrowserSeat>>> {
        self.seats.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn asks(&self) -> std::sync::MutexGuard<'_, HashMap<EntityId, (u64, Vec<EntityId>)>> {
        self.asks.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
