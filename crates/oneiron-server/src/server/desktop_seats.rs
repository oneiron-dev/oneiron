//! The run guests live on this host (CUA-001), so the owner's door can reach
//! the same guest a run's door drives, and a run's next door finds the guest
//! its last one left: an MCP `execute_code` run's next entry, or a pumped
//! run's resume after a durable wait. A run's desktop and its browser each
//! take a seat here ([`RunSeats`]), the browser's cart and login with it.
//!
//! A run's door binds the run's seat and unbinds it when it drops. A seat
//! whose run has no door bound is parked: the registry holds it, and its
//! guest with it, until the run ends ([`RunSeats::end_run`]) or it sits
//! idle past [`idle_limit`]. A seat whose guest never started goes with its
//! last door. Ending a seat ends a takeover still asked or held with an
//! `abandoned` receipt, clears the agent's inbox Ask and drops the guest.
//!
//! An agent's handover raises the owners' inbox Ask ("Needs you",
//! [`RunSeats::asked`]); the owner's take or return clears it
//! ([`RunSeats::answered`]). No seat outlives the host, so the host clears
//! every open takeover Ask when it starts ([`clear_stale_asks`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError, Weak};
use std::time::{Duration, Instant};

use oneiron::{EntityId, Vault};
use oneiron_browser::{AbandonedTakeover, BrowserError, DesktopSession, Takeover};

use super::SyncServer;

/// One run's guest: its session once the run's first call on it started the
/// guest. The run's calls and the owner's acts take turns on this lock.
pub(crate) type Seat<S> = Mutex<Option<S>>;

/// One run's desktop seat.
pub(crate) type DesktopSeat = Seat<DesktopSession>;

/// The run desktops' seats.
pub(crate) type DesktopSeats = RunSeats<DesktopSession>;

/// A run guest's session as its seat keeps it: who has it, the takeover a
/// seat's end cuts short and its receipt, and what the owner's frame
/// stream looks at.
pub(crate) trait SeatGuest: Send + Sized + 'static {
    /// The guest's name in its takeover's inbox Ask: `desktop` or `browser`.
    const GUEST: &'static str;
    /// What an owner's act names when the run has none: `run desktop`.
    const NOUN: &'static str;
    /// The route an owner takes the guest over at; its inbox Ask names it.
    const TAKE_ROUTE: &'static str;

    /// The server's seats of this guest.
    fn seats(server: &SyncServer) -> &Arc<RunSeats<Self>>;

    /// Who has the guest now.
    fn takeover(&self) -> &Takeover;

    /// Ends a takeover still asked or held as the guest goes away.
    fn abandon_takeover(&mut self) -> Option<AbandonedTakeover>;

    /// Lands `record`, a takeover the seat's end cut short, as the run's
    /// `abandoned` takeover receipt.
    fn land_abandoned(
        vault: &Vault,
        run: EntityId,
        record: &serde_json::Value,
    ) -> oneiron::Result<String>;

    /// One look for the owner's frame stream: what the view shows beside
    /// the screen (a browser's tabs), when the guest has more than one
    /// screen, and the screen in front.
    fn watch(&mut self) -> (Option<serde_json::Value>, Result<Vec<u8>, BrowserError>);
}

impl SeatGuest for DesktopSession {
    const GUEST: &'static str = "desktop";
    const NOUN: &'static str = "run desktop";
    const TAKE_ROUTE: &'static str = "/v1/owner/desktops/take";

    fn seats(server: &SyncServer) -> &Arc<RunSeats<Self>> {
        &server.desktop_seats
    }

    fn takeover(&self) -> &Takeover {
        Self::takeover(self)
    }

    fn abandon_takeover(&mut self) -> Option<AbandonedTakeover> {
        Self::abandon_takeover(self)
    }

    fn land_abandoned(
        vault: &Vault,
        run: EntityId,
        record: &serde_json::Value,
    ) -> oneiron::Result<String> {
        vault.append_desktop_takeover_abandoned_receipt(run, record)
    }

    fn watch(&mut self) -> (Option<serde_json::Value>, Result<Vec<u8>, BrowserError>) {
        (None, self.person_screen())
    }
}

/// How often the parked seats are checked for idleness.
const REAP_TICK: Duration = Duration::from_secs(30);

/// How long a parked run guest waits, with no door of its run bound and no
/// act of the owner on it, before it ends (CALLS, open): 30 minutes while
/// its agent has it, 24 hours while the agent's ask waits or the owner holds
/// it. The owner watching its frames is no act. A desktop and a browser
/// wait alike.
fn idle_limit(takeover: &Takeover) -> Duration {
    match takeover {
        Takeover::Agent => Duration::from_secs(30 * 60),
        Takeover::Waiting { .. } | Takeover::Held { .. } => Duration::from_secs(24 * 60 * 60),
    }
}

/// The seats of one kind of run guest, one per run.
pub(crate) struct RunSeats<S> {
    runs: Mutex<HashMap<EntityId, RunSeat<S>>>,
    /// Whether the idle reaper's thread runs.
    reaping: AtomicBool,
}

impl<S> Default for RunSeats<S> {
    fn default() -> Self {
        Self {
            runs: Mutex::default(),
            reaping: AtomicBool::new(false),
        }
    }
}

/// One run's seat in the registry.
struct RunSeat<S> {
    seat: Arc<Seat<S>>,
    vault: Arc<Vault>,
    /// The run's doors bound to the seat now.
    doors: usize,
    /// The run ended while a door was bound: the last door's unbind ends it.
    ended: bool,
    /// The last door's unbind, or the owner's last act on the seat.
    touched: Instant,
    /// The inbox Ask the agent's open handover raised: when it asked, and
    /// each owner's row.
    ask: Option<(u64, Vec<EntityId>)>,
}

impl<S: SeatGuest> RunSeats<S> {
    /// Binds a door of run `run` to the run's seat: the one its last door
    /// left, else a new one.
    pub(crate) fn bind(self: &Arc<Self>, run: EntityId, vault: &Arc<Vault>) -> Arc<Seat<S>> {
        self.reap_in_background();
        let mut runs = self.runs();
        let entry = runs.entry(run).or_insert_with(|| RunSeat {
            seat: Arc::new(Mutex::new(None)),
            vault: Arc::clone(vault),
            doors: 0,
            ended: false,
            touched: Instant::now(),
            ask: None,
        });
        entry.doors += 1;
        entry.touched = Instant::now();
        Arc::clone(&entry.seat)
    }

    /// Unbinds a door of run `run` from `seat`. The run's last door parks
    /// the seat, or ends it once the run ended; a seat whose guest never
    /// started goes with it.
    pub(crate) fn unbind(&self, run: EntityId, seat: &Arc<Seat<S>>) {
        let ending = {
            let mut runs = self.runs();
            let Some(entry) = runs
                .get_mut(&run)
                .filter(|entry| Arc::ptr_eq(&entry.seat, seat))
            else {
                return;
            };
            entry.doors = entry.doors.saturating_sub(1);
            entry.touched = Instant::now();
            let started = Self::peek(&entry.seat, |session| session.is_some()).unwrap_or(true);
            if entry.doors > 0 || (started && !entry.ended) {
                return;
            }
            runs.remove(&run)
        };
        if let Some(entry) = ending {
            end(run, entry);
        }
    }

    /// Run `run` ended: its seat ends now, or with the run's last door.
    pub(crate) fn end_run(&self, run: EntityId) {
        let ending = {
            let mut runs = self.runs();
            let Some(entry) = runs.get_mut(&run) else {
                return;
            };
            if entry.doors > 0 {
                entry.ended = true;
                return;
            }
            runs.remove(&run)
        };
        if let Some(entry) = ending {
            end(run, entry);
        }
    }

    /// Run `run`'s pumped attempt settled: unless it parked on a durable
    /// wait, the run ended.
    pub(crate) fn run_settled(&self, run: Option<EntityId>, parked: bool) {
        if let Some(run) = run.filter(|_| !parked) {
            self.end_run(run);
        }
    }

    /// Run `run`'s seat for an owner's act, which keeps a parked seat up.
    pub(crate) fn get(&self, run: EntityId) -> Option<Arc<Seat<S>>> {
        let mut runs = self.runs();
        let entry = runs.get_mut(&run)?;
        entry.touched = Instant::now();
        Some(Arc::clone(&entry.seat))
    }

    /// Run `run`'s seat for the owner's view, which keeps no seat up.
    pub(crate) fn watch(&self, run: EntityId) -> Option<Arc<Seat<S>>> {
        self.runs().get(&run).map(|entry| Arc::clone(&entry.seat))
    }

    /// Every run guest the registry holds, bound or parked.
    pub(crate) fn live(&self) -> Vec<(EntityId, Arc<Seat<S>>)> {
        self.runs()
            .iter()
            .map(|(run, entry)| (*run, Arc::clone(&entry.seat)))
            .collect()
    }

    /// After a call of run `run`'s agent on its guest, under the seat's
    /// lock: an ask the agent opened raises the owners' inbox Ask, once per
    /// ask. An Ask that does not land is logged; the owner still finds the
    /// ask in the guest's owner list.
    pub(crate) fn asked(&self, run: EntityId, takeover: &Takeover) {
        let Takeover::Waiting {
            reason,
            asked_at_ms,
        } = takeover
        else {
            return;
        };
        let vault = {
            let runs = self.runs();
            let Some(entry) = runs.get(&run) else {
                return;
            };
            if entry.ask.as_ref().is_some_and(|(at, _)| at == asked_at_ms) {
                return;
            }
            Arc::clone(&entry.vault)
        };
        let Some(rows) = raise_ask(&vault, S::GUEST, run, reason, *asked_at_ms, S::TAKE_ROUTE)
        else {
            return;
        };
        // A seat that ended meanwhile clears what was just raised.
        let stale = match self.runs().get_mut(&run) {
            Some(entry) => entry.ask.replace((*asked_at_ms, rows)),
            None => Some((*asked_at_ms, rows)),
        };
        if let Some((_, rows)) = stale {
            clear_ask(&vault, run, &rows);
        }
    }

    /// The owner took run `run`'s guest over or handed it back: the agent's
    /// ask is answered, and its inbox Ask clears.
    pub(crate) fn answered(&self, run: EntityId) {
        let (vault, ask) = {
            let mut runs = self.runs();
            let Some(entry) = runs.get_mut(&run) else {
                return;
            };
            (Arc::clone(&entry.vault), entry.ask.take())
        };
        if let Some((_, rows)) = ask {
            clear_ask(&vault, run, &rows);
        }
    }

    /// Starts the thread that ends idle parked seats, once.
    fn reap_in_background(self: &Arc<Self>) {
        if self.reaping.swap(true, Ordering::AcqRel) {
            return;
        }
        let seats = Arc::downgrade(self);
        let spawned = std::thread::Builder::new()
            .name(format!("{}-seats", S::GUEST))
            .spawn(move || reap_loop(&seats));
        if let Err(error) = spawned {
            self.reaping.store(false, Ordering::Release);
            tracing::warn!(%error, guest = S::GUEST, "the run guests' idle reaper did not start");
        }
    }

    /// Ends each parked seat idle past its limit at `now`.
    fn reap(&self, now: Instant) {
        let idle: Vec<(EntityId, RunSeat<S>)> = {
            let mut runs = self.runs();
            let expired: Vec<EntityId> = runs
                .iter()
                .filter(|(_, entry)| entry.doors == 0 && idle_past(entry, now))
                .map(|(run, _)| *run)
                .collect();
            expired
                .into_iter()
                .filter_map(|run| runs.remove(&run).map(|entry| (run, entry)))
                .collect()
        };
        for (run, entry) in idle {
            end(run, entry);
        }
    }

    /// Reads a seat without waiting for it: `None` while a call or an act
    /// holds it.
    pub(crate) fn peek<T>(seat: &Seat<S>, read: impl FnOnce(Option<&S>) -> T) -> Option<T> {
        match seat.try_lock() {
            Ok(session) => Some(read(session.as_ref())),
            Err(TryLockError::Poisoned(poisoned)) => Some(read(poisoned.into_inner().as_ref())),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    fn runs(&self) -> MutexGuard<'_, HashMap<EntityId, RunSeat<S>>> {
        self.runs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The reaper's loop: it ends with the registry.
fn reap_loop<S: SeatGuest>(seats: &Weak<RunSeats<S>>) {
    loop {
        std::thread::sleep(REAP_TICK);
        let Some(seats) = seats.upgrade() else {
            return;
        };
        seats.reap(Instant::now());
    }
}

/// Whether a parked seat sat idle past its limit at `now`. A seat an act
/// holds right now is not idle; one whose guest never started has nothing
/// to keep.
fn idle_past<S: SeatGuest>(entry: &RunSeat<S>, now: Instant) -> bool {
    match RunSeats::<S>::peek(&entry.seat, |session| {
        session.map(|s| idle_limit(s.takeover()))
    }) {
        None => false,
        Some(None) => true,
        Some(Some(limit)) => now.saturating_duration_since(entry.touched) >= limit,
    }
}

/// Ends a seat taken out of the registry: a takeover still asked or held
/// lands its `abandoned` receipt with what it held so far, the agent's inbox
/// Ask clears, and the guest goes with its session.
fn end<S: SeatGuest>(run: EntityId, entry: RunSeat<S>) {
    let session = entry
        .seat
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(mut session) = session
        && let Some(cut) = session.abandon_takeover()
    {
        let landed = serde_json::to_value(&cut)
            .map_err(|error| error.to_string())
            .and_then(|record| {
                S::land_abandoned(&entry.vault, run, &record).map_err(|error| error.to_string())
            });
        if let Err(error) = landed {
            tracing::warn!(%error, guest = S::GUEST, run = %run.to_hex(), "an abandoned takeover landed no receipt");
        }
    }
    if let Some((_, rows)) = entry.ask {
        clear_ask(&entry.vault, run, &rows);
    }
}

/// Raises run `run`'s `guest` takeover ask as each owner's inbox Ask
/// ("Needs you": the run, the agent's reason and `take`, the route that
/// takes the guest over) and returns its rows; `None`, logged, when it did
/// not land.
fn raise_ask(
    vault: &Vault,
    guest: &str,
    run: EntityId,
    reason: &str,
    asked_at_ms: u64,
    take: &str,
) -> Option<Vec<EntityId>> {
    match vault.raise_takeover_ask(guest, run, reason, asked_at_ms, take) {
        Ok(rows) => Some(rows),
        Err(error) => {
            tracing::warn!(%error, guest, run = %run.to_hex(), "a takeover ask raised no inbox ask");
            None
        }
    }
}

/// Clears a takeover ask's inbox rows, logging a failure.
fn clear_ask(vault: &Vault, run: EntityId, rows: &[EntityId]) {
    if let Err(error) = vault.clear_takeover_ask(rows) {
        tracing::warn!(%error, run = %run.to_hex(), "a takeover ask's inbox rows did not clear");
    }
}

/// Clears every takeover Ask still open in `vault`, desktop and browser
/// alike, as the host starts: no seat outlives a restart, so none of them
/// can be answered. A failure is logged; the Asks stay as they were.
pub(crate) fn clear_stale_asks(vault: &Vault) {
    match vault.clear_open_takeover_asks() {
        Ok(0) => {}
        Ok(cleared) => {
            tracing::info!(
                cleared,
                "takeover asks left open by the last run of the host cleared"
            );
        }
        Err(error) => {
            tracing::warn!(%error, "takeover asks left open by the last run of the host did not clear");
        }
    }
}
