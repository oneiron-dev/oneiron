//! The owner's reserve on the shared connection pool (FIX 8274).
//!
//! Beside the descriptor floor, and never out of it, the pool keeps one more
//! connection for the owner's own reads, so his wire-health check and his
//! other owner-route reads reach him while the floor is full. Only the API
//! listener's sockets take it. A socket that finds the floor full and the
//! reserve free is served on the reserve, and its request's head is read by
//! the same HTTP/1 parser as every other. A read the owner proves
//! ([`reserve_eligible`], then [`crate::auth::admit_owner_proof`]) is served
//! there. Any other request, on the same socket and as the same parsed
//! request, parks: it waits in the floor's own line beside the floor, and
//! once the floor admits it the app serves it as it serves every request,
//! with every check it has. Nothing here refuses, drops or answers a request
//! but a probe's, below.
//!
//! One connection holds the reserve at a time, and each request on it is
//! judged afresh. At most `max_connections` sockets park at once; while
//! parking is full the reserve takes no new socket, and the socket in hand
//! waits for the floor as every socket did before. The listener's header
//! deadline is the only clock: none is added.
//!
//! An API socket from off this device whose address's stranger share is full
//! is a probe (FIX 9130): it takes the reserve only when the reserve is free
//! and parking has room at once ([`probe_now`]), never a floor permit or a
//! share, and otherwise it is shed as before. Its first request is judged as
//! any other. One the owner does not prove gives the reserve back and is
//! answered with the listener's 503 shed ([`ProbeShed`]), never parked; after
//! a proven one its connection is judged as any on the reserve.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::http::header::ACCEPT;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use tokio::sync::Notify;

use crate::admission::{Admission, Permit};
use crate::server::SyncServer;
use crate::wire_telemetry::{
    BodyCredential, ObservedBody, ObservedSocket, PoolPressure, SocketHold, with_body_credential,
};

/// The media type of a stream the reserve never serves.
const EVENT_STREAM: &[u8] = b"text/event-stream";

/// Whether a request may be served on the owner's reserve: a GET or HEAD
/// under `/v1/owner/`, not one of its streams. Only the API listener's
/// sockets hold the reserve, so only its requests are asked, never the
/// artifact listener's. It authorizes nothing: the owner's proof is still
/// required, and the route keeps its own checks.
pub(super) fn reserve_eligible(parts: &Parts) -> bool {
    let path = parts.uri.path();
    matches!(parts.method, Method::GET | Method::HEAD)
        && path.starts_with("/v1/owner/")
        && !path.ends_with("/stream")
        && !accepts_event_stream(&parts.headers)
}

/// Whether any `Accept` value names `text/event-stream`, in any case.
fn accepts_event_stream(headers: &HeaderMap) -> bool {
    headers.get_all(ACCEPT).iter().any(|value| {
        value
            .as_bytes()
            .windows(EVENT_STREAM.len())
            .any(|window| window.eq_ignore_ascii_case(EVENT_STREAM))
    })
}

/// The pool's reserve: one connection for the owner beside the floor, and
/// the parking its demoted sockets wait in.
pub(super) struct OwnerReserve {
    state: Mutex<ReserveState>,
    /// Signalled when the reserve or a parking place comes free.
    freed: Notify,
    /// How many sockets may park at once: the floor's own bound.
    parking: usize,
}

#[derive(Default)]
struct ReserveState {
    /// Whether a connection holds the reserve.
    held: bool,
    /// How many sockets wait parked for the floor.
    parked: usize,
}

impl OwnerReserve {
    pub(super) fn new(parking: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
            freed: Notify::new(),
            parking: parking.max(1),
        })
    }

    /// The reserve, when no connection holds it and parking has room for
    /// its socket should its request go back to the floor.
    fn try_take(self: &Arc<Self>) -> Option<ReserveHold> {
        let mut state = lock(&self.state);
        if state.held || state.parked >= self.parking {
            return None;
        }
        state.held = true;
        Some(ReserveHold {
            reserve: Arc::clone(self),
            holding: true,
        })
    }

    /// [`Self::try_take`], at the first moment it can.
    pub(super) async fn take(self: &Arc<Self>) -> ReserveHold {
        loop {
            let freed = self.freed.notified();
            if let Some(hold) = self.try_take() {
                return hold;
            }
            freed.await;
        }
    }
}

/// The reserve, held by one connection. Dropping it frees the reserve.
pub(super) struct ReserveHold {
    reserve: Arc<OwnerReserve>,
    /// Still the reserve's, rather than parked.
    holding: bool,
}

impl ReserveHold {
    /// Frees the reserve and holds a parking place instead, in one step.
    /// Parking has room: the reserve is taken only while it does, and only
    /// its one holder parks.
    fn park(mut self) -> ParkPlace {
        let mut state = lock(&self.reserve.state);
        state.held = false;
        state.parked += 1;
        drop(state);
        self.holding = false;
        self.reserve.freed.notify_waiters();
        ParkPlace(Arc::clone(&self.reserve))
    }
}

impl Drop for ReserveHold {
    fn drop(&mut self) {
        if self.holding {
            lock(&self.reserve.state).held = false;
            self.reserve.freed.notify_waiters();
        }
    }
}

/// A parked socket's place beside the floor. Dropping it frees the place.
struct ParkPlace(Arc<OwnerReserve>);

impl Drop for ParkPlace {
    fn drop(&mut self) {
        let mut state = lock(&self.0.state);
        state.parked = state.parked.saturating_sub(1);
        drop(state);
        self.0.freed.notify_waiters();
    }
}

/// The pool as the API listener's socket in hand takes it without waiting:
/// a free floor permit, the one `admit` would give at once (while one is
/// free nobody waits) and nothing put in line; else the reserve, while it
/// is free and parking has room.
pub(super) fn take_now(
    floor: &Admission<()>,
    reserve: &Arc<OwnerReserve>,
    pressure: Option<&Arc<PoolPressure>>,
) -> Option<Arc<Custody>> {
    if let Some(permit) = floor.try_admit_background() {
        return Some(Custody::floor(permit, pressure));
    }
    reserve
        .try_take()
        .map(|hold| Custody::reserve(hold, pressure))
}

/// The reserve for a probe: an API socket past its address's stranger share,
/// taken without waiting while the reserve is free and parking has room,
/// never from the floor (FIX 9130). Its first request is judged on it.
pub(super) fn probe_now(
    reserve: &Arc<OwnerReserve>,
    pressure: Option<&Arc<PoolPressure>>,
) -> Option<Arc<Custody>> {
    let hold = reserve.try_take()?;
    Some(Custody::new(
        Held::Reserve { hold },
        SocketHold::Classifying,
        pressure,
        true,
    ))
}

/// A probe's first request the owner did not prove: the reserve is given
/// back, and the listener answers its 503 shed.
pub(super) struct ProbeShed;

/// How one connection holds the pool. Its socket keeps it for as long as
/// the socket is open, whoever owns the socket by then: across keep-alive
/// requests and through an upgrade.
pub(super) struct Custody {
    held: Mutex<Option<Held>>,
    /// Its place in the pool's pressure check, which counts it by how it
    /// holds the pool, until it gives back what it holds.
    observed: Mutex<Option<ObservedSocket>>,
    /// Signalled when it parks.
    parked: Notify,
    /// A probe whose first request is not judged yet: one the owner does not
    /// prove is shed, never parked (FIX 9130).
    probe: AtomicBool,
}

enum Held {
    /// A floor permit: an ordinary connection, for the rest of its life.
    Floor { _permit: Permit },
    /// The owner's reserve.
    Reserve { hold: ReserveHold },
    /// Parked beside the floor, waiting in its line.
    Parked { _place: ParkPlace },
}

impl Custody {
    /// A connection the floor admitted.
    pub(super) fn floor(permit: Permit, pressure: Option<&Arc<PoolPressure>>) -> Arc<Self> {
        Self::new(
            Held::Floor { _permit: permit },
            SocketHold::Floor,
            pressure,
            false,
        )
    }

    /// A connection on the owner's reserve, its request not judged yet.
    pub(super) fn reserve(hold: ReserveHold, pressure: Option<&Arc<PoolPressure>>) -> Arc<Self> {
        Self::new(
            Held::Reserve { hold },
            SocketHold::Classifying,
            pressure,
            false,
        )
    }

    fn new(
        held: Held,
        hold: SocketHold,
        pressure: Option<&Arc<PoolPressure>>,
        probe: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::new(Some(held)),
            observed: Mutex::new(pressure.map(|pressure| pressure.socket(hold))),
            parked: Notify::new(),
            probe: AtomicBool::new(probe),
        })
    }

    /// Gives back what it holds of the pool: a probe's reserve, once its
    /// first request was not the owner's. Its place in the pressure check
    /// goes with it, so the socket shed after counts as nothing (FIX 9263).
    fn release(&self) {
        let held = lock(&self.held).take();
        drop(held);
        let observed = lock(&self.observed).take();
        drop(observed);
    }

    /// Whether it holds the owner's reserve, so its next request is judged.
    pub(super) fn on_reserve(&self) -> bool {
        matches!(*lock(&self.held), Some(Held::Reserve { .. }))
    }

    /// A record in the pool's pressure check of a request body arriving on
    /// this connection, counted from now; none for a body already ended.
    pub(super) fn count_body(&self, ended: bool) -> Option<(ObservedBody, BodyCredential)> {
        lock(&self.observed)
            .as_ref()
            .filter(|_| !ended)
            .map(ObservedSocket::body)
    }

    /// Resolves once the connection is parked.
    pub(super) async fn parked(&self) {
        loop {
            let parked = self.parked.notified();
            if matches!(*lock(&self.held), Some(Held::Parked { .. })) {
                return;
            }
            parked.await;
        }
    }

    /// The request in flight goes back to the floor: the reserve frees, the
    /// socket parks, and it waits in the floor's line, looking again after
    /// each wait as the accept loop does, until the floor admits it. From
    /// then on the connection holds a floor permit for the rest of its life.
    async fn park_for_floor(
        &self,
        floor: &Admission<()>,
        pressure: Option<&PoolPressure>,
        bound: usize,
    ) {
        {
            let mut held = lock(&self.held);
            match held.take() {
                Some(Held::Reserve { hold }) => {
                    *held = Some(Held::Parked {
                        _place: hold.park(),
                    });
                }
                other => {
                    *held = other;
                    return;
                }
            }
        }
        self.observe(SocketHold::Parked);
        self.parked.notify_waiters();
        let permit = loop {
            if let Ok(permit) = super::admit_observed(floor, pressure, bound).await {
                break permit;
            }
        };
        *lock(&self.held) = Some(Held::Floor { _permit: permit });
        self.observe(SocketHold::Floor);
    }

    fn observe(&self, hold: SocketHold) {
        if let Some(observed) = lock(&self.observed).as_ref() {
            observed.holds(hold);
        }
    }
}

/// What the API listener judges a request on the owner's reserve with.
#[derive(Clone)]
pub(super) struct OwnerGate {
    server: Arc<SyncServer>,
    floor: Admission<()>,
    pressure: Option<Arc<PoolPressure>>,
    /// The floor's bound, as its pressure check names it.
    bound: usize,
}

impl OwnerGate {
    pub(super) fn new(
        server: Arc<SyncServer>,
        floor: Admission<()>,
        pressure: Option<Arc<PoolPressure>>,
        bound: usize,
    ) -> Self {
        Self {
            server,
            floor,
            pressure,
            bound,
        }
    }

    /// Judges one request on a connection that holds the reserve, and
    /// returns the record its body counts under. The owner's proven read is
    /// served on the reserve. Any other request parks, unanswered, until the
    /// floor admits it; parked it holds no permit, so its body counts only
    /// from then. A probe's first request that is not his gives the reserve
    /// back and is shed instead (FIX 9130).
    pub(super) async fn admit(
        &self,
        custody: &Custody,
        parts: &mut Parts,
        ended: bool,
    ) -> Result<Option<(ObservedBody, BodyCredential)>, ProbeShed> {
        let probe = custody.probe.swap(false, Ordering::Relaxed);
        let counted = custody.count_body(ended);
        let credential = counted.as_ref().map(|(_, credential)| credential.clone());
        let owner = reserve_eligible(parts)
            && with_body_credential(
                credential,
                crate::auth::admit_owner_proof(&self.server, parts),
            )
            .await;
        if owner {
            custody.observe(SocketHold::Owner);
            return Ok(counted);
        }
        drop(counted);
        if probe {
            custody.release();
            tracing::debug!(
                reason = "stranger_owner_probe",
                "connection shed at its address's unauthenticated share"
            );
            return Err(ProbeShed);
        }
        custody
            .park_for_floor(&self.floor, self.pressure.as_deref(), self.bound)
            .await;
        Ok(custody.count_body(ended))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
