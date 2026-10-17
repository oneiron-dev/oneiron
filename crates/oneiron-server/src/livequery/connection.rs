//! Socket attachment and bounded reconnect retention. RPC replies never enter
//! this registry. A fresh bind must match the complete verified CoreAuth.
//!
//! Sessions and subscriptions are rows, never refusals (rule 5): past either
//! row the next session or subscription waits its turn, round-robin across
//! principals, before the synchronous app tier runs, and a session waiting
//! its turn outranks a detached one kept only for a reconnect.
use super::subscriptions::{LiveQueries, LiveQuerySource, Push};
use super::*;
use crate::server::SyncServer;
use oneiron::memory::{MemorySubscriptionOwner, ScopedView};
use oneiron::sync::bridge::LiveQueryTee;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use crate::admission::{Admission, Permit};
use crate::wire_telemetry::LimitRow;

const RETENTION: Duration = Duration::from_secs(300);

struct Session {
    auth: CoreAuth,
    queries: Arc<LiveQueries>,
    attached: AtomicU32,
    touched: Mutex<Instant>,
    /// The session's turn under `limits.live_sessions`, held while the hub
    /// keeps it; a revoked session gives it back at once.
    turn: Mutex<Option<Permit>>,
}

pub(crate) struct Hub {
    server: Weak<SyncServer>,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    budget: Arc<super::budget::Budget>,
    session_line: Admission<String>,
    subscription_line: Admission<String>,
}

// GLOBAL STATE: one live-query hub per running server, keyed by the server's
// address. A hub holds its server weakly and lives while that server does.
static HUBS: OnceLock<Mutex<HashMap<usize, Weak<Hub>>>> = OnceLock::new();

impl Hub {
    pub(crate) fn for_server(server: &Arc<SyncServer>) -> Arc<Self> {
        let mut hubs = HUBS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hubs.retain(|_, hub| hub.strong_count() != 0);
        let key = Arc::as_ptr(server) as usize;
        if let Some(hub) = hubs.get(&key).and_then(Weak::upgrade) {
            return hub;
        }
        let limits = &server.config.limits;
        let questions = Arc::clone(server.wire_telemetry.limit_questions());
        let hub = Arc::new(Self {
            server: Arc::downgrade(server),
            sessions: Mutex::new(BTreeMap::new()),
            budget: super::budget::Budget::new(Arc::clone(&server.retained), questions.clone()),
            session_line: Admission::new(
                LimitRow::LiveSessions,
                questions.clone(),
                limits.live_sessions,
                limits.queue_wait(),
            ),
            subscription_line: Admission::new(
                LimitRow::LiveSubscriptions,
                questions,
                limits.live_subscriptions,
                limits.queue_wait(),
            ),
        });
        hubs.insert(key, Arc::downgrade(&hub));
        let worker = hub.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(25));
            loop {
                tick.tick().await;
                if worker.server.strong_count() == 0 {
                    break;
                }
                worker.refresh();
                // Refolding live authority can exceed one period. Do not replay
                // overdue checks in a continuously-ready catch-up loop that
                // starves socket I/O; inspect current state again after a pause.
                tick.reset();
            }
        });
        hub
    }

    /// The served handle of `server`, through the hub its sockets share: the
    /// app tier's synchronous RPC door holds only `&SyncServer`, and the
    /// facade dispatch it runs takes the handle its server and host doors
    /// take. `None` for a server no socket has opened a hub for.
    pub(crate) fn served(server: &SyncServer) -> Option<Arc<SyncServer>> {
        let hubs = HUBS
            .get()?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let served = hubs
            .get(&(std::ptr::from_ref(server) as usize))?
            .upgrade()?
            .server
            .upgrade()?;
        std::ptr::eq(Arc::as_ptr(&served), server).then_some(served)
    }

    fn refresh(&self) {
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        sessions.retain(|_, session| {
            let live = self
                .server
                .upgrade()
                .is_some_and(|server| session.auth.credential_is_live(server.vault().as_ref()));
            if !live {
                // A socket may still hold the session; its turn is not its own.
                session
                    .turn
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
            }
            live && (session.attached.load(Ordering::Acquire) != 0
                || session
                    .touched
                    .lock()
                    .is_ok_and(|time| time.elapsed() < RETENTION))
        });
        // Work waiting its turn outranks a session kept only for a
        // reconnect: the detached session kept longest goes, with its
        // subscriptions, and its reconnect gets a fresh snapshot.
        for _ in 0..self.session_line.waiting() + self.subscription_line.waiting() {
            let oldest = sessions
                .iter()
                .filter(|(_, session)| session.attached.load(Ordering::Acquire) == 0)
                .min_by_key(|(_, session)| session.touched.lock().map_or(Instant::now(), |at| *at))
                .map(|(document, _)| document.clone());
            let Some(document) = oldest else {
                break;
            };
            sessions.remove(&document);
        }
        let pending: Vec<_> = sessions.values().cloned().collect();
        drop(sessions);
        for session in pending {
            if let Err(_error) = session.queries.refresh() {
                tracing::warn!(
                    reason = "live_query_refresh_refused",
                    "live-query refresh refused; resync required"
                );
            }
        }
    }

    /// Indexed publication happens after the vault transaction commits, not
    /// in Observer B. Feed only the published entity ids through the existing
    /// dependency index; neither unindexed edits nor raw documents are pushed.
    pub(crate) fn indexed_published(&self, publications: &[oneiron::memory::IndexedPublication]) {
        let sessions: Vec<_> = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(|session| Arc::clone(&session.queries))
            .collect();
        for publication in publications {
            for queries in &sessions {
                queries.on_indexed_published(*publication);
            }
        }
    }

    /// Sessions and subscriptions waiting for their turn now.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> (usize, usize) {
        (
            self.session_line.waiting(),
            self.subscription_line.waiting(),
        )
    }

    /// The session the hub keeps under `document`.
    fn kept(&self, document: &str) -> Option<Arc<Session>> {
        self.sessions.lock().ok()?.get(document).cloned()
    }

    fn session(
        &self,
        auth: &CoreAuth,
        conn_id: u32,
        cursor: Option<&Cursor>,
        turn: Option<Permit>,
        resumed: Option<(String, Arc<Session>)>,
    ) -> Result<Arc<Session>, AppError> {
        let mut sessions = self.sessions.lock().map_err(|_| unavailable())?;
        let mut found = cursor.and_then(|cursor| sessions.get(&cursor.document).cloned());
        if found.is_none()
            && let (Some(cursor), Some((document, session))) = (cursor, resumed)
            && document == cursor.document
        {
            // The hub let the session go while this resume waited for its
            // turn; pinned by the resume, it kept its turns and comes back.
            sessions.insert(document, Arc::clone(&session));
            found = Some(session);
        }
        if let Some(session) = found {
            if !session.auth.same_authority(auth) {
                return Err(AppError::unauthorized());
            }
            session.attached.store(conn_id, Ordering::Release);
            session.queries.reconnect(conn_id)?;
            return Ok(session);
        }
        let server = self.server.upgrade().ok_or_else(AppError::unauthorized)?;
        let limits = server
            .vault()
            .policy_livequery_tracker_limits(auth.principal_ref())
            .map_err(|_| AppError::internal_server_error("livequery tracker policy refused"))?;
        let document = oneiron::EntityId::now().to_hex();
        let source: Arc<dyn LiveQuerySource> = Arc::new(super::source::BoundSource::with_budget(
            self.server.clone(),
            auth.clone(),
            document.clone(),
            self.budget.clone(),
        ));
        let queries = Arc::new(LiveQueries::with_budget_limits(
            conn_id,
            source,
            self.budget.clone(),
            limits,
        ));
        let tee: Arc<dyn LiveQueryTee> = queries.clone();
        server
            .reassert_manager
            .materializer()
            .attach_live_query_tee(&tee);
        let session = Arc::new(Session {
            auth: auth.clone(),
            queries,
            attached: AtomicU32::new(conn_id),
            touched: Mutex::new(Instant::now()),
            turn: Mutex::new(turn),
        });
        sessions.insert(document, session.clone());
        Ok(session)
    }

    #[cfg(test)]
    pub(crate) fn install_source(
        &self,
        auth: CoreAuth,
        document: String,
        source: Arc<dyn LiveQuerySource>,
    ) -> Arc<LiveQueries> {
        let queries = Arc::new(LiveQueries::with_budget(0, source, self.budget.clone()));
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                document,
                Arc::new(Session {
                    auth,
                    queries: queries.clone(),
                    attached: AtomicU32::new(0),
                    touched: Mutex::new(Instant::now()),
                    turn: Mutex::new(None),
                }),
            );
        queries
    }
}

// The socket keeps channel, cursor and origin; the engine facade supplies the
// actor-bound subscription verb without taking ownership of socket state.
struct SocketOwner<'a> {
    queries: &'a LiveQueries,
    channel: Channel,
    cursor: Option<Cursor>,
    origin: Option<String>,
    /// The turn a new subscription takes under `limits.live_subscriptions`.
    turn: std::cell::Cell<Option<Permit>>,
}

impl MemorySubscriptionOwner for SocketOwner<'_> {
    type Delivery = Vec<Push>;
    type Error = AppError;

    fn open(&self, id: u64, view: ScopedView) -> Result<Self::Delivery, Self::Error> {
        self.queries.open_in_turn(
            id,
            view,
            self.channel,
            self.cursor.as_ref(),
            self.origin.clone(),
            self.turn.take(),
        )
    }

    fn close(&self, id: u64) -> Result<(), Self::Error> {
        self.queries.close(id)
    }
}

pub(crate) struct Connection {
    hub: Arc<Hub>,
    conn_id: u32,
    session: Option<Arc<Session>>,
    /// Each open subscription and its incarnation. A frame queued for an
    /// earlier incarnation of the same id is never sent.
    active: BTreeMap<u64, u64>,
    incarnations: u64,
    sent: BTreeMap<u64, (u64, BTreeSet<&'static str>)>,
    /// Subscriptions whose queued body the release withheld: nothing more
    /// of theirs leaves before the gap that retires them.
    withheld: BTreeSet<u64>,
    /// Requests whose result the release refused: no later chunk of it
    /// leaves.
    refused: BTreeSet<u64>,
    /// Turns taken for the next request by [`Self::admit`]: a new session's
    /// and a new subscription's.
    session_turn: Option<Permit>,
    subscription_turn: Option<Permit>,
    /// The turn an open subscription holds, taken while its reopen runs so a
    /// close elsewhere cannot free it, and given back after.
    held_turn: Option<(Arc<Session>, u64, Permit)>,
    /// The kept session a resume names, pinned while the resume waits.
    resumed: Option<(String, Arc<Session>)>,
    /// The next request waited for a turn past its deadline.
    waited_out: bool,
}

impl Connection {
    pub(crate) fn new(hub: Arc<Hub>, conn_id: u32) -> Self {
        Self {
            hub,
            conn_id,
            session: None,
            active: BTreeMap::new(),
            incarnations: 0,
            sent: BTreeMap::new(),
            withheld: BTreeSet::new(),
            refused: BTreeSet::new(),
            session_turn: None,
            subscription_turn: None,
            held_turn: None,
            resumed: None,
            waited_out: false,
        }
    }

    /// Waits for the turns a subscription request needs, before the
    /// synchronous app tier runs it: a new session's under
    /// `limits.live_sessions` and a new subscription's under
    /// `limits.live_subscriptions`, each in its principal's place in line. A
    /// request that needs neither, or does not decode, waits for nothing.
    pub(crate) async fn admit(&mut self, auth: Option<&CoreAuth>, payload: &[u8]) {
        self.give_back();
        self.session_turn = None;
        self.subscription_turn = None;
        self.resumed = None;
        self.waited_out = false;
        let (
            Some(auth),
            Ok(SubRequest::Open {
                subscription_id,
                cursor,
                ..
            }),
        ) = (auth, decode_sub(payload))
        else {
            return;
        };
        let key = auth.principal_ref().unwrap_or(auth.principal()).to_owned();
        // A resume names the session it continues; pinned here, that session
        // keeps its turns while this request waits.
        let session = self.session.clone().or_else(|| {
            let cursor = cursor?;
            let session = self
                .hub
                .kept(&cursor.document)
                .filter(|session| session.auth.same_authority(auth))?;
            self.resumed = Some((cursor.document, Arc::clone(&session)));
            Some(session)
        });
        if session.is_none() {
            match self.hub.session_line.admit(key.clone()).await {
                Ok(turn) => self.session_turn = Some(turn),
                Err(_) => {
                    self.waited_out = true;
                    return;
                }
            }
        }
        // A subscription the session already holds keeps its own turn.
        if let Some(session) = session
            && let Some(turn) = session.queries.take_turn(subscription_id)
        {
            self.held_turn = Some((session, subscription_id, turn));
            return;
        }
        match self.hub.subscription_line.admit(key).await {
            Ok(turn) => self.subscription_turn = Some(turn),
            Err(_) => self.waited_out = true,
        }
    }

    /// Gives the turn [`Self::admit`] took from an open subscription back
    /// to it.
    fn give_back(&mut self) {
        if let Some((session, id, turn)) = self.held_turn.take() {
            session.queries.give_turn(id, turn);
        }
    }

    /// The document naming this socket's session, which a resume carries.
    #[cfg(test)]
    pub(crate) fn session_document(&self) -> Option<String> {
        let session = self.session.as_ref()?;
        let sessions = self.hub.sessions.lock().ok()?;
        sessions
            .iter()
            .find(|(_, kept)| Arc::ptr_eq(kept, session))
            .map(|(document, _)| document.clone())
    }

    /// Whether subscription `id` is open on this socket.
    #[cfg(test)]
    pub(crate) fn opened(&self, id: u64) -> bool {
        self.active.contains_key(&id)
    }

    pub(crate) fn control(
        &mut self,
        auth: &CoreAuth,
        request: SubRequest,
    ) -> Result<Vec<Vec<u8>>, ProtocolError> {
        let id = request.id();
        let result = auth
            .require(CoreScope::Read)
            .map_err(AppError::from)
            .and_then(|()| self.apply(auth, request));
        // A turn the request did not use goes back to its line.
        self.give_back();
        self.session_turn = None;
        self.subscription_turn = None;
        self.resumed = None;
        self.waited_out = false;
        match result {
            Ok(pushes) => self.frames(pushes),
            Err(error) => Ok(vec![sub_error(id, error)?]),
        }
    }

    fn apply(&mut self, auth: &CoreAuth, request: SubRequest) -> Result<Vec<Push>, AppError> {
        let id = request.id();
        let opening = matches!(&request, SubRequest::Open { .. });
        if opening && std::mem::take(&mut self.waited_out) {
            return Err(AppError::waited_out());
        }
        if self.session.is_none() {
            if let SubRequest::Open { cursor, .. } = &request {
                self.session = Some(self.hub.session(
                    auth,
                    self.conn_id,
                    cursor.as_ref(),
                    self.session_turn.take(),
                    self.resumed.take(),
                )?);
            } else if matches!(&request, SubRequest::Close { .. }) {
                return Ok(Vec::new());
            } else {
                return Err(AppError::not_found("subscription", None));
            }
        }
        let session = self.session.as_ref().ok_or_else(unavailable)?;
        if !session.auth.same_authority(auth)
            || session.attached.load(Ordering::Acquire) != self.conn_id
        {
            return Err(AppError::unauthorized());
        }
        if !opening && !self.active.contains_key(&id) {
            return Err(AppError::not_found("subscription", None));
        }
        let closing = matches!(&request, SubRequest::Close { .. });
        let pushes = match request {
            SubRequest::Open {
                scoped_view,
                channel,
                cursor,
                origin,
                ..
            } => {
                let server = self.hub.server.upgrade().ok_or_else(unavailable)?;
                let memory = bound_memory(server.vault(), auth)?;
                memory.subscribe(
                    &SocketOwner {
                        queries: &session.queries,
                        channel,
                        cursor,
                        origin,
                        turn: std::cell::Cell::new(self.subscription_turn.take()),
                    },
                    id,
                    scoped_view,
                )?
            }
            SubRequest::Close { .. } => {
                let server = self.hub.server.upgrade().ok_or_else(unavailable)?;
                let memory = bound_memory(server.vault(), auth)?;
                memory.unsubscribe(
                    &SocketOwner {
                        queries: &session.queries,
                        channel: Channel::View,
                        cursor: None,
                        origin: None,
                        turn: std::cell::Cell::new(None),
                    },
                    id,
                )?;
                Vec::new()
            }
            request => session.queries.control(request)?,
        };
        if opening {
            self.incarnations += 1;
            self.active.insert(id, self.incarnations);
            self.sent.remove(&id);
            self.withheld.remove(&id);
        }
        if closing {
            self.active.remove(&id);
            self.sent.remove(&id);
            self.withheld.remove(&id);
        }
        Ok(pushes)
    }

    /// Each push's frames, routed to this socket's release with the
    /// subscription's incarnation and the rows the push was derived from.
    fn frames(&mut self, pushes: Vec<Push>) -> Result<Vec<Vec<u8>>, ProtocolError> {
        let mut frames = Vec::new();
        for push in pushes {
            let incarnation = self.active.get(&push.subscription_id).copied();
            frames.extend(push.encode()?.into_iter().map(|frame| {
                super::routing::wrap(
                    self.conn_id,
                    push.subscription_id,
                    incarnation.unwrap_or_default(),
                    Some(push.rows.as_slice()),
                    frame,
                )
            }));
            let entry = self
                .sent
                .entry(push.subscription_id)
                .or_insert_with(|| (push.cursor.batch, BTreeSet::new()));
            if entry.0 != push.cursor.batch {
                *entry = (push.cursor.batch, BTreeSet::new());
            }
            entry.1.insert(push.kind);
        }
        Ok(frames)
    }

    pub(crate) const fn conn_id(&self) -> u32 {
        self.conn_id
    }

    pub(crate) fn is_scoped_broadcast(data: &[u8]) -> bool {
        super::routing::is_routed(data)
    }

    /// The frame a queued app frame releases to this socket, judged at its
    /// last door before the send (DEC-0005), whether it was queued as a
    /// reply or as a broadcast copy.
    ///
    /// A subscription frame of a closed or reopened incarnation is dropped:
    /// a replacement is never judged in its place. A body that names a row
    /// a device-local world keeps from a caller at `locality` now, by the
    /// rows its producer listed, stays unsent. Its subscription is retired
    /// for a gap and sends nothing more before it, and a read result is
    /// refused. A body whose producer could not list its rows fails closed.
    #[cfg(test)]
    pub(crate) fn release(
        &mut self,
        locality: oneiron::claim::CallerLocality,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        self.release_for(locality, oneiron::authority::PeerMachine::Unknown, data)
    }

    /// [`Self::release`] for the machine `peer` proved on the socket: a row
    /// is judged by that machine's own world read settings (OF-534 G6).
    pub(crate) fn release_for(
        &mut self,
        locality: oneiron::claim::CallerLocality,
        peer: oneiron::authority::PeerMachine,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let routed = super::routing::addressed(data, self.conn_id)?;
        let envelope = super::wire::decode::<serde::de::IgnoredAny>(&routed.frame[1..]).ok();
        if routed.frame[0] == crate::protocol::TAG_RPC {
            return self.release_reply(locality, peer, &routed, envelope.as_ref());
        }
        let session = self.session.as_ref()?;
        if self.active.get(&routed.id) != Some(&routed.incarnation)
            || session.attached.load(Ordering::Acquire) != self.conn_id
        {
            return None;
        }
        let kind = envelope.as_ref().map(|envelope| envelope.kind.as_str());
        if self.withheld.contains(&routed.id) {
            if kind != Some("sub.gap") {
                return None;
            }
            self.withheld.remove(&routed.id);
        } else if kind.is_none_or(|kind| matches!(kind, "sub.data" | "sub.snapshot"))
            && self.withholds(locality, peer, routed.rows.as_deref(), routed.frame)
        {
            if session.queries.retire(routed.id).is_err() {
                tracing::warn!("live-query retirement refused; resync required");
            }
            self.withheld.insert(routed.id);
            return None;
        }
        Some(routed.frame.to_vec())
    }

    /// A read result's chunk, or the refusal that replaces the rest of it.
    fn release_reply(
        &mut self,
        locality: oneiron::claim::CallerLocality,
        peer: oneiron::authority::PeerMachine,
        routed: &super::routing::Routed<'_>,
        envelope: Option<&super::wire::Envelope<serde::de::IgnoredAny>>,
    ) -> Option<Vec<u8>> {
        let last = envelope.is_none_or(|envelope| envelope.last);
        if self.refused.contains(&routed.id) {
            if last {
                self.refused.remove(&routed.id);
            }
            return None;
        }
        if !self.withholds(locality, peer, routed.rows.as_deref(), routed.frame) {
            return Some(routed.frame.to_vec());
        }
        if !last {
            self.refused.insert(routed.id);
        }
        // The refusal that replaces the result states the same call receipt.
        let stamp = envelope.map_or(
            crate::api::call_receipt::CallStamp::Unrecorded,
            |envelope| envelope.call_stamp(),
        );
        super::rpc_error(routed.id, AppError::result_changed(), &stamp)
            .ok()?
            .pop()
    }

    /// Whether a queued body stays on this device: see [`Self::release`].
    fn withholds(
        &self,
        locality: oneiron::claim::CallerLocality,
        peer: oneiron::authority::PeerMachine,
        rows: Option<&[oneiron::EntityId]>,
        frame: &[u8],
    ) -> bool {
        if locality == oneiron::claim::CallerLocality::OnDevice {
            return false;
        }
        let (Some(rows), Some(server)) = (rows, self.hub.server.upgrade()) else {
            return true;
        };
        crate::device_local::withholds_retained_for(server.vault(), locality, peer, rows, frame)
            .unwrap_or(true)
    }

    pub(crate) fn replay_after_lag(&mut self) {
        self.sent.clear();
    }

    /// What [`Self::delivery`] routes through the shared broadcast channel.
    pub(crate) fn broadcast_delivery(&mut self) -> Result<Vec<Vec<u8>>, ProtocolError> {
        self.delivery()
    }

    pub(crate) fn has_active_subscriptions(&self) -> bool {
        !self.active.is_empty()
    }

    pub(crate) fn delivery(&mut self) -> Result<Vec<Vec<u8>>, ProtocolError> {
        let Some(session) = self.session.as_ref() else {
            return Ok(Vec::new());
        };
        if session.attached.load(Ordering::Acquire) != self.conn_id {
            return Err(ProtocolError::RpcNoPrincipal);
        }
        let buffered = session
            .queries
            .buffered()
            .map_err(|_| ProtocolError::InvalidPayload("live-query buffer unavailable"))?;
        let pushes = buffered
            .into_iter()
            .filter(|push| {
                self.active.contains_key(&push.subscription_id)
                    && self
                        .sent
                        .get(&push.subscription_id)
                        .is_none_or(|(batch, kinds)| {
                            push.cursor.batch > *batch
                                || (push.cursor.batch == *batch && !kinds.contains(push.kind))
                        })
            })
            .collect();
        self.frames(pushes)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.give_back();
        if let Some(session) = &self.session
            && session
                .attached
                .compare_exchange(self.conn_id, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            && let Ok(mut touched) = session.touched.lock()
        {
            *touched = Instant::now();
        }
    }
}

fn unavailable() -> AppError {
    AppError::internal_server_error("live-query owner unavailable")
}
