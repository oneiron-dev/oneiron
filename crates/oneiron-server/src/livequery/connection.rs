//! Socket attachment and bounded reconnect retention. RPC replies never enter
//! this registry. A fresh bind must match the complete verified CoreAuth.
use super::subscriptions::{LiveQueries, LiveQuerySource, Push};
use super::*;
use crate::server::SyncServer;
use oneiron::sync::bridge::LiveQueryTee;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

const RETENTION: Duration = Duration::from_secs(300);
const MAX_SESSIONS: usize = 64;

struct Session {
    auth: CoreAuth,
    queries: Arc<LiveQueries>,
    attached: AtomicU32,
    touched: Mutex<Instant>,
}

pub(crate) struct Hub {
    server: Weak<SyncServer>,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
}

impl Hub {
    pub(crate) fn for_server(server: &Arc<SyncServer>) -> Arc<Self> {
        static HUBS: OnceLock<Mutex<HashMap<usize, Weak<Hub>>>> = OnceLock::new();
        let mut hubs = HUBS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hubs.retain(|_, hub| hub.strong_count() != 0);
        let key = Arc::as_ptr(server) as usize;
        if let Some(hub) = hubs.get(&key).and_then(Weak::upgrade) {
            return hub;
        }
        let hub = Arc::new(Self {
            server: Arc::downgrade(server),
            sessions: Mutex::new(BTreeMap::new()),
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
            }
        });
        hub
    }

    fn refresh(&self) {
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        sessions.retain(|_, session| {
            let live = self.server.upgrade().is_some_and(|server| {
                !session.auth.jti().is_some_and(|jti| {
                    crate::auth::is_revoked_or_unreadable(jti, server.vault().as_ref())
                })
            });
            live && (session.attached.load(Ordering::Acquire) != 0
                || session
                    .touched
                    .lock()
                    .is_ok_and(|time| time.elapsed() < RETENTION))
        });
        let pending: Vec<_> = sessions.values().cloned().collect();
        drop(sessions);
        for session in pending {
            if let Err(error) = session.queries.refresh() {
                tracing::warn!(?error, "live-query refresh refused; resync required");
            }
        }
    }

    fn session(
        &self,
        auth: &CoreAuth,
        conn_id: u32,
        cursor: Option<&Cursor>,
    ) -> Result<Arc<Session>, AppError> {
        let mut sessions = self.sessions.lock().map_err(|_| unavailable())?;
        if let Some(session) = cursor.and_then(|cursor| sessions.get(&cursor.document)) {
            if &session.auth != auth {
                return Err(AppError::unauthorized());
            }
            session.attached.store(conn_id, Ordering::Release);
            session.queries.reconnect(conn_id)?;
            return Ok(session.clone());
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(AppError::bad_request(
                "live-query session limit exceeded",
                None,
            ));
        }
        let server = self.server.upgrade().ok_or_else(AppError::unauthorized)?;
        let document = oneiron::EntityId::now().to_hex();
        let source: Arc<dyn LiveQuerySource> = Arc::new(super::source::BoundSource::new(
            self.server.clone(),
            auth.clone(),
            document.clone(),
        ));
        let queries = Arc::new(LiveQueries::new(conn_id, source));
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
        let queries = Arc::new(LiveQueries::new(0, source));
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
                }),
            );
        queries
    }
}

pub(crate) struct Connection {
    hub: Arc<Hub>,
    conn_id: u32,
    session: Option<Arc<Session>>,
    active: BTreeSet<u64>,
    sent: BTreeMap<u64, (u64, BTreeSet<&'static str>)>,
}

impl Connection {
    pub(crate) fn new(hub: Arc<Hub>, conn_id: u32) -> Self {
        Self {
            hub,
            conn_id,
            session: None,
            active: BTreeSet::new(),
            sent: BTreeMap::new(),
        }
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
        match result {
            Ok(pushes) => self.frames(pushes),
            Err(error) => Ok(vec![sub_error(id, error)?]),
        }
    }

    fn apply(&mut self, auth: &CoreAuth, request: SubRequest) -> Result<Vec<Push>, AppError> {
        let id = request.id();
        let opening = matches!(&request, SubRequest::Open { .. });
        if self.session.is_none() {
            if let SubRequest::Open { cursor, .. } = &request {
                self.session = Some(self.hub.session(auth, self.conn_id, cursor.as_ref())?);
            } else if matches!(&request, SubRequest::Close { .. }) {
                return Ok(Vec::new());
            } else {
                return Err(AppError::not_found("subscription", None));
            }
        }
        let session = self.session.as_ref().ok_or_else(unavailable)?;
        if &session.auth != auth || session.attached.load(Ordering::Acquire) != self.conn_id {
            return Err(AppError::unauthorized());
        }
        if !opening && !self.active.contains(&id) {
            return Err(AppError::not_found("subscription", None));
        }
        let closing = matches!(&request, SubRequest::Close { .. });
        let pushes = session.queries.control(request)?;
        if opening {
            self.active.insert(id);
            self.sent.remove(&id);
        }
        if closing {
            self.active.remove(&id);
            self.sent.remove(&id);
        }
        Ok(pushes)
    }

    fn frames(&mut self, pushes: Vec<Push>) -> Result<Vec<Vec<u8>>, ProtocolError> {
        let mut frames = Vec::new();
        for push in pushes {
            frames.push(push.encode()?);
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
                self.active.contains(&push.subscription_id)
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
