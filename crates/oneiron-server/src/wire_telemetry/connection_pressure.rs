//! The shared connection pool's live pressure check (FIX 7656, OF-520). When
//! a socket finds the descriptor floor full and has to wait, the owner's
//! `/v1/owner/wire-health` shows one typed "is everything okay" check: the
//! credentials whose open request bodies hold the most connections, how long
//! and how fast, and what the owner can do. It clears when nobody waits.
//!
//! Observation only: it holds no permit and cuts, refuses or slows nothing.
//! The floor, its fair line and the body idle clock stay the listener's. A
//! request body counts from its headers to its last frame, end, error or
//! drop, or until its socket closes, under the slip or account key its
//! request was accepted on; a body no accepted credential is attached to
//! counts as unattributed. Nothing samples on a timer: frames count their
//! bytes as they arrive, and a read works out the rest. It lives in this
//! process only, as the sockets it counts do.
//!
//! It also counts the pool's open connections by how each holds it: a floor
//! permit, the owner's one reserve beside the floor, or a place parked
//! beside it while the floor's line is awaited (FIX 8274). A connection
//! counts there with or without a request body open.
//!
//! A managed relay locker keeps the same check over its own connections
//! (FIX 7739, [`PoolPressure::relay_locker`]). It has no floor to wait for
//! and no owner reserve: its check is raised while its open connections are
//! as many as the public listener's floor would hold, and names its own
//! remedy.
//!
//! The mesh listener's sync streams keep one of their own (FIX 7737,
//! [`PoolPressure::mesh`]): raised while a stream waits for a place under
//! the mesh's connection floor, each stream counted under `floor` and its
//! bytes under the MACHINE its connection proved. It has no owner reserve.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use serde::Serialize;

use super::{LimitRow, WireQuestionKind, lock};

/// Most credentials one reading names, most connections first. It bounds
/// the list only: every open body is counted, and the connections of the
/// credentials past it are summed in `other_credential_open_body_permits`.
const MAX_PRESSURE_CREDENTIALS: usize = 16;

/// Connections the owner's reserve keeps beside the floor (FIX 8274). They
/// are never counted in the floor's bound.
const OWNER_RESERVE_CONNECTIONS: u64 = 1;

/// What a relay locker's operator can do, and what its check does not
/// promise (FIX 7739).
const RELAY_LOCKER_REMEDY: &str = "Is everything okay? This relay locker holds as many open connections as a vault's public listener holds at its descriptor floor. Its open request bodies are uploads under the room's one access token. If they are not the room's own devices, rotate the room's access token file and restart the room. This check does not cut an upload or refuse a connection.";

/// What the owner can do about the mesh's streams, and what its check does
/// not promise (FIX 7737).
const MESH_REMEDY: &str = r#"Is everything okay? A mesh sync stream waits for a place. The listed machines hold the most open streams; each counts every byte its peer sent on them, requests and upgraded sockets alike. Pause the sync client on a listed machine, or remove the machine with POST /v1/owner/machines/remove, passing {"machine":"<machine_id>","seen":"<revision from GET /v1/owner/machines/answer>"}. This check does not cut a stream or refuse a connection."#;

/// What the owner can do, and what the check does not promise.
const REMEDY: &str = r#"Is everything okay? This connection pool has a waiter. The listed credential keys hold the most open request bodies. Pause the client using a listed key, or revoke its credential. For a slip key, revoke with POST /v1/core/slips/revoke, passing {"slip_id":[32 bytes decoded from the listed hex ID]}. For an engine-run client, its existing pause door is POST /v1/core/facade/vault.runs.pause with {"branch":"<attempt-id>"}; that pauses a run branch, not a credential. Account-key pause/revoke belongs to the host control plane. This check does not cut a body or guarantee that revocation releases an already-open body."#;

/// The pool's pressure as the owner reads it now.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum ConnectionPoolPressure {
    /// Nobody waits for the pool.
    Clear,
    /// A socket waits for the pool: this episode's check.
    Active { check: ConnectionPoolPressureCheck },
}

/// One episode of waiting for the pool, as it stands when read.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ConnectionPoolPressureCheck {
    /// Always `inspect_connection_pool_pressure`.
    kind: WireQuestionKind,
    /// Which episode this is, in this process: from the first socket that
    /// had to wait until nobody waits.
    episode: u64,
    /// When its first socket found it had to wait, unix seconds.
    episode_started_at: u64,
    /// When this reading was taken, unix seconds.
    sampled_at: u64,
    /// The `[limits]` row the pool is: `limits.max_connections`.
    row: String,
    /// What the row is set to: connections open at once.
    bound: u64,
    /// The credentials holding the most connections with a request body
    /// open, most first.
    top_credentials: Vec<CredentialBodyPressure>,
    /// Connections with an open body that credentials past the list hold.
    other_credential_open_body_permits: u64,
    /// Connections with an open body no accepted credential is attached to.
    unattributed_open_body_permits: u64,
    /// The pool's open connections now, by how each holds it.
    connections: PoolConnections,
    /// Connections the owner's reserve keeps beside the floor: one, never
    /// counted in `bound`.
    reserve_bound: u64,
    /// How many sockets may wait parked beside the floor at once: the
    /// floor's own bound.
    parking_bound: u64,
    remedy: String,
}

/// The pool's open connections by how each holds it (FIX 8274).
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct PoolConnections {
    /// Connections holding a floor permit. Guests' network work may hold
    /// the floor's other permits.
    floor: u64,
    /// The connection on the owner's reserve whose latest request was his
    /// proven read, served or idle since: 0 or 1.
    reserve_owner: u64,
    /// The connection on the owner's reserve whose request is not judged
    /// yet: 0 or 1.
    reserve_classifying: u64,
    /// Sockets whose request went back from the reserve to wait for the
    /// floor. They hold no permit, and their bodies count only once the
    /// floor admits them.
    parked: u64,
}

impl PoolConnections {
    fn count(&mut self, hold: SocketHold) -> &mut u64 {
        match hold {
            SocketHold::Floor => &mut self.floor,
            SocketHold::Owner => &mut self.reserve_owner,
            SocketHold::Classifying => &mut self.reserve_classifying,
            SocketHold::Parked => &mut self.parked,
        }
    }
}

/// How a connection holds the pool, as the check counts it (FIX 8274).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketHold {
    /// A floor permit.
    Floor,
    /// The owner's reserve, its latest request his proven read.
    Owner,
    /// The owner's reserve, its request not judged yet.
    Classifying,
    /// Parked beside the floor, in its line, holding no permit.
    Parked,
}

/// One credential's open request bodies.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct CredentialBodyPressure {
    credential_key: PressureCredentialKey,
    /// Connections it holds with a request body open.
    open_body_permits: u64,
    /// When its oldest open body began, unix seconds.
    oldest_body_started_at: u64,
    /// How long that body has been open, in milliseconds.
    held_ms: u64,
    /// Each open body's bytes so far over its time open, summed: a lifetime
    /// average, not a current rate.
    bytes_per_second: f64,
}

/// The id a credential is revoked by, never the credential itself.
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum PressureCredentialKey {
    /// A capability slip, by its mint id: 64 lowercase hex.
    Slip { slip_id: String },
    /// An account API key the host's control plane verified, by its key id.
    AccountKey { key_id: String },
    /// A paired machine on the mesh listener, by its MACHINE id: 32
    /// lowercase hex (FIX 7737).
    #[cfg_attr(not(feature = "mesh"), allow(dead_code))] // Only the mesh listener names one.
    Machine { machine_id: String },
}

/// The check one pool keeps: the episode on show and every open body.
#[derive(Default)]
pub(crate) struct PoolPressure {
    /// Whose connections it counts.
    pool: PoolKind,
    episodes: Mutex<Episodes>,
    /// Each open body, by its socket's id and its own.
    bodies: Mutex<BTreeMap<(u64, u64), Arc<BodyRecord>>>,
    /// The open connections, by how each holds the pool.
    connections: Mutex<PoolConnections>,
    /// The next socket or body id.
    next: AtomicU64,
}

/// Whose connections a check counts.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PoolKind {
    /// A vault server's listeners: raised while a socket waits for the
    /// floor, with the owner's reserve beside it.
    #[default]
    Listener,
    /// A relay locker's: raised while its open connections are as many as
    /// the listener's floor, each counted under `floor`; it has no floor
    /// and no reserve (FIX 7739).
    RelayLocker,
    /// The mesh listener's sync streams: raised while one waits for a place
    /// under its floor, each counted under `floor`; no reserve (FIX 7737).
    Mesh,
}

#[derive(Default)]
struct Episodes {
    /// The episode on show, if one is.
    active: Option<Episode>,
    /// The latest crossing the line said was over: none up to it raises.
    drained: u64,
}

#[derive(Clone, Copy)]
struct Episode {
    /// The floor's crossing ([`oneiron::work_line::WorkLine::crossing_epoch`]).
    epoch: u64,
    started_at: u64,
    bound: u64,
}

/// One request body as it arrives.
struct BodyRecord {
    started_at: u64,
    started: Instant,
    bytes: AtomicU64,
    /// The credential its request was first accepted on.
    key: OnceLock<PressureCredentialKey>,
}

impl PoolPressure {
    /// A relay locker's check (FIX 7739).
    pub(crate) fn relay_locker() -> Arc<Self> {
        Arc::new(Self {
            pool: PoolKind::RelayLocker,
            ..Self::default()
        })
    }

    /// The mesh listener's sync streams' check (FIX 7737).
    pub(crate) fn mesh() -> Arc<Self> {
        Arc::new(Self {
            pool: PoolKind::Mesh,
            ..Self::default()
        })
    }

    /// A socket waits for the pool in the floor's crossing `epoch`, the
    /// floor set to `bound`: the check is raised, once for the crossing. A
    /// crossing already over, or older than the one on show, raises nothing.
    pub(crate) fn raise(&self, epoch: u64, bound: u64) {
        let mut episodes = lock(&self.episodes);
        if epoch <= episodes.drained || episodes.active.is_some_and(|active| active.epoch >= epoch)
        {
            return;
        }
        episodes.active = Some(Episode {
            epoch,
            started_at: oneiron_vault_contract::now_ts(),
            bound,
        });
        drop(episodes);
        let said = match self.pool {
            PoolKind::Listener => "a connection waits for the connection pool; is everything okay?",
            PoolKind::RelayLocker => {
                "the relay locker holds as many connections as a descriptor floor; is everything okay?"
            }
            PoolKind::Mesh => "a mesh sync stream waits for a place; is everything okay?",
        };
        tracing::warn!(
            kind = "connection_pool_pressure",
            episode = epoch,
            bound,
            "{said}"
        );
    }

    /// Nobody waits since the floor's crossing `epoch`: its check clears.
    pub(crate) fn drain(&self, epoch: u64) {
        let mut episodes = lock(&self.episodes);
        episodes.drained = episodes.drained.max(epoch);
        let cleared = episodes.active.filter(|active| active.epoch <= epoch);
        if cleared.is_some() {
            episodes.active = None;
        }
        drop(episodes);
        if let Some(cleared) = cleared {
            tracing::info!(
                kind = "connection_pool_pressure",
                episode = cleared.epoch,
                "nobody waits for the connection pool now; its check is clear"
            );
        }
    }

    /// A newly admitted socket's place in the check, holding the pool as
    /// `hold`.
    pub(crate) fn socket(self: &Arc<Self>, hold: SocketHold) -> ObservedSocket {
        *lock(&self.connections).count(hold) += 1;
        ObservedSocket {
            pressure: Arc::clone(self),
            socket: self.next.fetch_add(1, Ordering::Relaxed),
            hold: Mutex::new(hold),
        }
    }

    /// The check as it stands now.
    pub(crate) fn snapshot(&self) -> ConnectionPoolPressure {
        let Some(episode) = lock(&self.episodes).active else {
            return ConnectionPoolPressure::Clear;
        };
        let now = Instant::now();
        let mut held: BTreeMap<Option<PressureCredentialKey>, Held> = BTreeMap::new();
        let bodies = lock(&self.bodies);
        for (&(socket, _), body) in &*bodies {
            let key = body.key.get().cloned();
            held.entry(key).or_default().count(socket, body, now);
        }
        drop(bodies);
        let unattributed = held.remove(&None).map_or(0, |held| held.permits());
        let mut credentials: Vec<CredentialBodyPressure> = held
            .into_iter()
            .filter_map(|(key, held)| Some(held.row(key?, now)))
            .collect();
        credentials.sort_by(|a, b| {
            b.open_body_permits
                .cmp(&a.open_body_permits)
                .then(b.held_ms.cmp(&a.held_ms))
                .then_with(|| a.credential_key.cmp(&b.credential_key))
        });
        let other: u64 = credentials
            .iter()
            .skip(MAX_PRESSURE_CREDENTIALS)
            .map(|row| row.open_body_permits)
            .sum();
        credentials.truncate(MAX_PRESSURE_CREDENTIALS);
        let connections = lock(&self.connections).clone();
        let (reserve_bound, parking_bound, remedy) = match self.pool {
            PoolKind::Listener => (OWNER_RESERVE_CONNECTIONS, episode.bound, REMEDY),
            PoolKind::RelayLocker => (0, 0, RELAY_LOCKER_REMEDY),
            PoolKind::Mesh => (0, 0, MESH_REMEDY),
        };
        ConnectionPoolPressure::Active {
            check: ConnectionPoolPressureCheck {
                kind: WireQuestionKind::InspectConnectionPoolPressure,
                episode: episode.epoch,
                episode_started_at: episode.started_at,
                sampled_at: oneiron_vault_contract::now_ts(),
                row: LimitRow::Connections.key().to_owned(),
                bound: episode.bound,
                top_credentials: credentials,
                other_credential_open_body_permits: other,
                unattributed_open_body_permits: unattributed,
                connections,
                reserve_bound,
                parking_bound,
                remedy: remedy.to_owned(),
            },
        }
    }
}

/// One credential's open bodies, as a reading counts them.
#[derive(Default)]
struct Held {
    /// The sockets they arrive on: one connection each, however many
    /// bodies it carried.
    sockets: BTreeSet<u64>,
    /// The oldest body's start, as an instant and in unix seconds.
    oldest: Option<(Instant, u64)>,
    bytes_per_second: f64,
}

impl Held {
    fn count(&mut self, socket: u64, body: &BodyRecord, now: Instant) {
        self.sockets.insert(socket);
        if self
            .oldest
            .is_none_or(|(started, _)| body.started < started)
        {
            self.oldest = Some((body.started, body.started_at));
        }
        // A body open no time yet adds nothing until time has passed.
        let open = now.saturating_duration_since(body.started).as_secs_f64();
        if open > 0.0 {
            self.bytes_per_second += body.bytes.load(Ordering::Relaxed) as f64 / open;
        }
    }

    fn permits(&self) -> u64 {
        self.sockets.len() as u64
    }

    fn row(self, credential_key: PressureCredentialKey, now: Instant) -> CredentialBodyPressure {
        let (started, oldest_body_started_at) = self.oldest.unwrap_or((now, 0));
        let held = now.saturating_duration_since(started).as_millis();
        CredentialBodyPressure {
            credential_key,
            open_body_permits: self.permits(),
            oldest_body_started_at,
            held_ms: u64::try_from(held).unwrap_or(u64::MAX),
            bytes_per_second: self.bytes_per_second,
        }
    }
}

/// One admitted socket's place in the check. Dropped with the socket, it
/// ends the record of every body that came on it, and its count.
pub(crate) struct ObservedSocket {
    pressure: Arc<PoolPressure>,
    socket: u64,
    /// How its connection holds the pool now.
    hold: Mutex<SocketHold>,
}

impl ObservedSocket {
    /// Its connection holds the pool as `hold` from now on.
    pub(crate) fn holds(&self, hold: SocketHold) {
        let mut current = lock(&self.hold);
        let mut connections = lock(&self.pressure.connections);
        let was = connections.count(*current);
        *was = was.saturating_sub(1);
        *connections.count(hold) += 1;
        *current = hold;
    }

    /// A record of a request body arriving on this socket, counted from now,
    /// and the handle its request's credential is attached through.
    pub(crate) fn body(&self) -> (ObservedBody, BodyCredential) {
        let record = Arc::new(BodyRecord {
            started_at: oneiron_vault_contract::now_ts(),
            started: Instant::now(),
            bytes: AtomicU64::new(0),
            key: OnceLock::new(),
        });
        let at = (
            self.socket,
            self.pressure.next.fetch_add(1, Ordering::Relaxed),
        );
        lock(&self.pressure.bodies).insert(at, Arc::clone(&record));
        let observed = ObservedBody {
            pressure: Arc::clone(&self.pressure),
            at,
            record: Arc::clone(&record),
        };
        (observed, BodyCredential(record))
    }
}

impl Drop for ObservedSocket {
    fn drop(&mut self) {
        let mut bodies = lock(&self.pressure.bodies);
        let socket = (self.socket, 0)..=(self.socket, u64::MAX);
        while let Some(at) = bodies.range(socket.clone()).next().map(|(at, _)| *at) {
            bodies.remove(&at);
        }
        drop(bodies);
        let hold = *lock(&self.hold);
        let mut connections = lock(&self.pressure.connections);
        let count = connections.count(hold);
        *count = count.saturating_sub(1);
    }
}

/// One request body's record, held by the body itself, so it counts for
/// whoever reads the body while it is open. Dropping it ends the record.
pub(crate) struct ObservedBody {
    pressure: Arc<PoolPressure>,
    at: (u64, u64),
    record: Arc<BodyRecord>,
}

impl ObservedBody {
    /// Counts `bytes` of the body's data as arrived.
    pub(crate) fn carried(&self, bytes: usize) {
        self.record.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

impl Drop for ObservedBody {
    fn drop(&mut self) {
        lock(&self.pressure.bodies).remove(&self.at);
    }
}

/// Where the credential a request is accepted on is attached to its body.
#[derive(Clone)]
pub(crate) struct BodyCredential(Arc<BodyRecord>);

tokio::task_local! {
    /// The counted body of the request in flight, if it has one.
    static BODY_CREDENTIAL: Option<BodyCredential>;
}

/// Runs `request` with `body` as the counted body of its request.
pub(crate) fn with_body_credential<F: Future>(
    body: Option<BodyCredential>,
    request: F,
) -> impl Future<Output = F::Output> {
    BODY_CREDENTIAL.scope(body, request)
}

/// Attaches `key`, the credential the request in flight was accepted on, to
/// its counted body, unless one is attached already. Outside a counted
/// request, or for a request with no body to count, it does nothing.
pub(crate) fn attach_body_credential(key: PressureCredentialKey) {
    let _ = BODY_CREDENTIAL.try_with(|body| {
        if let Some(BodyCredential(record)) = body {
            let _ = record.key.set(key);
        }
    });
}
